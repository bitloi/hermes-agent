"""Tests for the Matrix bridge / system-identity filter (issue #15763).

Bridges and Matrix appservice "ghost users" deliver system-level events
with valid-looking but unauthorized MXIDs.  The gateway must drop these
before the pairing flow so they cannot be approved into a "hall of
mirrors" loop where the gateway's own outbound traffic is relayed back
as inbound user input.
"""
from collections import deque
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.platforms.base import MessageEvent
from gateway.platforms.matrix import (
    _OUTBOUND_ECHO_RING_SIZE,
    _parse_bridge_prefixes,
    _parse_bridge_users,
    is_matrix_bridge_sender,
)
from gateway.session import SessionSource


def _clear_matrix_env(monkeypatch) -> None:
    for key in (
        "MATRIX_ALLOWED_USERS",
        "MATRIX_ALLOW_ALL_USERS",
        "MATRIX_BRIDGE_PREFIXES",
        "MATRIX_BRIDGE_USERS",
        "GATEWAY_ALLOWED_USERS",
        "GATEWAY_ALLOW_ALL_USERS",
    ):
        monkeypatch.delenv(key, raising=False)


def _make_runner(config: GatewayConfig):
    from gateway.run import GatewayRunner

    runner = object.__new__(GatewayRunner)
    runner.config = config
    adapter = SimpleNamespace(send=AsyncMock())
    runner.adapters = {Platform.MATRIX: adapter}
    runner.pairing_store = MagicMock()
    runner.pairing_store.is_approved.return_value = False
    runner.pairing_store._is_rate_limited.return_value = False
    runner._running_agents = {}
    runner._running_agents_ts = {}
    runner._update_prompts = {}
    runner.hooks = SimpleNamespace(dispatch=AsyncMock(return_value=None))
    runner._sessions = {}
    return runner, adapter


def _make_event(user_id: str, chat_id: str, *, message_id: str = "m1") -> MessageEvent:
    return MessageEvent(
        text="hello",
        message_id=message_id,
        source=SessionSource(
            platform=Platform.MATRIX,
            user_id=user_id,
            chat_id=chat_id,
            user_name="tester",
            chat_type="dm",
        ),
    )


# ---------------------------------------------------------------------------
# Pure-function helper coverage
# ---------------------------------------------------------------------------

def test_default_prefix_matches_underscore_ghost_user():
    prefixes = _parse_bridge_prefixes(None)
    assert is_matrix_bridge_sender(
        "@_telegram_bot_:matrix.org", prefixes=prefixes, users=frozenset()
    )


def test_default_prefix_does_not_match_real_user():
    prefixes = _parse_bridge_prefixes(None)
    assert not is_matrix_bridge_sender(
        "@alice:matrix.org", prefixes=prefixes, users=frozenset()
    )


def test_explicit_user_match_is_case_insensitive():
    users = _parse_bridge_users("@Bridge:Example.Org")
    assert is_matrix_bridge_sender(
        "@bridge:example.org", prefixes=(), users=users
    )


def test_custom_prefix_list_overrides_default():
    prefixes = _parse_bridge_prefixes("@_irc_,@_signal_")
    assert is_matrix_bridge_sender(
        "@_signal_alice:server.org", prefixes=prefixes, users=frozenset()
    )
    # Default "@_" prefix is gone — non-matching ghost passes through.
    assert not is_matrix_bridge_sender(
        "@_telegram_alice:server.org", prefixes=prefixes, users=frozenset()
    )


def test_empty_prefix_list_disables_prefix_matching():
    prefixes = _parse_bridge_prefixes("")
    assert not is_matrix_bridge_sender(
        "@_telegram_alice:server.org", prefixes=prefixes, users=frozenset()
    )


def test_blank_sender_is_not_a_bridge():
    prefixes = _parse_bridge_prefixes(None)
    assert not is_matrix_bridge_sender("", prefixes=prefixes, users=frozenset())


# ---------------------------------------------------------------------------
# Runner-level _is_system_identity / _handle_message integration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_matrix_bridge_default_prefix_drops_pairing(monkeypatch):
    """T1: a default-prefix bridge sender in a DM is dropped, no pairing code sent."""
    _clear_matrix_env(monkeypatch)
    runner, adapter = _make_runner(
        GatewayConfig(platforms={Platform.MATRIX: PlatformConfig(enabled=True)})
    )

    result = await runner._handle_message(
        _make_event("@_telegram_bot_:matrix.org", "!room:matrix.org")
    )

    assert result is None
    runner.pairing_store.generate_code.assert_not_called()
    adapter.send.assert_not_awaited()


@pytest.mark.asyncio
async def test_matrix_bridge_users_env_drops_pairing(monkeypatch):
    """T2: MATRIX_BRIDGE_USERS allowlist matches and drops the event."""
    _clear_matrix_env(monkeypatch)
    monkeypatch.setenv("MATRIX_BRIDGE_USERS", "@bridge:example.org")
    runner, adapter = _make_runner(
        GatewayConfig(platforms={Platform.MATRIX: PlatformConfig(enabled=True)})
    )

    result = await runner._handle_message(
        _make_event("@bridge:example.org", "!room:example.org")
    )

    assert result is None
    runner.pairing_store.generate_code.assert_not_called()
    adapter.send.assert_not_awaited()


@pytest.mark.asyncio
async def test_matrix_bridge_prefix_env_overrides_default(monkeypatch):
    """T3: a custom MATRIX_BRIDGE_PREFIXES list catches its own bridges."""
    _clear_matrix_env(monkeypatch)
    monkeypatch.setenv("MATRIX_BRIDGE_PREFIXES", "@_irc_,@_signal_")
    runner, adapter = _make_runner(
        GatewayConfig(platforms={Platform.MATRIX: PlatformConfig(enabled=True)})
    )

    result = await runner._handle_message(
        _make_event("@_signal_alice:server.org", "!room:server.org")
    )

    assert result is None
    adapter.send.assert_not_awaited()


@pytest.mark.asyncio
async def test_real_matrix_user_still_pairs(monkeypatch):
    """T4: regression guard — a real MXID still triggers pairing."""
    _clear_matrix_env(monkeypatch)
    runner, adapter = _make_runner(
        GatewayConfig(platforms={Platform.MATRIX: PlatformConfig(enabled=True)})
    )
    runner.pairing_store.generate_code.return_value = "ABC12DEF"

    result = await runner._handle_message(
        _make_event("@alice:matrix.org", "!room:matrix.org")
    )

    assert result is None
    runner.pairing_store.generate_code.assert_called_once_with(
        "matrix", "@alice:matrix.org", "tester"
    )
    adapter.send.assert_awaited_once()
    assert "ABC12DEF" in adapter.send.await_args.args[1]


@pytest.mark.asyncio
async def test_paired_bridge_user_is_still_dropped(monkeypatch):
    """T5: even if an operator already approved a bridge, the system check
    runs before authorization and still drops the event."""
    _clear_matrix_env(monkeypatch)
    runner, adapter = _make_runner(
        GatewayConfig(platforms={Platform.MATRIX: PlatformConfig(enabled=True)})
    )
    runner.pairing_store.is_approved.return_value = True

    result = await runner._handle_message(
        _make_event("@_telegram_relay_:matrix.org", "!room:matrix.org")
    )

    assert result is None
    runner.pairing_store.generate_code.assert_not_called()
    adapter.send.assert_not_awaited()


@pytest.mark.asyncio
async def test_internal_event_still_bypasses_system_check(monkeypatch):
    """T8: synthetic events with internal=True must skip both gates,
    including the new system-identity check (regression for #6540)."""
    _clear_matrix_env(monkeypatch)
    import gateway.run as gateway_run

    runner, _adapter = _make_runner(
        GatewayConfig(platforms={Platform.MATRIX: PlatformConfig(enabled=True)})
    )

    sentinel_called = False

    async def _sentinel(*_a, **_kw):
        nonlocal sentinel_called
        sentinel_called = True
        raise RuntimeError("stop here")

    monkeypatch.setattr(
        gateway_run.GatewayRunner, "_handle_message_with_agent", _sentinel
    )

    event = MessageEvent(
        text="[SYSTEM]",
        internal=True,
        source=SessionSource(
            platform=Platform.MATRIX,
            user_id="@_telegram_bot_:matrix.org",
            chat_id="!room:matrix.org",
            chat_type="dm",
        ),
    )

    try:
        await runner._handle_message(event)
    except RuntimeError:
        pass

    assert sentinel_called, (
        "internal=True must bypass the system-identity guard"
    )


@pytest.mark.asyncio
async def test_mixed_case_bridge_mxid_is_dropped(monkeypatch):
    """T9: case-insensitive comparison so bridge MXIDs that arrive with
    server-side casing changes are still recognized."""
    _clear_matrix_env(monkeypatch)
    runner, adapter = _make_runner(
        GatewayConfig(platforms={Platform.MATRIX: PlatformConfig(enabled=True)})
    )

    result = await runner._handle_message(
        _make_event("@_TELEGRAM_BOT_:Matrix.Org", "!room:matrix.org")
    )

    assert result is None
    adapter.send.assert_not_awaited()


# ---------------------------------------------------------------------------
# Adapter-level outbound echo guard
# ---------------------------------------------------------------------------

def _stub_matrix_adapter(monkeypatch):
    """Build a minimal MatrixAdapter without invoking the network."""
    from gateway.platforms.matrix import MatrixAdapter

    monkeypatch.setenv("MATRIX_HOMESERVER", "https://matrix.example.org")
    monkeypatch.setenv("MATRIX_ACCESS_TOKEN", "syt_x")
    monkeypatch.setenv("MATRIX_USER_ID", "@bot:matrix.org")
    return MatrixAdapter(PlatformConfig(enabled=True))


@pytest.mark.asyncio
async def test_outbound_echo_dropped_in_room_handler(monkeypatch):
    """T6: an inbound event with a previously-sent event_id is dropped at
    the adapter, regardless of sender (catches relay reflections)."""
    _clear_matrix_env(monkeypatch)
    adapter = _stub_matrix_adapter(monkeypatch)
    adapter._record_outbound_event_id("$echo123")

    handled = AsyncMock()
    monkeypatch.setattr(adapter, "_handle_text_message", handled)

    event = SimpleNamespace(
        room_id="!room:matrix.org",
        sender="@_relay_:matrix.org",
        event_id="$echo123",
        timestamp=int(adapter._startup_ts * 1000) + 60_000,
        content={"msgtype": "m.text", "body": "hi"},
    )

    await adapter._on_room_message(event)

    handled.assert_not_called()


def test_outbound_ring_is_bounded(monkeypatch):
    """T7: outbound deque size is capped at _OUTBOUND_ECHO_RING_SIZE; old
    entries are evicted from the lookup set so the data structure can't
    grow without bound."""
    _clear_matrix_env(monkeypatch)
    adapter = _stub_matrix_adapter(monkeypatch)

    for i in range(_OUTBOUND_ECHO_RING_SIZE + 100):
        adapter._record_outbound_event_id(f"$evt_{i}")

    assert len(adapter._recent_outbound_event_ids) == _OUTBOUND_ECHO_RING_SIZE
    assert len(adapter._recent_outbound_event_ids_set) == _OUTBOUND_ECHO_RING_SIZE
    assert "$evt_0" not in adapter._recent_outbound_event_ids_set
    assert f"$evt_{_OUTBOUND_ECHO_RING_SIZE + 99}" in adapter._recent_outbound_event_ids_set


@pytest.mark.asyncio
async def test_bridge_sender_dropped_in_room_handler(monkeypatch):
    """T10: bridge senders are filtered at the adapter even outside DMs,
    where the runner-level pairing flow does not run."""
    _clear_matrix_env(monkeypatch)
    adapter = _stub_matrix_adapter(monkeypatch)

    handled = AsyncMock()
    monkeypatch.setattr(adapter, "_handle_text_message", handled)

    event = SimpleNamespace(
        room_id="!group:matrix.org",
        sender="@_telegram_bot_:matrix.org",
        event_id="$bridge_evt",
        timestamp=int(adapter._startup_ts * 1000) + 60_000,
        content={"msgtype": "m.text", "body": "status update"},
    )

    await adapter._on_room_message(event)

    handled.assert_not_called()


def test_record_outbound_ignores_empty_event_id(monkeypatch):
    """Defensive: send() may produce a None message_id on empty payloads."""
    _clear_matrix_env(monkeypatch)
    adapter = _stub_matrix_adapter(monkeypatch)
    adapter._record_outbound_event_id(None)
    adapter._record_outbound_event_id("")
    assert len(adapter._recent_outbound_event_ids) == 0
    assert isinstance(adapter._recent_outbound_event_ids, deque)


def test_record_outbound_is_idempotent(monkeypatch):
    """Recording the same event_id twice must not enter it twice into the
    ring — otherwise an early eviction can drop the set entry while a stale
    deque copy lingers, breaking echo detection."""
    _clear_matrix_env(monkeypatch)
    adapter = _stub_matrix_adapter(monkeypatch)
    adapter._record_outbound_event_id("$same")
    adapter._record_outbound_event_id("$same")
    assert len(adapter._recent_outbound_event_ids) == 1
    assert adapter._recent_outbound_event_ids_set == {"$same"}
