#!/usr/bin/env python3
"""Side-effect manifest recording and verification for delegated subagents."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import urllib.error
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener

from tools.registry import registry, tool_error
from tools.url_safety import is_safe_url


_MAX_EFFECTS_PER_TASK = 256
_MAX_BODY_BYTES = 2_000_000
_DEFAULT_FIELD_CHARS = 2_048
_FIELD_LIMITS = {
    "kind": 64,
    "path": 4_096,
    "url": 4_096,
    "verify_url": 4_096,
    "target": 2_048,
    "sha256": 128,
    "contains": 8_192,
    "description": 2_048,
}
_SUPPORTED_FILE_KINDS = {"file_write"}
_REMOTE_MUTATION_KINDS = {"http_post", "http_put", "remote_write"}
_SUPPORTED_URL_KINDS = {"url", "http_resource"} | _REMOTE_MUTATION_KINDS
_CONSTRAINT_FIELDS = (
    "bytes",
    "min_bytes",
    "sha256",
    "contains",
    "expected_status",
)
_ALLOWED_FIELDS = {
    "kind",
    "path",
    "url",
    "verify_url",
    "target",
    "status",
    "bytes",
    "min_bytes",
    "sha256",
    "contains",
    "expected_status",
    "description",
}


class _UnsafeRedirectError(Exception):
    """Raised when URL verification follows a redirect to an unsafe target."""


class _SafeRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirect_url = urljoin(req.full_url, newurl)
        if not redirect_url.startswith(("http://", "https://")):
            raise _UnsafeRedirectError(
                f"Blocked redirect to non-http(s) URL: {redirect_url}"
            )
        if not is_safe_url(redirect_url):
            raise _UnsafeRedirectError(
                f"Blocked redirect to private/internal address: {redirect_url}"
            )
        return super().redirect_request(req, fp, code, msg, headers, redirect_url)


_URL_OPENER = build_opener(_SafeRedirectHandler)


def _open_verification_url(request: Request, timeout: int = 10):
    return _URL_OPENER.open(request, timeout=timeout)


class SideEffectManifestRegistry:
    """Process-wide manifest store keyed by subagent task_id."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._effects: Dict[str, List[Dict[str, Any]]] = {}

    def record(self, task_id: str, effect: Dict[str, Any]) -> Dict[str, Any]:
        normalized = _normalize_effect(effect)
        normalized["recorded_at"] = time.time()
        with self._lock:
            items = self._effects.setdefault(task_id, [])
            items.append(normalized)
            if len(items) > _MAX_EFFECTS_PER_TASK:
                del items[: len(items) - _MAX_EFFECTS_PER_TASK]
        return dict(normalized)

    def list(self, task_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._effects.get(task_id, [])]

    def clear(self, task_id: Optional[str] = None) -> None:
        with self._lock:
            if task_id is None:
                self._effects.clear()
            else:
                self._effects.pop(task_id, None)


_registry = SideEffectManifestRegistry()


def get_registry() -> SideEffectManifestRegistry:
    return _registry


def record_side_effect(task_id: str, effect: Dict[str, Any]) -> Dict[str, Any]:
    return _registry.record(task_id, effect)


def verify_side_effects(
    task_id: str,
    expected_side_effects: Optional[Iterable[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    effects = _registry.list(task_id)
    verified_effects: List[Dict[str, Any]] = []
    counts = {"verified": 0, "failed": 0, "unverified": 0}

    expected = [
        _normalize_effect(e)
        for e in (expected_side_effects or [])
        if isinstance(e, dict)
    ]

    for effect in effects:
        checked = dict(effect)
        matching_expected = [
            expected_effect
            for expected_effect in expected
            if _matches_expected(effect, expected_effect)
        ]
        verification = _verify_with_expected_constraints(effect, matching_expected)
        checked["verification"] = verification
        counts[verification["status"]] += 1
        verified_effects.append(checked)

    missing = [
        expected_effect
        for expected_effect in expected
        if not any(_matches_expected(recorded, expected_effect) for recorded in effects)
    ]

    if not effects:
        status = "failed"
        message = "No side effects were recorded by the subagent."
    elif counts["failed"] or missing:
        status = "failed"
        message = _verification_message(counts, len(missing))
    elif counts["unverified"]:
        status = "unverified"
        message = _verification_message(counts, 0)
    else:
        status = "verified"
        message = _verification_message(counts, 0)

    return {
        "requested": True,
        "status": status,
        "message": message,
        "recorded_count": len(effects),
        "verified_count": counts["verified"],
        "failed_count": counts["failed"],
        "unverified_count": counts["unverified"],
        "missing_expected_count": len(missing),
        "missing_expected": missing,
        "side_effects": verified_effects,
    }


def _normalize_effect(effect: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in effect.items():
        if key not in _ALLOWED_FIELDS or value is None:
            continue
        if isinstance(value, str):
            limit = _FIELD_LIMITS.get(key, _DEFAULT_FIELD_CHARS)
            out[key] = value[:limit]
        elif isinstance(value, (int, float, bool)):
            out[key] = value
        else:
            limit = _FIELD_LIMITS.get(key, _DEFAULT_FIELD_CHARS)
            out[key] = str(value)[:limit]
    kind = str(out.get("kind") or "").strip().lower()
    out["kind"] = kind or "other"
    for key in (
        "path",
        "url",
        "verify_url",
        "target",
        "sha256",
        "contains",
        "description",
    ):
        if key in out and isinstance(out[key], str):
            out[key] = out[key].strip()
    return out


def _verify_one(effect: Dict[str, Any]) -> Dict[str, str]:
    kind = str(effect.get("kind") or "").lower()
    if kind in _SUPPORTED_FILE_KINDS:
        return _verify_file_write(effect)
    if kind in _SUPPORTED_URL_KINDS:
        return _verify_url_effect(effect)
    return {
        "status": "unverified",
        "reason": f"Unsupported side-effect kind: {kind or 'unknown'}",
    }


def _verify_with_expected_constraints(
    effect: Dict[str, Any], matching_expected: Iterable[Dict[str, Any]]
) -> Dict[str, str]:
    expected_items = list(matching_expected)
    recorded_input = dict(effect)
    for expected_effect in expected_items:
        if (
            "expected_status" in expected_effect
            and "expected_status" not in recorded_input
        ):
            recorded_input["expected_status"] = expected_effect["expected_status"]
            break

    checks = [_verify_one(recorded_input)]
    for expected_effect in expected_items:
        expected_input = dict(effect)
        for key in _CONSTRAINT_FIELDS:
            if key in expected_effect:
                expected_input[key] = expected_effect[key]
        checks.append(_verify_one(expected_input))

    return _combine_verification_results(checks)


def _combine_verification_results(checks: List[Dict[str, str]]) -> Dict[str, str]:
    for index, check in enumerate(checks):
        if check.get("status") == "failed":
            if index:
                return {
                    "status": "failed",
                    "reason": f"Expected side-effect constraint failed: {check.get('reason')}",
                }
            return check
    expected_checks = checks[1:]
    if expected_checks:
        for check in expected_checks:
            if check.get("status") == "unverified":
                return {
                    "status": "unverified",
                    "reason": f"Expected side-effect constraint unverified: {check.get('reason')}",
                }
        if all(check.get("status") == "verified" for check in expected_checks):
            recorded = checks[0]
            if recorded.get("status") == "unverified":
                return expected_checks[0]
            return recorded
    for index, check in enumerate(checks):
        if check.get("status") == "unverified":
            if index:
                return {
                    "status": "unverified",
                    "reason": f"Expected side-effect constraint unverified: {check.get('reason')}",
                }
            return check
    return checks[0] if checks else {"status": "unverified", "reason": "No check ran."}


def _verify_file_write(effect: Dict[str, Any]) -> Dict[str, str]:
    path_value = str(effect.get("path") or "").strip()
    if not path_value:
        return {"status": "failed", "reason": "Missing file path."}

    path = Path(path_value).expanduser()
    try:
        resolved = path.resolve()
        stat = resolved.stat()
    except OSError as exc:
        return {"status": "failed", "reason": f"File is not readable: {exc}"}

    exact_bytes = _as_int(effect.get("bytes"))
    if exact_bytes is not None and stat.st_size != exact_bytes:
        return {
            "status": "failed",
            "reason": f"File size {stat.st_size} did not match expected {exact_bytes}.",
        }

    min_bytes = _as_int(effect.get("min_bytes"))
    if min_bytes is not None and stat.st_size < min_bytes:
        return {
            "status": "failed",
            "reason": f"File size {stat.st_size} was below expected minimum {min_bytes}.",
        }

    digest = str(effect.get("sha256") or "").strip().lower()
    marker = str(effect.get("contains") or "")
    needs_content = bool(digest or marker)
    data = b""
    if needs_content:
        try:
            with resolved.open("rb") as f:
                data = f.read(_MAX_BODY_BYTES + 1)
        except OSError as exc:
            return {"status": "failed", "reason": f"File could not be read: {exc}"}

    if digest:
        actual = hashlib.sha256(data).hexdigest()
        if len(data) > _MAX_BODY_BYTES:
            return {
                "status": "failed",
                "reason": "File was too large to verify sha256 safely.",
            }
        if actual != digest:
            return {"status": "failed", "reason": "File sha256 did not match."}

    if marker and marker not in data.decode("utf-8", errors="ignore"):
        return {"status": "failed", "reason": "File did not contain expected marker."}

    return {"status": "verified", "reason": "File side effect verified."}


def _verify_url_effect(effect: Dict[str, Any]) -> Dict[str, str]:
    kind = str(effect.get("kind") or "").lower()
    expected_status = _as_int(effect.get("expected_status"))
    recorded_status = _as_int(effect.get("status"))
    if recorded_status is not None:
        if expected_status is not None:
            if recorded_status != expected_status:
                return {
                    "status": "failed",
                    "reason": f"Recorded HTTP status {recorded_status} did not match expected {expected_status}.",
                }
        elif not (200 <= recorded_status < 300):
            return {
                "status": "failed",
                "reason": f"Recorded HTTP status {recorded_status} was not successful.",
            }

    url = str(effect.get("verify_url") or effect.get("url") or "").strip()
    if kind in _REMOTE_MUTATION_KINDS:
        if not str(effect.get("verify_url") or "").strip():
            return {
                "status": "unverified",
                "reason": "Remote mutation verification requires a separate verify_url.",
            }
        if not any(
            key in effect and effect.get(key) not in (None, "")
            for key in ("bytes", "min_bytes", "sha256", "contains")
        ):
            return {
                "status": "unverified",
                "reason": "Remote mutation verification requires content, size, or hash evidence.",
            }

    if not url:
        return {
            "status": "unverified",
            "reason": "No verification URL was recorded.",
        }
    if not url.startswith(("http://", "https://")):
        return {"status": "failed", "reason": "Verification URL must be http(s)."}
    if not is_safe_url(url):
        return {
            "status": "failed",
            "reason": "Verification URL targets a private or internal address.",
        }

    request = Request(url, headers={"User-Agent": "hermes-side-effect-verifier/1.0"})
    try:
        with _open_verification_url(request, timeout=10) as response:
            status_value = getattr(response, "status", None)
            if status_value is None:
                status_value = response.getcode()
            status = int(status_value)
            data = response.read(_MAX_BODY_BYTES + 1)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        data = exc.read(_MAX_BODY_BYTES + 1)
    except Exception as exc:
        return {"status": "failed", "reason": f"Verification request failed: {exc}"}

    if expected_status is not None:
        if status != expected_status:
            return {
                "status": "failed",
                "reason": f"HTTP {status} did not match expected {expected_status}.",
            }
    elif not (200 <= status < 300):
        return {"status": "failed", "reason": f"HTTP {status} was not successful."}

    min_bytes = _as_int(effect.get("min_bytes"))
    if min_bytes is not None and len(data) < min_bytes:
        return {
            "status": "failed",
            "reason": f"Response size {len(data)} was below expected minimum {min_bytes}.",
        }

    exact_bytes = _as_int(effect.get("bytes"))
    if exact_bytes is not None and len(data) != exact_bytes:
        return {
            "status": "failed",
            "reason": f"Response size {len(data)} did not match expected {exact_bytes}.",
        }

    digest = str(effect.get("sha256") or "").strip().lower()
    if digest:
        if len(data) > _MAX_BODY_BYTES:
            return {
                "status": "failed",
                "reason": "Response was too large to verify sha256 safely.",
            }
        if hashlib.sha256(data).hexdigest() != digest:
            return {"status": "failed", "reason": "Response sha256 did not match."}

    marker = str(effect.get("contains") or "")
    if marker and marker not in data.decode("utf-8", errors="ignore"):
        return {
            "status": "failed",
            "reason": "Response did not contain expected marker.",
        }

    return {"status": "verified", "reason": "URL side effect verified."}


def _matches_expected(recorded: Dict[str, Any], expected: Dict[str, Any]) -> bool:
    if recorded.get("kind") != expected.get("kind"):
        return False
    for key in ("path", "url", "verify_url", "target"):
        expected_value = str(expected.get(key) or "").strip()
        if not expected_value:
            continue
        recorded_value = str(recorded.get(key) or "").strip()
        if key == "path":
            recorded_value = _norm_path(recorded_value)
            expected_value = _norm_path(expected_value)
        if recorded_value != expected_value:
            return False
    return True


def _norm_path(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path)) if path else ""


def _as_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _verification_message(counts: Dict[str, int], missing_expected: int) -> str:
    parts = []
    if counts["verified"]:
        parts.append(f"{counts['verified']} verified")
    if counts["failed"]:
        parts.append(f"{counts['failed']} failed")
    if counts["unverified"]:
        parts.append(f"{counts['unverified']} unverified")
    if missing_expected:
        parts.append(f"{missing_expected} expected missing")
    return ", ".join(parts) if parts else "No side effects were verified."


RECORD_SIDE_EFFECT_SCHEMA = {
    "name": "record_side_effect",
    "description": (
        "Record a typed external side effect performed by this subagent so "
        "delegate_task can verify it before the parent trusts the final summary."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "kind": {
                "type": "string",
                "description": "Side-effect kind, e.g. file_write, url, http_post, remote_write.",
            },
            "path": {
                "type": "string",
                "description": "Absolute file path for file_write effects.",
            },
            "url": {
                "type": "string",
                "description": "Public result URL or resource URL to verify.",
            },
            "verify_url": {
                "type": "string",
                "description": "Safe GET URL that verifies the side effect.",
            },
            "target": {
                "type": "string",
                "description": "External target identifier when no URL/path applies.",
            },
            "status": {
                "type": "integer",
                "description": "HTTP status observed by the subagent, if any.",
            },
            "bytes": {
                "type": "integer",
                "description": "Exact expected byte length, if known.",
            },
            "min_bytes": {
                "type": "integer",
                "description": "Minimum expected byte length.",
            },
            "sha256": {
                "type": "string",
                "description": "Expected SHA-256 for file content.",
            },
            "contains": {
                "type": "string",
                "description": "Text that should appear in the verified resource.",
            },
            "expected_status": {
                "type": "integer",
                "description": "Expected HTTP status for URL verification.",
            },
            "description": {
                "type": "string",
                "description": "Short human-readable note about the effect.",
            },
        },
        "required": ["kind"],
    },
}


def _handle_record_side_effect(
    args: Dict[str, Any], task_id: Optional[str] = None, **_kw
) -> str:
    if not task_id:
        return tool_error("record_side_effect requires a task_id.")
    try:
        recorded = record_side_effect(task_id, args)
    except Exception as exc:
        return tool_error(f"Could not record side effect: {exc}")
    return json.dumps({"ok": True, "side_effect": recorded}, ensure_ascii=False)


registry.register(
    name="record_side_effect",
    toolset="side_effects",
    schema=RECORD_SIDE_EFFECT_SCHEMA,
    handler=_handle_record_side_effect,
    emoji="",
    max_result_size_chars=8_000,
)
