"""Bounded, process-bound MemPalace access for trusted Hermes routes."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import secrets
import stat
import time
from pathlib import Path
from typing import Any


_CONFIRM_RE = re.compile(
    r"^\s*/memory-confirm\s+([A-Za-z0-9_-]{24,128})\s+([A-Fa-f0-9]{64})\s*$"
)
_MAX_RESPONSE_BYTES = 256 * 1024
_PROCESS_TIMEOUT_SECONDS = 20
_REWRITE_TTL_SECONDS = 30
_MAX_PENDING_REWRITES = 128
_PENDING_REWRITES: dict[str, tuple[float, dict[str, Any]]] = {}


def _config_path() -> Path:
    configured = os.environ.get("HERMES_MEMPALACE_CONFIG")
    return (
        Path(configured).expanduser()
        if configured
        else Path.home() / ".hermes" / "mempalace-hermes.json"
    )


def _load_config() -> dict[str, Any]:
    path = _config_path()
    try:
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise RuntimeError("unsafe config mode")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError("MemPalace Hermes config is unavailable") from exc
    if payload.get("schemaVersion") != 1:
        raise RuntimeError("MemPalace Hermes config version is unsupported")
    for key in ("nodeCommand", "serverPath", "dbPath"):
        if not os.path.isabs(str(payload.get(key) or "")):
            raise RuntimeError("MemPalace Hermes config is invalid")
    node_command = Path(str(payload["nodeCommand"]))
    server_path = Path(str(payload["serverPath"]))
    database = Path(str(payload["dbPath"]))
    if (
        not node_command.is_file()
        or not os.access(node_command, os.X_OK)
        or not server_path.is_file()
        or not database.is_file()
        or stat.S_IMODE(database.parent.stat().st_mode) != 0o700
        or stat.S_IMODE(database.stat().st_mode) != 0o600
    ):
        raise RuntimeError("MemPalace Hermes config is invalid")
    ttl = payload.get("proposalTtlSeconds")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or not 30 <= ttl <= 300:
        raise RuntimeError("MemPalace Hermes config is invalid")
    routes = payload.get("routes")
    if not isinstance(routes, list) or not routes:
        raise RuntimeError("MemPalace Hermes routes are unavailable")
    normalized_routes = []
    identities: set[tuple[str, str, str]] = set()
    for route in routes:
        if not isinstance(route, dict):
            raise RuntimeError("MemPalace Hermes route is invalid")
        normalized = {
            "profile": str(route.get("profile") or "").strip().lower(),
            "chatId": str(route.get("chatId") or "").strip(),
            "userId": str(route.get("userId") or "").strip(),
        }
        identity = (normalized["profile"], normalized["chatId"], normalized["userId"])
        if (
            not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", normalized["profile"])
            or not normalized["chatId"].isdecimal()
            or normalized["chatId"] != normalized["userId"]
            or identity in identities
        ):
            raise RuntimeError("MemPalace Hermes route is invalid")
        identities.add(identity)
        normalized_routes.append(normalized)
    payload["routes"] = normalized_routes
    return payload


def _source_value(value: Any) -> str:
    raw = getattr(value, "value", value)
    return str(raw or "").strip()


def _normalize_topic(value: Any) -> str:
    topic = _source_value(value)
    return "" if topic in {"", "0", "1"} else topic[:200]


def _event_context(event: Any) -> dict[str, str]:
    source = getattr(event, "source", None)
    return {
        "platform": _source_value(getattr(source, "platform", "")).lower(),
        "chatId": _source_value(getattr(source, "chat_id", "")),
        "chatType": _source_value(getattr(source, "chat_type", "")).lower(),
        "userId": _source_value(getattr(source, "user_id", "")),
        "profile": _source_value(getattr(source, "profile", "")).lower(),
        "topicId": _normalize_topic(getattr(source, "thread_id", "")),
        "messageId": _source_value(getattr(event, "message_id", "")),
    }


def _session_context() -> dict[str, str]:
    from gateway.session_context import get_session_env

    return {
        "platform": str(get_session_env("HERMES_SESSION_PLATFORM", "") or "").strip().lower(),
        "chatId": str(get_session_env("HERMES_SESSION_CHAT_ID", "") or "").strip(),
        "chatType": str(get_session_env("HERMES_SESSION_CHAT_TYPE", "") or "").strip().lower(),
        "userId": str(get_session_env("HERMES_SESSION_USER_ID", "") or "").strip(),
        "profile": str(get_session_env("HERMES_SESSION_PROFILE", "") or "").strip().lower(),
        "topicId": _normalize_topic(get_session_env("HERMES_SESSION_THREAD_ID", "")),
        "messageId": str(get_session_env("HERMES_SESSION_MESSAGE_ID", "") or "").strip(),
        "sessionKey": str(get_session_env("HERMES_SESSION_KEY", "") or "").strip(),
        "sessionId": str(get_session_env("HERMES_SESSION_ID", "") or "").strip(),
    }


def _route_allowed(config: dict[str, Any], context: dict[str, str]) -> bool:
    if context.get("platform") != "telegram" or context.get("chatType") not in {"dm", "private"}:
        return False
    chat_id = context.get("chatId", "")
    user_id = context.get("userId", "")
    profile = context.get("profile", "")
    if not chat_id.isdecimal() or chat_id != user_id or not profile:
        return False
    matches = [
        route
        for route in config.get("routes", [])
        if str(route.get("profile", "")).strip().lower() == profile
        and str(route.get("chatId", "")).strip() == chat_id
        and str(route.get("userId", "")).strip() == user_id
    ]
    return len(matches) == 1


def _encode(value: dict[str, Any]) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _prune_pending_rewrites(now: float) -> None:
    expired = [token for token, (expires_at, _payload) in _PENDING_REWRITES.items() if expires_at <= now]
    for token in expired:
        _PENDING_REWRITES.pop(token, None)
    while len(_PENDING_REWRITES) >= _MAX_PENDING_REWRITES:
        oldest = min(_PENDING_REWRITES, key=lambda token: _PENDING_REWRITES[token][0])
        _PENDING_REWRITES.pop(oldest, None)


def _bridge_env(context: dict[str, str]) -> dict[str, str]:
    return {
        "HERMES_MEMPALACE_CONFIG": str(_config_path()),
        "HERMES_MEMPALACE_CONTEXT_B64": _encode(context),
        "HOME": str(Path.home()),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }


def _pre_gateway_dispatch(**kwargs: Any) -> dict[str, str] | None:
    event = kwargs.get("event")
    text = str(getattr(event, "text", "") or "")
    match = _CONFIRM_RE.fullmatch(text)
    if not match:
        return None
    try:
        config = _load_config()
        context = _event_context(event)
    except Exception:
        return {"action": "skip", "reason": "mempalace_config_unavailable"}
    if not _route_allowed(config, context):
        return {"action": "skip", "reason": "mempalace_route_denied"}
    payload = {
        "nonce": match.group(1),
        "payloadHash": match.group(2).lower(),
        "context": context,
    }
    now = time.monotonic()
    _prune_pending_rewrites(now)
    token = secrets.token_urlsafe(24)
    _PENDING_REWRITES[token] = (now + _REWRITE_TTL_SECONDS, payload)
    return {"action": "rewrite", "text": f"/memory-confirm-private {token}"}


async def _invoke_process(mode: str, payload: dict[str, Any], context: dict[str, str]) -> dict[str, Any]:
    config = _load_config()
    if not _route_allowed(config, context):
        raise RuntimeError("MemPalace route is not authorized")
    process = await asyncio.create_subprocess_exec(
        str(config["nodeCommand"]),
        str(config["serverPath"]),
        mode,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_bridge_env(context),
    )
    try:
        stdout, _stderr = await asyncio.wait_for(
            process.communicate(json.dumps(payload, ensure_ascii=False).encode("utf-8")),
            timeout=_PROCESS_TIMEOUT_SECONDS,
        )
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise RuntimeError("MemPalace bridge timed out") from exc
    if len(stdout) > _MAX_RESPONSE_BYTES:
        raise RuntimeError("MemPalace bridge response exceeded its bound")
    try:
        result = json.loads(stdout.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("MemPalace bridge returned invalid output") from exc
    if process.returncode != 0 or result.get("ok") is not True:
        raise RuntimeError("MemPalace bridge rejected the request")
    return result.get("result") or {}


async def _invoke_mcp(name: str, args: dict[str, Any], context: dict[str, str]) -> dict[str, Any]:
    config = _load_config()
    if not _route_allowed(config, context):
        raise RuntimeError("MemPalace route is not authorized")
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    }
    process = await asyncio.create_subprocess_exec(
        str(config["nodeCommand"]),
        str(config["serverPath"]),
        "mcp",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_bridge_env(context),
    )
    try:
        stdout, _stderr = await asyncio.wait_for(
            process.communicate((json.dumps(request) + "\n").encode("utf-8")),
            timeout=_PROCESS_TIMEOUT_SECONDS,
        )
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise RuntimeError("MemPalace bridge timed out") from exc
    if len(stdout) > _MAX_RESPONSE_BYTES:
        raise RuntimeError("MemPalace bridge response exceeded its bound")
    try:
        response = json.loads(stdout.decode("utf-8").strip())
        result = response["result"]["structuredContent"]
    except Exception as exc:
        raise RuntimeError("MemPalace bridge returned invalid output") from exc
    if process.returncode != 0 or not isinstance(result, dict):
        raise RuntimeError("MemPalace bridge rejected the request")
    return result


def _make_tool_handler(name: str):
    async def _handler(args: dict[str, Any], **_kwargs: Any) -> str:
        if not isinstance(args, dict):
            raise RuntimeError("MemPalace tool arguments must be an object")
        try:
            config = _load_config()
            context = _session_context()
            if not _route_allowed(config, context):
                return json.dumps(
                    {"version": 1, "ok": False, "items": [], "truncated": False, "error": {"code": "route_denied"}},
                    separators=(",", ":"),
                )
            result = await _invoke_mcp(name, args, context)
            return json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            return json.dumps(
                {"version": 1, "ok": False, "items": [], "truncated": False, "error": {"code": "memory_unavailable"}},
                separators=(",", ":"),
            )

    return _handler


async def _confirm_command(raw_args: str) -> str:
    try:
        token = raw_args.strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", token):
            raise RuntimeError("MemPalace confirmation relay is invalid")
        now = time.monotonic()
        _prune_pending_rewrites(now)
        pending = _PENDING_REWRITES.pop(token, None)
        if pending is None or pending[0] <= now:
            raise RuntimeError("MemPalace confirmation relay is invalid")
        payload = pending[1]
        supplied = payload.get("context")
        current = _session_context()
        if not isinstance(supplied, dict):
            raise RuntimeError("MemPalace command context is invalid")
        for key in ("platform", "chatId", "chatType", "userId", "profile", "topicId"):
            if str(supplied.get(key, "")) != str(current.get(key, "")):
                raise RuntimeError("MemPalace command context changed")
        result = await _invoke_process(
            "confirm",
            {"nonce": payload.get("nonce"), "payloadHash": payload.get("payloadHash")},
            current,
        )
        if result.get("ok") is not True:
            raise RuntimeError("MemPalace confirmation failed")
        return "Память сохранена после точного подтверждения."
    except Exception:
        return "Подтверждение памяти отклонено: команда истекла, уже использована или относится к другому чату, профилю, теме либо сеансу."


_TOOLS = (
    (
        "mempalace_context",
        "Read bounded authorized MemPalace context for this exact trusted profile and Telegram topic.",
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["query"],
            "properties": {
                "query": {"type": "string", "minLength": 1, "maxLength": 2000},
                "limit": {"type": "integer", "minimum": 1, "maximum": 8},
            },
        },
    ),
    (
        "mempalace_propose_write",
        "Propose one memory item. No event is written until the user sends the exact direct confirmation command.",
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["eventType", "content"],
            "properties": {
                "eventType": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,63}$"},
                "content": {"type": "string", "minLength": 1, "maxLength": 4000},
                "tags": {
                    "type": "array",
                    "maxItems": 8,
                    "items": {"type": "string", "minLength": 1, "maxLength": 64},
                },
            },
        },
    ),
)


def register(ctx: Any) -> None:
    ctx.register_hook("pre_gateway_dispatch", _pre_gateway_dispatch)
    ctx.register_command(
        "memory-confirm-private",
        _confirm_command,
        description="Confirm one process-bound MemPalace write proposal.",
        args_hint="<opaque-payload>",
    )
    for name, description, schema in _TOOLS:
        ctx.register_tool(
            name=name,
            toolset="mempalace",
            schema=schema,
            handler=_make_tool_handler(name),
            is_async=True,
            description=description,
        )
