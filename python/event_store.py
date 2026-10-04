#!/usr/bin/env python3
"""Shared append-only memory event store used by MemPalace and local producers."""

from __future__ import annotations

import hashlib
import heapq
import hmac
import json
import math
import os
import re
import sqlite3
import struct
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


CANONICAL_READER_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
CONTRACT_VERSION = 1
SCHEMA_VERSION = 5
DEFAULT_BUSY_TIMEOUT_MS = 5000
DEFAULT_SEARCH_LIMIT = 20
LIFECYCLE_CONTROL_EVENT_TYPES = ("fact_retraction", "fact_conflict")
SCOPED_EVENT_FIELDS = (
    "scope_kind", "source_profile", "source_platform", "source_chat_id",
    "source_user_id", "source_topic_id", "source_session_id", "authorization_version",
)

SECRET_PATTERNS = (
    (re.compile(r"\bsk-(?:or-v1-)?[A-Za-z0-9_-]{20,}\b"), "api-key"),
    (re.compile(r"\bsk_[A-Za-z0-9_-]{20,}\b"), "api-key"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{25,}\b"), "google-key"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "jwt"),
    (re.compile(r"\b\d{7,}:[A-Za-z0-9_-]{25,}\b"), "bot-token"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b", re.I), "bearer-token"),
    (re.compile(r"\b(?:TG_)?API_HASH\b[\s\S]{0,256}?\b[a-f0-9]{32}\b", re.I), "telegram-api-hash"),
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
        ),
        "private-key",
    ),
)


def resolve_db_path(db_path: str | Path | None = None) -> Path:
    if db_path:
        return Path(db_path).expanduser().resolve()
    override = os.environ.get("MEMORY_EVENTS_DB_PATH") or os.environ.get("MEMPALACE_MEMORY_DB")
    if override:
        return Path(override).expanduser().resolve()
    root = Path(os.environ.get("MEMPALACE_GLOBAL_ROOT", "~/.mempalace")).expanduser()
    return (root / "memory_events.sqlite3").resolve()


def _sha256(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _sanitize_text(value: Any) -> str:
    text = str(value if value is not None else "").replace("\x00", "\ufffd")
    for pattern, kind in SECRET_PATTERNS:
        text = pattern.sub(f"[REDACTED:{kind}]", text)
    text = re.sub(
        r'("(?:apiKey|api_key|secret|token|accessToken|refreshToken|authorization)"\s*:\s*")([^"\r\n]{8,})(")',
        lambda match: f'{match.group(1)}[REDACTED:secret-field]{match.group(3)}'
        if not match.group(2).startswith("[REDACTED:")
        else match.group(0),
        text,
        flags=re.I,
    )
    text = re.sub(
        r"\b([A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*\s*=\s*)([^\s\"'`]{8,})",
        lambda match: f"{match.group(1)}[REDACTED:secret-assignment]"
        if not match.group(2).startswith("[REDACTED:")
        else match.group(0),
        text,
    )
    return text


def _clean(value: Any) -> str:
    return _sanitize_text(value).strip()


def _sanitize_value(value: Any, depth: int = 0) -> Any:
    if depth > 8 or value is None:
        return value
    if isinstance(value, str):
        return _sanitize_text(value)
    if isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(item, depth + 1) for item in value]
    if isinstance(value, dict):
        return {_clean(key): _sanitize_value(item, depth + 1) for key, item in value.items()}
    return _clean(value)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _parse_json(value: str, fallback: Any) -> Any:
    try:
        return json.loads(value or "")
    except Exception:
        return fallback


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _timestamp(value: Any, fallback: str | None = None) -> str:
    if not value:
        return fallback or _now()
    text = str(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return fallback or _now()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _value(payload: dict, *names: str, default: Any = None) -> Any:
    for name in names:
        if name in payload and payload[name] is not None:
            return payload[name]
    return default


def _valid_external_id(value: Any) -> str:
    text = _clean(value)
    return text if re.fullmatch(r"[A-Za-z0-9._:@/-]{1,200}", text) else ""


def _supersession_cancellation_pairs(value: Any) -> list[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()

    def visit(item: Any) -> None:
        if isinstance(item, (list, tuple)):
            for child in item:
                visit(child)
            return
        if not isinstance(item, dict):
            return
        superseded_id = _valid_external_id(
            _value(item, "superseded_event_id", "supersededEventId")
        )
        superseding_id = _valid_external_id(
            _value(item, "superseding_event_id", "supersedingEventId")
        )
        if superseded_id and superseding_id and superseded_id != superseding_id:
            pairs.add((superseded_id, superseding_id))

    visit(value)
    return sorted(pairs)


def _normalize_cancellation_metadata(metadata: Any) -> dict:
    if not isinstance(metadata, dict):
        return {}
    normalized = dict(metadata)
    for container in (normalized, normalized.get("extensions")):
        if not isinstance(container, dict) or "cancels_supersessions" not in container:
            continue
        container["cancels_supersessions"] = [
            {
                "superseded_event_id": superseded_id,
                "superseding_event_id": superseding_id,
            }
            for superseded_id, superseding_id in _supersession_cancellation_pairs(
                container.get("cancels_supersessions")
            )
        ]
    return normalized


def _cancellation_pairs_from_metadata(metadata: Any) -> list[tuple[str, str]]:
    if not isinstance(metadata, dict):
        return []
    extensions = metadata.get("extensions") if isinstance(metadata.get("extensions"), dict) else {}
    return sorted(
        set(
            _supersession_cancellation_pairs(metadata.get("cancels_supersessions"))
            + _supersession_cancellation_pairs(extensions.get("cancels_supersessions"))
        )
    )


def _fts_query(value: str) -> str:
    terms = list(dict.fromkeys(re.findall(r"[^\W_]{2,}|[\w]{2,}", _clean(value).lower(), re.UNICODE)))[:16]
    return " OR ".join(f'"{term.replace(chr(34), chr(34) * 2)}"' for term in terms)


def _lexical_score(rank: Any) -> float:
    try:
        value = abs(float(rank or 0.0))
    except (TypeError, ValueError):
        value = 0.0
    return round(1.0 / (1.0 + value), 6)


def _ranked_lexical_rows(connection, fts, alias, select_sql, from_sql, clauses, params, timestamp, deadline=None):
    """Hydrate ranked FTS batches, preserving canonical predicates and full ties.

    Scope filtering happens before admission; this is not a fixed shortlist.
    FTS streams every candidate if necessary, without sorting all large bodies.
    """
    limit = params[-1]
    if deadline is not None:
        if time.monotonic() >= deadline:
            raise TimeoutError('lexical deadline exceeded')
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 10000)
    if not connection.in_transaction:
        connection.execute('BEGIN')
    cursor = connection.execute(
        f"SELECT rowid, rank FROM {fts} WHERE {fts} MATCH ? AND rank MATCH 'bm25()' ORDER BY rank", (params[0],))
    selected = []
    try:
        while batch := cursor.fetchmany(64):
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError('lexical deadline exceeded')
            ranks = {row['rowid']: row['rank'] for row in batch}
            filtered = [f"{alias}.rowid IN ({','.join('?' for _ in batch)})", *clauses[1:]]
            rows = connection.execute(
                f'SELECT {alias}.rowid AS ranked_rowid, {select_sql} FROM {from_sql} '
                f"WHERE {' AND '.join(filtered)}", [*ranks, *params[1:-1]]).fetchall()
            selected.extend({**dict(row), 'rank': ranks[row['ranked_rowid']]} for row in rows)
            selected.sort(key=lambda row: row[timestamp], reverse=True)
            selected.sort(key=lambda row: row['rank'])
            selected = selected[:limit]
            # A strict boundary exhausts the complete tie group, including rows
            # filtered from this batch. Never stop after merely seeing k raw hits.
            if len(selected) == limit and batch[-1]['rank'] > selected[-1]['rank']:
                break
    finally:
        cursor.close()
    return selected


def _normalize_vector(vector: Any, dimensions: Any = None) -> list[float]:
    if not isinstance(vector, (list, tuple)) or not vector:
        raise ValueError("embedding vector is required")
    values = [float(value) for value in vector]
    if any(not math.isfinite(value) for value in values):
        raise ValueError("embedding vector must contain finite numbers")
    expected = len(values) if dimensions is None else int(dimensions)
    if expected <= 0 or expected != len(values):
        raise ValueError(f"embedding dimensions {expected} do not match vector length {len(values)}")
    return values


def _vector_sha256(vector: list[float]) -> str:
    digest = hashlib.sha256()
    for value in vector:
        digest.update(struct.pack(">d", value))
    return digest.hexdigest()


def _required_sha256(value: Any, label: str) -> str:
    digest = _clean(value).lower()
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError(f"{label} must be a 64-character SHA-256 digest")
    return digest


def _cosine_similarity(left: list[float], right: list[float]) -> float:
    dot = sum(a * b for a, b in zip(left, right))
    left_magnitude = sum(value * value for value in left)
    right_magnitude = sum(value * value for value in right)
    if not left_magnitude or not right_magnitude:
        return 0.0
    return dot / math.sqrt(left_magnitude * right_magnitude)


def _superseded_sql(alias: str = "e") -> str:
    safe_alias = alias if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", alias or "") else "e"
    return f"""(
      EXISTS (
        SELECT 1 FROM memory_event_supersessions supersession
        WHERE supersession.superseded_event_id = {safe_alias}.id
          AND NOT EXISTS (
            SELECT 1 FROM memory_event_supersession_cancellations cancellation
            WHERE cancellation.superseded_event_id = supersession.superseded_event_id
              AND cancellation.superseding_event_id = supersession.superseding_event_id
          )
      )
    )"""


def _lifecycle_control_sql(alias: str = "e") -> str:
    safe_alias = alias if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", alias or "") else "e"
    event_types = ", ".join(f"'{value}'" for value in LIFECYCLE_CONTROL_EVENT_TYPES)
    metadata = (
        f"CASE WHEN json_valid({safe_alias}.metadata_json) "
        f"THEN {safe_alias}.metadata_json ELSE '{{}}' END"
    )
    return f"""(
      {safe_alias}.event_type IN ({event_types})
      OR COALESCE(json_extract({metadata}, '$.lifecycle_control'), 0) = 1
    )"""


def _append_current_event_clauses(
    clauses: list[str], include_superseded: bool, alias: str = "e"
) -> None:
    if include_superseded:
        return
    clauses.append(f"NOT {_superseded_sql(alias)}")
    clauses.append(f"NOT {_lifecycle_control_sql(alias)}")


def _llm_wiki_fact_ledger_sql(alias: str = "e") -> str:
    safe_alias = alias if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", alias or "") else "e"
    return f"""(
      COALESCE({safe_alias}.source, '') = 'llm-wiki'
      AND (
        COALESCE({safe_alias}.event_type, '') = 'fact'
        OR {_lifecycle_control_sql(safe_alias)}
      )
    )"""


def _append_unscoped_metadata_clauses(clauses: list[str], *expressions: str) -> None:
    keys = ", ".join(
        "'" + spelling + "'"
        for field in SCOPED_EVENT_FIELDS
        for spelling in (field, re.sub(r"_([a-z])", lambda match: match[1].upper(), field))
    )
    for expression in expressions:
        # Legacy labels must not evade the structured-column boundary.
        value = f"CASE WHEN json_valid({expression}) THEN {expression} ELSE '{{}}' END"
        clauses.append(f"json_valid({expression})")
        clauses.append(f"""NOT EXISTS (
            SELECT 1 FROM json_tree({value}) label
            WHERE (label.key IN ({keys}) AND COALESCE(CAST(label.value AS TEXT), '') NOT IN ('', '0'))
               OR (label.key IN ('source', 'event_source', 'eventSource', 'producer')
                   AND lower(trim(CAST(label.value AS TEXT))) IN ('hermes', 'hermes-mempalace'))
        )""")


def _append_unscoped_event_clauses(
    connection: sqlite3.Connection, clauses: list[str], alias: str = "e"
) -> None:
    """Fail closed for callers with no trusted profile/topic authorization."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", alias):
        raise ValueError("invalid event alias")
    columns = {row[1] for row in connection.execute("PRAGMA table_info(memory_events)")}
    clauses.extend([
        f"{alias}.id IS NOT NULL",
        f"lower(trim({alias}.source)) NOT IN ('hermes', 'hermes-mempalace')",
        f"lower(trim({alias}.producer)) NOT IN ('hermes', 'hermes-mempalace')",
        f"{alias}.privacy_scope = 'local'",
        f"{alias}.status IN ('captured', 'current')",
    ])
    for field in SCOPED_EVENT_FIELDS:
        if field in columns:
            clauses.append(f"COALESCE(CAST({alias}.{field} AS TEXT), '') IN ('', '0')")
    _append_unscoped_metadata_clauses(clauses, f"{alias}.metadata_json", f"{alias}.provenance_json")


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS memory_contract_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memory_events (
  id TEXT PRIMARY KEY,
  contract_version INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  producer TEXT NOT NULL,
  source TEXT NOT NULL,
  source_ref TEXT NOT NULL DEFAULT '',
  session_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  role TEXT NOT NULL,
  wing TEXT NOT NULL DEFAULT '',
  room TEXT NOT NULL DEFAULT '',
  privacy_scope TEXT NOT NULL DEFAULT 'local',
  status TEXT NOT NULL DEFAULT 'captured',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  content TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS memory_events_source_session_idx ON memory_events(source, session_id, created_at);
CREATE INDEX IF NOT EXISTS memory_events_content_idx ON memory_events(content_sha256);
CREATE TABLE IF NOT EXISTS memory_event_supersessions (
  superseded_event_id TEXT NOT NULL,
  superseding_event_id TEXT NOT NULL REFERENCES memory_events(id),
  recorded_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY(superseded_event_id, superseding_event_id)
);
CREATE INDEX IF NOT EXISTS memory_event_supersessions_newer_idx
  ON memory_event_supersessions(superseding_event_id, superseded_event_id);
CREATE TABLE IF NOT EXISTS memory_event_supersession_cancellations (
  superseded_event_id TEXT NOT NULL,
  superseding_event_id TEXT NOT NULL,
  cancellation_event_id TEXT NOT NULL REFERENCES memory_events(id),
  recorded_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY(superseded_event_id, superseding_event_id, cancellation_event_id)
);
CREATE INDEX IF NOT EXISTS memory_event_supersession_cancellations_pair_idx
  ON memory_event_supersession_cancellations(superseded_event_id, superseding_event_id);
CREATE TABLE IF NOT EXISTS memory_projections (
  projection_id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL REFERENCES memory_events(id),
  target TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('success', 'failure')),
  projected_at TEXT NOT NULL,
  projection_ref TEXT NOT NULL DEFAULT '',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  UNIQUE(event_id, target, status)
);
CREATE INDEX IF NOT EXISTS memory_projections_target_idx ON memory_projections(target, status, event_id);
CREATE TABLE IF NOT EXISTS memory_event_embeddings (
  event_id TEXT NOT NULL REFERENCES memory_events(id),
  model TEXT NOT NULL,
  model_digest TEXT NOT NULL CHECK(length(model_digest) = 64),
  dimensions INTEGER NOT NULL CHECK(dimensions > 0),
  vector_sha256 TEXT NOT NULL CHECK(length(vector_sha256) = 64),
  vector_json TEXT NOT NULL,
  projected_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY(event_id, model, model_digest)
);
CREATE INDEX IF NOT EXISTS memory_event_embeddings_model_idx
  ON memory_event_embeddings(model, model_digest, dimensions, projected_at);
CREATE TABLE IF NOT EXISTS mempalace_documents (
  doc_id TEXT PRIMARY KEY,
  content TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  wing TEXT NOT NULL DEFAULT '',
  room TEXT NOT NULL DEFAULT '',
  source_file TEXT NOT NULL DEFAULT '',
  event_id TEXT NOT NULL DEFAULT '',
  event_source TEXT NOT NULL DEFAULT '',
  event_session_id TEXT NOT NULL DEFAULT '',
  indexed_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS mempalace_documents_source_idx ON mempalace_documents(source_file);
CREATE INDEX IF NOT EXISTS mempalace_documents_content_idx ON mempalace_documents(content_sha256);
CREATE TABLE IF NOT EXISTS memory_retrieval_traces (
  trace_id TEXT PRIMARY KEY,
  contract_version INTEGER NOT NULL,
  query TEXT NOT NULL DEFAULT '',
  query_sha256 TEXT NOT NULL DEFAULT '',
  query_preview TEXT NOT NULL DEFAULT '',
  consumer TEXT NOT NULL,
  session_id TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  result_ids_json TEXT NOT NULL DEFAULT '[]',
  result_count INTEGER NOT NULL DEFAULT 0,
  filters_json TEXT NOT NULL DEFAULT '{}',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memory_served_items (
  serve_id TEXT PRIMARY KEY,
  memory_key TEXT NOT NULL,
  consumer TEXT NOT NULL,
  session_id TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT '',
  trace_id TEXT NOT NULL DEFAULT '',
  served_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  UNIQUE(memory_key, consumer, session_id)
);
CREATE VIRTUAL TABLE IF NOT EXISTS memory_events_fts USING fts5(
  content, source, session_id, message_id, role,
  content='memory_events', content_rowid='rowid',
  tokenize='unicode61 remove_diacritics 2'
);
CREATE VIRTUAL TABLE IF NOT EXISTS mempalace_documents_fts USING fts5(
  content, wing, room, source_file,
  content='mempalace_documents', content_rowid='rowid',
  tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER IF NOT EXISTS memory_events_fts_insert AFTER INSERT ON memory_events BEGIN
  INSERT INTO memory_events_fts(rowid, content, source, session_id, message_id, role)
  VALUES (new.rowid, new.content, new.source, new.session_id, new.message_id, new.role);
END;
CREATE TRIGGER IF NOT EXISTS memory_events_no_update BEFORE UPDATE ON memory_events BEGIN
  SELECT RAISE(ABORT, 'memory_events is append-only');
END;
CREATE TRIGGER IF NOT EXISTS memory_events_no_delete BEFORE DELETE ON memory_events BEGIN
  SELECT RAISE(ABORT, 'memory_events is append-only');
END;
CREATE TRIGGER IF NOT EXISTS memory_event_supersessions_no_update BEFORE UPDATE ON memory_event_supersessions BEGIN
  SELECT RAISE(ABORT, 'memory_event_supersessions is append-only');
END;
CREATE TRIGGER IF NOT EXISTS memory_event_supersessions_no_delete BEFORE DELETE ON memory_event_supersessions BEGIN
  SELECT RAISE(ABORT, 'memory_event_supersessions is append-only');
END;
CREATE TRIGGER IF NOT EXISTS memory_event_supersession_cancellations_no_update
  BEFORE UPDATE ON memory_event_supersession_cancellations BEGIN
  SELECT RAISE(ABORT, 'memory_event_supersession_cancellations is append-only');
END;
CREATE TRIGGER IF NOT EXISTS memory_event_supersession_cancellations_no_delete
  BEFORE DELETE ON memory_event_supersession_cancellations BEGIN
  SELECT RAISE(ABORT, 'memory_event_supersession_cancellations is append-only');
END;
CREATE TRIGGER IF NOT EXISTS mempalace_documents_fts_insert AFTER INSERT ON mempalace_documents BEGIN
  INSERT INTO mempalace_documents_fts(rowid, content, wing, room, source_file)
  VALUES (new.rowid, new.content, new.wing, new.room, new.source_file);
END;
CREATE TRIGGER IF NOT EXISTS mempalace_documents_fts_delete AFTER DELETE ON mempalace_documents BEGIN
  INSERT INTO mempalace_documents_fts(mempalace_documents_fts, rowid, content, wing, room, source_file)
  VALUES ('delete', old.rowid, old.content, old.wing, old.room, old.source_file);
END;
CREATE TRIGGER IF NOT EXISTS mempalace_documents_fts_update AFTER UPDATE ON mempalace_documents BEGIN
  INSERT INTO mempalace_documents_fts(mempalace_documents_fts, rowid, content, wing, room, source_file)
  VALUES ('delete', old.rowid, old.content, old.wing, old.room, old.source_file);
  INSERT INTO mempalace_documents_fts(rowid, content, wing, room, source_file)
  VALUES (new.rowid, new.content, new.wing, new.room, new.source_file);
END;
CREATE TRIGGER IF NOT EXISTS memory_retrieval_traces_no_update BEFORE UPDATE ON memory_retrieval_traces BEGIN
  SELECT RAISE(ABORT, 'memory_retrieval_traces is append-only');
END;
CREATE TRIGGER IF NOT EXISTS memory_retrieval_traces_no_delete BEFORE DELETE ON memory_retrieval_traces BEGIN
  SELECT RAISE(ABORT, 'memory_retrieval_traces is append-only');
END;
"""


class MemoryEventStore:
    def __init__(
        self,
        db_path: str | Path | None = None,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
        *,
        read_only: bool = False,
    ):
        self.db_path = resolve_db_path(db_path)
        self.busy_timeout_ms = max(1, int(busy_timeout_ms))
        self.read_only = bool(read_only)

    def connect(self) -> sqlite3.Connection:
        if self.read_only:
            connection = sqlite3.connect(
                self.db_path.as_uri() + "?mode=ro",
                uri=True,
                timeout=self.busy_timeout_ms / 1000,
            )
            try:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA query_only = ON")
                connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
                current = int(connection.execute("PRAGMA user_version").fetchone()[0] or 0)
                if current != SCHEMA_VERSION:
                    raise RuntimeError(
                        f"memory store schema {current} does not match required {SCHEMA_VERSION}"
                    )
                return connection
            except Exception:
                connection.close()
                raise
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.db_path, timeout=self.busy_timeout_ms / 1000)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        connection.execute("PRAGMA foreign_keys = ON")
        self._initialize(connection)
        return connection

    def _initialize(self, connection: sqlite3.Connection) -> None:
        fresh_store = not connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='memory_events'"
        ).fetchone()
        current = int(connection.execute("PRAGMA user_version").fetchone()[0] or 0)
        if current > SCHEMA_VERSION:
            raise RuntimeError(f"memory store schema {current} is newer than supported {SCHEMA_VERSION}")
        had_event_fts = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='memory_events_fts'"
        ).fetchone()
        had_document_fts = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='mempalace_documents_fts'"
        ).fetchone()
        self._migrate_embedding_schema(connection)
        connection.executescript(SCHEMA_SQL)
        self._add_column(connection, "memory_events", "privacy_scope", "TEXT NOT NULL DEFAULT 'local'")
        self._add_column(connection, "memory_events", "status", "TEXT NOT NULL DEFAULT 'captured'")
        self._add_column(connection, "memory_events", "provenance_json", "TEXT NOT NULL DEFAULT '{}'")
        self._add_column(connection, "memory_retrieval_traces", "query_sha256", "TEXT NOT NULL DEFAULT ''")
        self._add_column(connection, "memory_retrieval_traces", "query_preview", "TEXT NOT NULL DEFAULT ''")
        self._backfill_supersessions(connection)
        self._backfill_supersession_cancellations(connection)
        if not had_event_fts:
            connection.execute("INSERT INTO memory_events_fts(memory_events_fts) VALUES ('rebuild')")
        if not had_document_fts:
            connection.execute("INSERT INTO mempalace_documents_fts(mempalace_documents_fts) VALUES ('rebuild')")
        connection.execute(
            "INSERT OR REPLACE INTO memory_contract_meta(key, value) VALUES (?, ?)",
            ("contract_version", str(CONTRACT_VERSION)),
        )
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        if fresh_store:
            connection.execute("CREATE INDEX memory_events_source_ref_created_idx ON memory_events(source_ref, created_at DESC, id ASC) WHERE source_ref <> ''")
            connection.execute("CREATE INDEX memory_events_objective_created_idx ON memory_events(json_extract(CASE WHEN json_valid(metadata_json) THEN metadata_json ELSE '{}' END, '$.objective_id'), created_at DESC, id ASC)")
        connection.commit()

    @staticmethod
    def _backfill_supersessions(connection: sqlite3.Connection) -> None:
        completed = connection.execute(
            "SELECT value FROM memory_contract_meta WHERE key='supersessions_backfilled_v1'"
        ).fetchone()
        if completed is not None and completed[0] == "1":
            return
        metadata = "CASE WHEN json_valid(e.metadata_json) THEN e.metadata_json ELSE '{}' END"
        for json_path in ("$.supersedes", "$.extensions.supersedes"):
            connection.execute(
                f"""
                INSERT OR IGNORE INTO memory_event_supersessions(
                  superseded_event_id, superseding_event_id, recorded_at, metadata_json
                )
                SELECT CAST(supersession.value AS TEXT), e.id, e.captured_at,
                  '{{"source":"metadata_backfill"}}'
                FROM memory_events e, json_each({metadata}, ?) supersession
                WHERE supersession.type IN ('text', 'integer')
                  AND length(CAST(supersession.value AS TEXT)) BETWEEN 1 AND 200
                  AND CAST(supersession.value AS TEXT) <> e.id
                """,
                (json_path,),
            )
        connection.execute(
            "INSERT OR REPLACE INTO memory_contract_meta(key, value) VALUES (?, ?)",
            ("supersessions_backfilled_v1", "1"),
        )

    @staticmethod
    def _backfill_supersession_cancellations(connection: sqlite3.Connection) -> None:
        completed = connection.execute(
            "SELECT value FROM memory_contract_meta "
            "WHERE key='supersession_cancellations_backfilled_v1'"
        ).fetchone()
        if completed is not None and completed[0] == "1":
            return
        rows = connection.execute(
            "SELECT id, captured_at, metadata_json FROM memory_events ORDER BY rowid"
        ).fetchall()
        for row in rows:
            metadata = _parse_json(row["metadata_json"], {})
            for superseded_id, superseding_id in _cancellation_pairs_from_metadata(metadata):
                connection.execute(
                    """
                    INSERT OR IGNORE INTO memory_event_supersession_cancellations(
                      superseded_event_id, superseding_event_id, cancellation_event_id,
                      recorded_at, metadata_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        superseded_id,
                        superseding_id,
                        row["id"],
                        row["captured_at"],
                        _json({"source": "metadata_backfill"}),
                    ),
                )
        connection.execute(
            "INSERT OR REPLACE INTO memory_contract_meta(key, value) VALUES (?, ?)",
            ("supersession_cancellations_backfilled_v1", "1"),
        )

    @staticmethod
    def _migrate_embedding_schema(connection: sqlite3.Connection) -> None:
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='memory_event_embeddings'"
        ).fetchone()
        if not exists:
            return
        columns = {row[1] for row in connection.execute("PRAGMA table_info(memory_event_embeddings)")}
        if {"model_digest", "vector_sha256"}.issubset(columns):
            return
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                DROP INDEX IF EXISTS memory_event_embeddings_model_idx;
                ALTER TABLE memory_event_embeddings RENAME TO memory_event_embeddings_legacy;
                CREATE TABLE memory_event_embeddings (
                  event_id TEXT NOT NULL REFERENCES memory_events(id),
                  model TEXT NOT NULL,
                  model_digest TEXT NOT NULL CHECK(length(model_digest) = 64),
                  dimensions INTEGER NOT NULL CHECK(dimensions > 0),
                  vector_sha256 TEXT NOT NULL CHECK(length(vector_sha256) = 64),
                  vector_json TEXT NOT NULL,
                  projected_at TEXT NOT NULL,
                  metadata_json TEXT NOT NULL DEFAULT '{}',
                  PRIMARY KEY(event_id, model, model_digest)
                );
                INSERT INTO memory_event_embeddings(
                  event_id, model, model_digest, dimensions, vector_sha256,
                  vector_json, projected_at, metadata_json
                )
                SELECT event_id, model,
                  '0000000000000000000000000000000000000000000000000000000000000000',
                  dimensions, digest, vector_json, projected_at, metadata_json
                FROM memory_event_embeddings_legacy;
                DROP TABLE memory_event_embeddings_legacy;
                CREATE INDEX memory_event_embeddings_model_idx
                  ON memory_event_embeddings(model, model_digest, dimensions, projected_at);
                COMMIT;
                """
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise

    @staticmethod
    def _add_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _trace_hmac_key(self) -> bytes:
        if self.read_only:
            raise RuntimeError("read-only memory store cannot access trace key material")
        key_path = Path(
            os.environ.get("MEMORY_TRACE_HMAC_KEY_PATH")
            or self.db_path.parent / "memory_trace_hmac.key"
        ).expanduser().resolve()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            encoded = key_path.read_text(encoding="utf-8").strip().lower()
        except FileNotFoundError:
            generated = os.urandom(32).hex()
            try:
                descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    os.write(descriptor, f"{generated}\n".encode("ascii"))
                finally:
                    os.close(descriptor)
                encoded = generated
            except FileExistsError:
                encoded = key_path.read_text(encoding="utf-8").strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", encoded):
            raise RuntimeError(f"invalid memory trace HMAC key: {key_path}")
        key_path.chmod(0o600)
        return bytes.fromhex(encoded)

    def _query_hmac_sha256(self, value: str) -> str:
        return hmac.new(self._trace_hmac_key(), value.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _event_from_row(row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        keys = set(row.keys())
        return {
            "id": row["id"],
            "contract_version": row["contract_version"],
            "event_type": row["event_type"],
            "producer": row["producer"],
            "source": row["source"],
            "source_ref": row["source_ref"],
            "session_id": row["session_id"],
            "message_id": row["message_id"],
            "role": row["role"],
            "wing": row["wing"],
            "room": row["room"],
            "privacy_scope": row["privacy_scope"],
            "status": row["status"],
            "provenance": _parse_json(row["provenance_json"], {}),
            "content": row["content"],
            "content_sha256": row["content_sha256"],
            "created_at": row["created_at"],
            "captured_at": row["captured_at"],
            "metadata": _parse_json(row["metadata_json"], {}),
            "projected": bool(row["projected"]) if "projected" in keys else False,
            "superseded": bool(row["superseded"]) if "superseded" in keys else False,
            "lexical_score": _lexical_score(row["rank"]) if "rank" in keys else None,
            "memory_key": f"content:{row['content_sha256']}",
        }

    @staticmethod
    def _record_supersessions(connection: sqlite3.Connection, event: dict) -> None:
        metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
        extensions = metadata.get("extensions") if isinstance(metadata.get("extensions"), dict) else {}
        values = [metadata.get("supersedes"), extensions.get("supersedes")]
        superseded_ids: list[str] = []

        def visit(value: Any) -> None:
            if isinstance(value, (list, tuple)):
                for item in value:
                    visit(item)
                return
            event_id = _valid_external_id(value)
            if event_id and event_id != event["id"] and event_id not in superseded_ids:
                superseded_ids.append(event_id)

        for value in values:
            visit(value)
        for superseded_id in superseded_ids:
            connection.execute(
                """
                INSERT OR IGNORE INTO memory_event_supersessions(
                  superseded_event_id, superseding_event_id, recorded_at, metadata_json
                ) VALUES (?, ?, ?, ?)
                """,
                (superseded_id, event["id"], event["captured_at"], _json({"source": "event_metadata"})),
            )

    @staticmethod
    def _record_supersession_cancellations(
        connection: sqlite3.Connection, event: dict
    ) -> None:
        for superseded_id, superseding_id in _cancellation_pairs_from_metadata(
            event.get("metadata")
        ):
            connection.execute(
                """
                INSERT OR IGNORE INTO memory_event_supersession_cancellations(
                  superseded_event_id, superseding_event_id, cancellation_event_id,
                  recorded_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    superseded_id,
                    superseding_id,
                    event["id"],
                    event["captured_at"],
                    _json({"source": "event_metadata"}),
                ),
            )

    @staticmethod
    def _normalize_event(payload: dict, defaults: dict | None = None) -> dict:
        defaults = defaults or {}
        source = _clean(_value(payload, "source", default=defaults.get("source")))
        session_id = _clean(
            _value(payload, "session_id", "sessionId", default=_value(defaults, "session_id", "sessionId"))
        )
        message_id = _clean(
            _value(payload, "message_id", "messageId", default=_value(defaults, "message_id", "messageId"))
        )
        role = _clean(_value(payload, "role", default=defaults.get("role", "unknown"))).lower()
        content = _sanitize_text(_value(payload, "content", "text", default="")).strip()
        if not source:
            raise ValueError("memory event source is required")
        if not session_id:
            raise ValueError("memory event session_id is required")
        if not message_id:
            raise ValueError("memory event message_id is required")
        if not content:
            raise ValueError("memory event content is required")
        content_sha256 = _sha256(content)
        event_type = _clean(
            _value(payload, "event_type", "eventType", default=_value(defaults, "event_type", "eventType", default="message"))
        ).lower() or "message"
        producer = _clean(_value(payload, "producer", default=defaults.get("producer", source))) or source
        source_ref = _clean(
            _value(payload, "source_ref", "sourceRef", default=_value(defaults, "source_ref", "sourceRef", default=""))
        )
        wing = _clean(_value(payload, "wing", default=defaults.get("wing", "")))
        room = _clean(_value(payload, "room", default=defaults.get("room", "")))
        privacy_scope = _clean(
            _value(
                payload,
                "privacy_scope",
                "privacyScope",
                default=_value(defaults, "privacy_scope", "privacyScope", default="local"),
            )
        ) or "local"
        status = _clean(_value(payload, "status", default=defaults.get("status", "captured"))) or "captured"
        provenance = _sanitize_value(payload.get("provenance", defaults.get("provenance", {}))) or {}
        created_at = _timestamp(
            _value(payload, "created_at", "createdAt", default=_value(defaults, "created_at", "createdAt"))
        )
        captured_at = _timestamp(_value(payload, "captured_at", "capturedAt"))
        explicit_id = _valid_external_id(_value(payload, "event_id", "eventId", "id"))
        deterministic = _sha256(
            "\x1f".join(
                str(item)
                for item in (
                    CONTRACT_VERSION,
                    event_type,
                    source,
                    session_id,
                    message_id,
                    role,
                    content_sha256,
                )
            )
        )
        metadata = {
            **(_sanitize_value(defaults.get("metadata", {})) or {}),
            **(_sanitize_value(payload.get("metadata", {})) or {}),
        }
        if "status" in payload:
            metadata["status"] = _sanitize_value(payload["status"])
        if "provenance" in payload:
            metadata["provenance"] = _sanitize_value(payload["provenance"])
        known = {
            "event_id", "eventId", "id", "event_type", "eventType", "producer", "source",
            "source_ref", "sourceRef", "session_id", "sessionId", "message_id", "messageId",
            "role", "wing", "room", "content", "text", "created_at", "createdAt", "captured_at",
            "capturedAt", "privacy_scope", "privacyScope", "metadata", "status", "provenance",
        }
        extensions = {key: _sanitize_value(value) for key, value in payload.items() if key not in known}
        if extensions:
            metadata["extensions"] = extensions
        metadata = _normalize_cancellation_metadata(metadata)
        return {
            "id": explicit_id or f"mem_{deterministic}",
            "contract_version": CONTRACT_VERSION,
            "event_type": event_type,
            "producer": producer,
            "source": source,
            "source_ref": source_ref,
            "session_id": session_id,
            "message_id": message_id,
            "role": role,
            "wing": wing,
            "room": room,
            "privacy_scope": privacy_scope,
            "status": status,
            "provenance": provenance,
            "content": content,
            "content_sha256": content_sha256,
            "created_at": created_at,
            "captured_at": captured_at,
            "metadata": metadata,
        }

    def _insert_event(self, connection: sqlite3.Connection, payload: dict, defaults: dict | None = None) -> dict:
        event = self._normalize_event(payload, defaults)
        result = connection.execute(
            """
            INSERT OR IGNORE INTO memory_events(
              id, contract_version, event_type, producer, source, source_ref, session_id, message_id,
              role, wing, room, privacy_scope, status, provenance_json, content, content_sha256,
              created_at, captured_at, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["id"], event["contract_version"], event["event_type"], event["producer"],
                event["source"], event["source_ref"], event["session_id"], event["message_id"],
                event["role"], event["wing"], event["room"], event["privacy_scope"], event["status"],
                _json(event["provenance"]), event["content"], event["content_sha256"], event["created_at"],
                event["captured_at"], _json(event["metadata"]),
            ),
        )
        row = connection.execute("SELECT * FROM memory_events WHERE id = ?", (event["id"],)).fetchone()
        expected = {
            "contract_version": event["contract_version"],
            "event_type": event["event_type"],
            "producer": event["producer"],
            "source": event["source"],
            "source_ref": event["source_ref"],
            "session_id": event["session_id"],
            "message_id": event["message_id"],
            "role": event["role"],
            "wing": event["wing"],
            "room": event["room"],
            "privacy_scope": event["privacy_scope"],
            "status": event["status"],
            "provenance_json": _json(event["provenance"]),
            "content": event["content"],
            "content_sha256": event["content_sha256"],
            "metadata_json": _json(event["metadata"]),
        }
        if any(name in payload for name in ("created_at", "createdAt")) or any(
            name in (defaults or {}) for name in ("created_at", "createdAt")
        ):
            expected["created_at"] = event["created_at"]
        if any(name in payload for name in ("captured_at", "capturedAt")):
            expected["captured_at"] = event["captured_at"]
        mismatches = ["missing"] if row is None else [
            field for field, value in expected.items() if row[field] != value
        ]
        if mismatches:
            raise RuntimeError(
                f"memory event id collision for {event['id']}: {', '.join(mismatches)}"
            )
        stored_event = self._event_from_row(row)
        self._record_supersessions(connection, stored_event)
        self._record_supersession_cancellations(connection, stored_event)
        return {"inserted": result.rowcount == 1, "event": stored_event}

    def capture_event(self, payload: dict) -> dict:
        with self.connect() as connection:
            return self._insert_event(connection, payload)

    def capture_turn(self, payload: dict) -> dict:
        messages = payload.get("messages") if isinstance(payload.get("messages"), list) else []
        if not messages:
            raise ValueError("capture_turn requires at least one message")
        defaults = {
            "source": payload.get("source"),
            "producer": payload.get("producer"),
            "source_ref": _value(payload, "source_ref", "sourceRef"),
            "session_id": _value(payload, "session_id", "sessionId"),
            "wing": payload.get("wing"),
            "room": payload.get("room"),
            "privacy_scope": _value(payload, "privacy_scope", "privacyScope"),
            "status": payload.get("status"),
            "provenance": payload.get("provenance"),
            "event_type": _value(payload, "event_type", "eventType", default="message"),
            "metadata": payload.get("metadata", {}),
            "created_at": _value(payload, "created_at", "createdAt"),
        }
        events = []
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for index, message in enumerate(messages, 1):
                item = dict(message)
                if not _value(item, "message_id", "messageId"):
                    item["message_id"] = f"{_value(payload, 'turn_id', 'turnId', default='turn')}:{index}"
                events.append(self._insert_event(connection, item, defaults))
            connection.commit()
        return {
            "contract_version": CONTRACT_VERSION,
            "inserted_count": sum(1 for item in events if item["inserted"]),
            "existing_count": sum(1 for item in events if not item["inserted"]),
            "events": [item["event"] for item in events],
        }

    def pending_events(
        self,
        target: str = "mempalace",
        limit: int = 1000,
        include_superseded: bool = False,
        source: str | None = None,
        event_type: str | None = None,
    ) -> list[dict]:
        superseded_sql = _superseded_sql("e")
        clauses = [
            "NOT EXISTS (SELECT 1 FROM memory_projections p "
            "WHERE p.event_id=e.id AND p.target=? AND p.status='success')"
        ]
        params: list[Any] = [_clean(target or "mempalace")]
        _append_current_event_clauses(clauses, include_superseded, "e")
        if source:
            clauses.append("e.source=?")
            params.append(_clean(source))
        if event_type:
            clauses.append("e.event_type=?")
            params.append(_clean(event_type).lower())
        params.append(max(1, int(limit)))
        with self.connect() as connection:
            rows = connection.execute(
                f"""
                SELECT e.*, 0 AS projected, {superseded_sql} AS superseded
                FROM memory_events e
                WHERE {' AND '.join(clauses)}
                ORDER BY e.created_at, e.rowid LIMIT ?
                """,
                params,
            ).fetchall()
        return [self._event_from_row(row) for row in rows]

    def mark_projected(
        self,
        event_ids: Iterable[str],
        target: str = "mempalace",
        projection_ref: str = "",
        projection_refs: dict[str, str] | None = None,
        metadata: dict | None = None,
        projected_at: str | None = None,
    ) -> dict:
        ids = list(dict.fromkeys(_clean(item) for item in event_ids if _clean(item)))
        target = _clean(target or "mempalace")
        inserted = 0
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for event_id in ids:
                projection_id = f"proj_{_sha256(chr(31).join(map(str, (CONTRACT_VERSION, event_id, target, 'success'))))}"
                result = connection.execute(
                    """
                    INSERT OR IGNORE INTO memory_projections(
                      projection_id, event_id, target, status, projected_at, projection_ref, metadata_json
                    ) VALUES (?, ?, ?, 'success', ?, ?, ?)
                    """,
                    (
                        projection_id,
                        event_id,
                        target,
                        _timestamp(projected_at),
                        _clean((projection_refs or {}).get(event_id, projection_ref)),
                        _json(_sanitize_value(metadata or {})),
                    ),
                )
                inserted += max(0, result.rowcount)
            connection.commit()
        return {"target": target, "requested_count": len(ids), "inserted_count": inserted}

    def upsert_event_embedding(
        self,
        event_id: str,
        *,
        model: str,
        vector: Iterable[float],
        dimensions: int | None = None,
        model_digest: str = "",
        digest: str = "",
        vector_sha256: str = "",
        projected_at: str | None = None,
        metadata: dict | None = None,
    ) -> dict:
        event_id = _clean(event_id)
        model = _clean(model)
        if not event_id:
            raise ValueError("embedding event_id is required")
        if not model:
            raise ValueError("embedding model is required")
        pinned_model_digest = _required_sha256(
            model_digest or digest, "embedding model digest"
        )
        values = _normalize_vector(list(vector), dimensions)
        vector_checksum = _vector_sha256(values)
        supplied_vector_checksum = _clean(vector_sha256).lower()
        if supplied_vector_checksum and supplied_vector_checksum != vector_checksum:
            raise ValueError("embedding vector_sha256 does not match vector")
        with self.connect() as connection:
            if connection.execute("SELECT 1 FROM memory_events WHERE id=?", (event_id,)).fetchone() is None:
                raise ValueError(f"memory event not found: {event_id}")
            connection.execute(
                """
                INSERT INTO memory_event_embeddings(
                  event_id, model, model_digest, dimensions, vector_sha256,
                  vector_json, projected_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id, model, model_digest) DO UPDATE SET
                  dimensions=excluded.dimensions, vector_sha256=excluded.vector_sha256,
                  vector_json=excluded.vector_json, projected_at=excluded.projected_at,
                  metadata_json=excluded.metadata_json
                """,
                (
                    event_id,
                    model,
                    pinned_model_digest,
                    len(values),
                    vector_checksum,
                    json.dumps(values, separators=(",", ":")),
                    _timestamp(projected_at),
                    _json(_sanitize_value(metadata or {})),
                ),
            )
            connection.commit()
        return {
            "event_id": event_id,
            "model": model,
            "model_digest": pinned_model_digest,
            "dimensions": len(values),
            "vector_sha256": vector_checksum,
        }

    def list_embeddable_events(
        self,
        *,
        model: str,
        dimensions: int,
        model_digest: str = "",
        digest: str = "",
        source: str | None = None,
        status: str | None = None,
        include_superseded: bool = False,
        limit: int = 100,
    ) -> list[dict]:
        model = _clean(model)
        if not model:
            raise ValueError("embedding model is required")
        pinned_model_digest = _required_sha256(
            model_digest or digest, "embedding model digest"
        )
        expected_dimensions = int(dimensions)
        if expected_dimensions <= 0:
            raise ValueError("embedding dimensions must be a positive integer")
        clauses = ["x.event_id IS NULL"]
        params: list[Any] = [model, pinned_model_digest, expected_dimensions]
        superseded_sql = _superseded_sql("e")
        _append_current_event_clauses(clauses, include_superseded, "e")
        if source:
            clauses.append("e.source=?")
            params.append(_clean(source))
        if status:
            clauses.append("e.status=?")
            params.append(_clean(status))
        params.append(max(1, int(limit)))
        with self.connect() as connection:
            rows = connection.execute(
                f"""
                SELECT e.*, 0 AS projected, {superseded_sql} AS superseded
                FROM memory_events e
                LEFT JOIN memory_event_embeddings x
                  ON x.event_id=e.id AND x.model=? AND x.model_digest=? AND x.dimensions=?
                WHERE {' AND '.join(clauses)}
                ORDER BY e.created_at, e.rowid LIMIT ?
                """,
                params,
            ).fetchall()
        return [self._event_from_row(row) for row in rows]

    def semantic_events(
        self,
        query_vector: Iterable[float],
        *,
        model: str,
        dimensions: int | None = None,
        model_digest: str = "",
        digest: str = "",
        wing: str | None = None,
        room: str | None = None,
        exclude_session_ids: Iterable[str] = (),
        exclude_sources: Iterable[str] = (),
        include_superseded: bool = False,
        unscoped_only: bool = False,
        limit: int = DEFAULT_SEARCH_LIMIT,
        deadline_monotonic: float | None = None,
    ) -> list[dict]:
        def check_deadline():
            if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                raise TimeoutError('semantic retrieval deadline exceeded')
        check_deadline()
        model = _clean(model)
        if not model:
            raise ValueError("embedding model is required")
        pinned_model_digest = _required_sha256(
            model_digest or digest, "embedding model digest"
        )
        vector = _normalize_vector(list(query_vector), dimensions)
        clauses = ["x.model=?", "x.model_digest=?", "x.dimensions=?"]
        params: list[Any] = [model, pinned_model_digest, len(vector)]
        superseded_sql = _superseded_sql("e")
        _append_current_event_clauses(clauses, include_superseded, "e")
        if wing:
            clauses.append("e.wing=?")
            params.append(_clean(wing))
        if room:
            clauses.append("e.room=?")
            params.append(_clean(room))
        for session_id in dict.fromkeys(_clean(item) for item in exclude_session_ids if _clean(item)):
            clauses.append("e.session_id<>?")
            params.append(session_id)
        for source in dict.fromkeys(_clean(item) for item in exclude_sources if _clean(item)):
            clauses.append("e.source<>?")
            params.append(source)
        top = []
        result_limit = max(1, int(limit))
        with closing(self.connect()) as connection:
            # Cache admission, ranking and winner hydration share one read snapshot.
            connection.execute("BEGIN")
            if deadline_monotonic is not None:
                connection.set_progress_handler(lambda: int(time.monotonic() >= deadline_monotonic), 10000)
            if unscoped_only:
                _append_unscoped_event_clauses(connection, clauses)
            compact = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='memory_event_embedding_vectors'"
            ).fetchone() is not None
            # Canonical rows always own membership and checksums. Admit a cache
            # row individually, so missing/stale entries fall back without a
            # second corpus scan and orphan cache entries can never be evidence.
            compact_join = """LEFT JOIN memory_event_embedding_vectors v
                ON v.event_id=x.event_id AND v.model=x.model AND v.model_digest=x.model_digest
                AND v.dimensions=x.dimensions AND v.vector_sha256=x.vector_sha256
                AND length(v.vector_blob)=x.dimensions*8""" if compact else ""
            vector_columns = (
                "v.vector_blob, CASE WHEN v.event_id IS NULL THEN x.vector_json ELSE NULL END AS vector_json"
                if compact else "NULL AS vector_blob, x.vector_json"
            )
            rows = connection.execute(
                f"""
                SELECT e.id, x.model AS embedding_model, x.dimensions AS embedding_dimensions,
                  x.model_digest AS embedding_model_digest, x.vector_sha256, {vector_columns}
                FROM memory_event_embeddings x JOIN memory_events e ON e.id=x.event_id
                {compact_join}
                WHERE {' AND '.join(clauses)}
                """,
                params,
            )
            # Keep only K rows, not the corpus-sized JSON vectors and event bodies.
            # The ordinal preserves the previous stable ordering for equal scores.
            for ordinal, row in enumerate(rows):
                if ordinal % 128 == 0:
                    check_deadline()
                candidate_vector = None
                dimensions = row["embedding_dimensions"]
                if row["vector_blob"] is not None:
                    decoded = struct.unpack(f"<{dimensions}d", row["vector_blob"])
                    checksum = hashlib.sha256(struct.pack(f">{dimensions}d", *decoded)).hexdigest()
                    if checksum == row["vector_sha256"]:
                        candidate_vector = _normalize_vector(decoded, dimensions)
                if candidate_vector is None:
                    vector_json = row["vector_json"]
                    if vector_json is None:
                        # A damaged cache never changes the canonical ranking.
                        vector_json = connection.execute(
                            "SELECT vector_json FROM memory_event_embeddings "
                            "WHERE event_id=? AND model=? AND model_digest=?",
                            (row["id"], model, pinned_model_digest),
                        ).fetchone()[0]
                    candidate_vector = _normalize_vector(_parse_json(vector_json, []), dimensions)
                score = round(_cosine_similarity(vector, candidate_vector), 6)
                candidate = (score, -ordinal, row)
                if len(top) < result_limit:
                    heapq.heappush(top, candidate)
                elif candidate[:2] > top[0][:2]:
                    heapq.heapreplace(top, candidate)
            results = []
            for score, _, row in sorted(top, reverse=True):
                check_deadline()
                # Hydrate only winners; large event bodies and projection subqueries
                # are not needed for the vector scan.
                event_row = connection.execute(
                    f"""SELECT e.*, {superseded_sql} AS superseded,
                      EXISTS(SELECT 1 FROM memory_projections p WHERE p.event_id=e.id
                        AND p.target='mempalace' AND p.status='success') AS projected
                      FROM memory_events e WHERE e.id=?""", (row["id"],),
                ).fetchone()
                event = self._event_from_row(event_row)
                event["semantic_similarity"] = score
                event["embedding"] = {
                    "model": row["embedding_model"],
                    "model_digest": row["embedding_model_digest"],
                    "dimensions": row["embedding_dimensions"],
                    "vector_sha256": row["vector_sha256"],
                }
                results.append(event)
        return results

    semantic_search_events = semantic_events

    def lexical_events(
        self,
        query: str,
        *,
        wing: str | None = None,
        room: str | None = None,
        pending_only: bool = False,
        target: str = "mempalace",
        exclude_session_ids: Iterable[str] = (),
        exclude_sources: Iterable[str] = (),
        include_superseded: bool = False,
        unscoped_only: bool = False,
        limit: int = DEFAULT_SEARCH_LIMIT,
        deadline_monotonic: float | None = None,
    ) -> list[dict]:
        match = _fts_query(query)
        if not match:
            return []
        clauses = ["memory_events_fts MATCH ?"]
        params: list[Any] = [match]
        superseded_sql = _superseded_sql("e")
        _append_current_event_clauses(clauses, include_superseded, "e")
        if wing:
            clauses.append("e.wing = ?")
            params.append(_clean(wing))
        if room:
            clauses.append("e.room = ?")
            params.append(_clean(room))
        if pending_only:
            clauses.append(
                "NOT EXISTS (SELECT 1 FROM memory_projections px WHERE px.event_id=e.id AND px.target=? AND px.status='success')"
            )
            params.append(_clean(target))
        for session_id in dict.fromkeys(_clean(item) for item in exclude_session_ids if _clean(item)):
            clauses.append("e.session_id <> ?")
            params.append(session_id)
        for source in dict.fromkeys(_clean(item) for item in exclude_sources if _clean(item)):
            clauses.append("e.source <> ?")
            params.append(source)
        params.append(max(1, int(limit)))
        with closing(self.connect()) as connection:
            # Scope-column discovery and ranking must use the same snapshot.
            connection.execute('BEGIN')
            if unscoped_only:
                _append_unscoped_event_clauses(connection, clauses)
            rows = _ranked_lexical_rows(
                connection, 'memory_events_fts', 'e',
                f"e.*, {superseded_sql} AS superseded, "
                "EXISTS(SELECT 1 FROM memory_projections p WHERE p.event_id=e.id AND p.target='mempalace' AND p.status='success') AS projected",
                'memory_events e', clauses, params, 'created_at', deadline_monotonic)
        return [self._event_from_row(row) for row in rows]

    def upsert_documents(self, documents: Iterable[dict]) -> dict:
        count = 0
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for document in documents:
                content = _sanitize_text(_value(document, "content", "text", default="")).strip()
                if not content:
                    continue
                doc_id = _clean(_value(document, "doc_id", "docId", "id")) or f"doc_{_sha256(content)}"
                connection.execute(
                    """
                    INSERT INTO mempalace_documents(
                      doc_id, content, content_sha256, wing, room, source_file, event_id, event_source,
                      event_session_id, indexed_at, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(doc_id) DO UPDATE SET
                      content=excluded.content, content_sha256=excluded.content_sha256, wing=excluded.wing,
                      room=excluded.room, source_file=excluded.source_file, event_id=excluded.event_id,
                      event_source=excluded.event_source, event_session_id=excluded.event_session_id,
                      indexed_at=excluded.indexed_at, metadata_json=excluded.metadata_json
                    """,
                    (
                        doc_id,
                        content,
                        _sha256(content),
                        _clean(document.get("wing")),
                        _clean(document.get("room")),
                        _clean(_value(document, "source_file", "sourceFile")),
                        _clean(_value(document, "event_id", "eventId")),
                        _clean(_value(document, "event_source", "eventSource")),
                        _clean(_value(document, "event_session_id", "eventSessionId")),
                        _timestamp(_value(document, "indexed_at", "indexedAt")),
                        _json(_sanitize_value(document.get("metadata", {}))),
                    ),
                )
                count += 1
            connection.commit()
        return {"upserted_count": count}

    def lexical_documents(
        self,
        query: str,
        *,
        wing: str | None = None,
        room: str | None = None,
        exclude_session_ids: Iterable[str] = (),
        exclude_sources: Iterable[str] = (),
        include_superseded: bool = False,
        unscoped_only: bool = False,
        limit: int = DEFAULT_SEARCH_LIMIT,
        deadline_monotonic: float | None = None,
    ) -> list[dict]:
        match = _fts_query(query)
        if not match:
            return []
        clauses = ["mempalace_documents_fts MATCH ?"]
        params: list[Any] = [match]
        superseded_sql = _superseded_sql("e")
        clauses.append(f"NOT {_llm_wiki_fact_ledger_sql('e')}")
        if not include_superseded:
            clauses.append(f"(e.id IS NULL OR NOT {superseded_sql})")
        if wing:
            clauses.append("d.wing = ?")
            params.append(_clean(wing))
        if room:
            clauses.append("d.room = ?")
            params.append(_clean(room))
        for session_id in dict.fromkeys(_clean(item) for item in exclude_session_ids if _clean(item)):
            clauses.append("(d.event_session_id='' OR d.event_session_id<>?)")
            params.append(session_id)
        for source in dict.fromkeys(_clean(item) for item in exclude_sources if _clean(item)):
            clauses.append("(d.event_source='' OR d.event_source<>?)")
            params.append(source)
        params.append(max(1, int(limit)))
        with closing(self.connect()) as connection:
            connection.execute('BEGIN')
            if unscoped_only:
                _append_current_event_clauses(clauses, False)
                _append_unscoped_event_clauses(connection, clauses)
                _append_unscoped_metadata_clauses(clauses, "d.metadata_json")
                # Unknown, mismatched and stale projection provenance is not evidence.
                clauses.extend([
                    "(d.event_source = '' OR d.event_source = e.source)",
                    """EXISTS (SELECT 1 FROM memory_projections p
                        WHERE p.event_id=e.id AND p.target='mempalace' AND p.status='success'
                          AND p.projection_ref=d.source_file AND p.projection_ref<>'')""",
                    """NOT EXISTS (
                        SELECT 1 FROM json_tree(CASE WHEN json_valid(d.metadata_json)
                            THEN d.metadata_json ELSE '{}' END) label
                        WHERE label.key IN ('event_id', 'eventId', 'memory_event_id', 'memoryEventId')
                          AND COALESCE(CAST(label.value AS TEXT), '') NOT IN ('', e.id)
                    )""",
                ])
            rows = _ranked_lexical_rows(
                connection, 'mempalace_documents_fts', 'd', 'd.*',
                'mempalace_documents d LEFT JOIN memory_events e ON e.id=d.event_id',
                clauses, params, 'indexed_at', deadline_monotonic)
        return [
            {
                "id": row["doc_id"],
                "text": row["content"],
                "content_sha256": row["content_sha256"],
                "wing": row["wing"],
                "room": row["room"],
                "source_file": row["source_file"],
                "event_id": row["event_id"],
                "event_source": row["event_source"],
                "event_session_id": row["event_session_id"],
                "indexed_at": row["indexed_at"],
                "metadata": _parse_json(row["metadata_json"], {}),
                "lexical_score": _lexical_score(row["rank"]),
                "memory_key": f"content:{row['content_sha256']}",
            }
            for row in rows
        ]

    def documents_by_ids(self, doc_ids: Iterable[str]) -> dict[str, dict]:
        ids = list(dict.fromkeys(_clean(item) for item in doc_ids if _clean(item)))
        if not ids:
            return {}
        rows = []
        superseded_sql = _superseded_sql("e")
        with self.connect() as connection:
            for offset in range(0, len(ids), 500):
                batch = ids[offset : offset + 500]
                placeholders = ",".join("?" for _ in batch)
                rows.extend(
                    connection.execute(
                        f"""
                        SELECT d.*, e.source AS linked_event_source,
                          e.event_type AS linked_event_type, e.status AS linked_event_status,
                          e.metadata_json AS linked_event_metadata_json,
                          {superseded_sql} AS superseded
                        FROM mempalace_documents d
                        LEFT JOIN memory_events e ON e.id=d.event_id
                        WHERE d.doc_id IN ({placeholders})
                        """,
                        batch,
                    ).fetchall()
                )
        return {
            row["doc_id"]: {
                "id": row["doc_id"],
                "content_sha256": row["content_sha256"],
                "source_file": row["source_file"],
                "event_id": row["event_id"],
                "event_source": row["event_source"] or row["linked_event_source"] or "",
                "event_session_id": row["event_session_id"],
                "event_type": row["linked_event_type"] or "",
                "event_status": row["linked_event_status"] or "",
                "event_metadata": _parse_json(row["linked_event_metadata_json"], {}),
                "superseded": bool(row["superseded"]),
                "memory_key": f"content:{row['content_sha256']}",
            }
            for row in rows
        }

    def sync_mempalace_collection(self, collection, batch_size: int = 1000, force: bool = False) -> dict:
        collection_count = int(collection.count())
        with self.connect() as connection:
            current_count = int(connection.execute("SELECT COUNT(*) FROM mempalace_documents").fetchone()[0])
            if not force and current_count == collection_count and current_count > 0:
                return {"synced": False, "reason": "count_unchanged", "document_count": current_count}
            projection_rows = connection.execute(
                """
                SELECT p.projection_ref, e.id, e.source, e.session_id
                FROM memory_projections p JOIN memory_events e ON e.id=p.event_id
                WHERE p.target='mempalace' AND p.status='success' AND p.projection_ref<>''
                """
            ).fetchall()
            projections = {
                row["projection_ref"]: (row["id"], row["source"], row["session_id"])
                for row in projection_rows
            }

        documents = []
        seen_ids = set()
        for offset in range(0, collection_count, max(1, int(batch_size))):
            page = collection.get(
                include=["documents", "metadatas"],
                limit=max(1, int(batch_size)),
                offset=offset,
            )
            ids = page.get("ids", [])
            docs = page.get("documents", [])
            metas = page.get("metadatas", [])
            for doc_id, content, metadata in zip(ids, docs, metas):
                metadata = metadata or {}
                source_file = str(metadata.get("source_file", ""))
                event_id, event_source, event_session_id = projections.get(
                    source_file,
                    (
                        str(metadata.get("event_id", "")),
                        str(metadata.get("event_source", "")),
                        str(metadata.get("event_session_id", "")),
                    ),
                )
                seen_ids.add(str(doc_id))
                documents.append(
                    {
                        "id": str(doc_id),
                        "content": content or "",
                        "wing": metadata.get("wing", ""),
                        "room": metadata.get("room", ""),
                        "source_file": source_file,
                        "event_id": event_id,
                        "event_source": event_source,
                        "event_session_id": event_session_id,
                        "metadata": metadata,
                    }
                )
        result = self.upsert_documents(documents)
        with self.connect() as connection:
            existing = [row[0] for row in connection.execute("SELECT doc_id FROM mempalace_documents")]
            stale = [doc_id for doc_id in existing if doc_id not in seen_ids]
            for offset in range(0, len(stale), 500):
                batch = stale[offset : offset + 500]
                placeholders = ",".join("?" for _ in batch)
                connection.execute(f"DELETE FROM mempalace_documents WHERE doc_id IN ({placeholders})", batch)
            connection.execute(
                "INSERT OR REPLACE INTO memory_contract_meta(key, value) VALUES (?, ?)",
                ("mempalace_documents_synced_at", _now()),
            )
            connection.commit()
        return {
            "synced": True,
            "document_count": len(seen_ids),
            "upserted_count": result["upserted_count"],
            "removed_count": len(stale),
        }

    def record_retrieval_trace(self, trace: dict) -> dict:
        trace_id = _valid_external_id(_value(trace, "trace_id", "traceId")) or f"trace_{uuid.uuid4()}"
        result_ids = [_clean(item) for item in _value(trace, "result_ids", "resultIds", default=[]) if _clean(item)]
        sanitized_query = _clean(trace.get("query", ""))
        store_preview = os.environ.get("MEMORY_TRACE_STORE_QUERY", "").lower() in {"1", "true", "yes"}
        query_preview = sanitized_query[:240] if store_preview else ""
        query_sha256 = self._query_hmac_sha256(sanitized_query)
        raw_metadata = _sanitize_value(trace.get("metadata", {}))
        metadata = dict(raw_metadata) if isinstance(raw_metadata, dict) else {}
        metadata["query_digest_algorithm"] = "hmac-sha256-v1"
        with self.connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO memory_retrieval_traces(
                  trace_id, contract_version, query, query_sha256, query_preview, consumer, session_id,
                  source, result_ids_json, result_count, filters_json, metadata_json, created_at
                ) VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    trace_id,
                    CONTRACT_VERSION,
                    query_sha256,
                    query_preview,
                    _clean(trace.get("consumer", "unknown")),
                    _clean(_value(trace, "session_id", "sessionId")),
                    _clean(trace.get("source", "")),
                    _json(result_ids),
                    len(result_ids),
                    _json(_sanitize_value(trace.get("filters", {}))),
                    _json(metadata),
                    _timestamp(_value(trace, "created_at", "createdAt")),
                ),
            )
            connection.commit()
        return {
            "trace_id": trace_id,
            "query_sha256": query_sha256,
            "query_digest_algorithm": "hmac-sha256-v1",
            "query_preview": query_preview,
            "result_count": len(result_ids),
        }

    def served_keys(self, consumer: str, session_id: str) -> set[str]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT memory_key FROM memory_served_items WHERE consumer=? AND session_id=?",
                (_clean(consumer), _clean(session_id)),
            ).fetchall()
        return {row["memory_key"] for row in rows}

    def mark_served(
        self,
        items: Iterable[dict],
        *,
        consumer: str,
        session_id: str,
        source: str = "",
        trace_id: str = "",
        metadata: dict | None = None,
    ) -> dict:
        consumer = _clean(consumer or "unknown")
        session_id = _clean(session_id)
        if not session_id:
            raise ValueError("mark_served session_id is required")
        inserted = 0
        with self.connect() as connection:
            for item in items:
                memory_key = _clean(_value(item, "memory_key", "memoryKey"))
                if not memory_key:
                    continue
                serve_id = f"serve_{_sha256(chr(31).join((memory_key, consumer, session_id)))}"
                result = connection.execute(
                    """
                    INSERT OR IGNORE INTO memory_served_items(
                      serve_id, memory_key, consumer, session_id, source, trace_id, served_at, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        serve_id,
                        memory_key,
                        consumer,
                        session_id,
                        _clean(source),
                        _clean(trace_id),
                        _now(),
                        _json(_sanitize_value(metadata or {})),
                    ),
                )
                inserted += max(0, result.rowcount)
            connection.commit()
        return {"inserted_count": inserted}

    def stats(self) -> dict:
        superseded_sql = _superseded_sql("e")
        lifecycle_control_sql = _lifecycle_control_sql("e")
        with self.connect() as connection:
            return {
                "contract_version": CONTRACT_VERSION,
                "schema_version": int(connection.execute("PRAGMA user_version").fetchone()[0]),
                "events": int(connection.execute("SELECT COUNT(*) FROM memory_events").fetchone()[0]),
                "superseded": int(
                    connection.execute(
                        f"SELECT COUNT(*) FROM memory_events e WHERE {superseded_sql}"
                    ).fetchone()[0]
                ),
                "pending": int(
                    connection.execute(
                        f"""
                        SELECT COUNT(*) FROM memory_events e WHERE NOT EXISTS (
                          SELECT 1 FROM memory_projections p
                          WHERE p.event_id=e.id AND p.target='mempalace' AND p.status='success'
                        )
                        AND NOT {superseded_sql}
                        AND NOT {lifecycle_control_sql}
                        """
                    ).fetchone()[0]
                ),
                "documents": int(connection.execute("SELECT COUNT(*) FROM mempalace_documents").fetchone()[0]),
                "embeddings": int(connection.execute("SELECT COUNT(*) FROM memory_event_embeddings").fetchone()[0]),
                "traces": int(connection.execute("SELECT COUNT(*) FROM memory_retrieval_traces").fetchone()[0]),
            }


def sync_mempalace_collection(palace_path: str, *, force: bool = False, batch_size: int = 1000) -> dict:
    import chromadb

    client = chromadb.PersistentClient(path=palace_path)
    collection = client.get_collection("mempalace_drawers")
    return MemoryEventStore().sync_mempalace_collection(collection, batch_size=batch_size, force=force)
