const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const { sanitizeForMemory } = require('./mempalace_sanitize');
const {
  assertAdapterOperation,
  resolveExperimentalMemoryPolicy,
} = require('./ai_runtime_policy');

const CONTRACT_VERSION = 1;
const SCHEMA_VERSION = 5;
const DEFAULT_BUSY_TIMEOUT_MS = 5000;
const DEFAULT_SEARCH_LIMIT = 20;
const LIFECYCLE_CONTROL_EVENT_TYPES = ['fact_retraction', 'fact_conflict'];
const SCOPED_EVENT_FIELDS = [
  'scope_kind', 'source_profile', 'source_platform', 'source_chat_id',
  'source_user_id', 'source_topic_id', 'source_session_id', 'authorization_version',
];
const HERMES_MEMORY_AUTHORIZATION_VERSION = 1;
const HERMES_MEMORY_PROPOSAL_TTL_SECONDS = 300;
const HERMES_MEMORY_MAX_CONTENT_CHARS = 4000;
const HERMES_MEMORY_MAX_QUERY_CHARS = 2000;

let captureSavepointCounter = 0;
let readSnapshotCounter = 0;

function resolveMemoryDbPath(options = {}) {
  return path.resolve(
    options.dbPath
      || process.env.MEMORY_EVENTS_DB_PATH
      || process.env.MEMPALACE_MEMORY_DB
      || path.join(process.env.MEMPALACE_GLOBAL_ROOT || path.join(os.homedir(), '.mempalace'), 'memory_events.sqlite3'),
  );
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
}

function resolveTraceHmacKeyPath(options = {}) {
  return path.resolve(
    options.traceHmacKeyPath
      || process.env.MEMORY_TRACE_HMAC_KEY_PATH
      || path.join(path.dirname(resolveMemoryDbPath(options)), 'memory_trace_hmac.key'),
  );
}

function traceHmacKey(options = {}) {
  const keyPath = resolveTraceHmacKeyPath(options);
  fs.mkdirSync(path.dirname(keyPath), { recursive: true });
  let encoded;
  try {
    encoded = fs.readFileSync(keyPath, 'utf8').trim().toLowerCase();
  } catch (error) {
    if (!error || error.code !== 'ENOENT') throw error;
    const generated = crypto.randomBytes(32).toString('hex');
    try {
      const descriptor = fs.openSync(keyPath, 'wx', 0o600);
      try {
        fs.writeFileSync(descriptor, `${generated}\n`, 'utf8');
      } finally {
        fs.closeSync(descriptor);
      }
      encoded = generated;
    } catch (createError) {
      if (!createError || createError.code !== 'EEXIST') throw createError;
      encoded = fs.readFileSync(keyPath, 'utf8').trim().toLowerCase();
    }
  }
  if (!/^[a-f0-9]{64}$/.test(encoded)) throw new Error(`invalid memory trace HMAC key: ${keyPath}`);
  fs.chmodSync(keyPath, 0o600);
  return Buffer.from(encoded, 'hex');
}

function queryHmacSha256(value, options = {}) {
  return crypto.createHmac('sha256', traceHmacKey(options)).update(String(value || ''), 'utf8').digest('hex');
}

function cleanText(value) {
  return sanitizeForMemory(String(value ?? '').replace(/\u0000/g, '\uFFFD')).text.trim();
}

function sanitizeValue(value, depth = 0) {
  if (depth > 8 || value === null || value === undefined) return value ?? null;
  if (typeof value === 'string') return sanitizeForMemory(value.replace(/\u0000/g, '\uFFFD')).text;
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.map((item) => sanitizeValue(item, depth + 1));
  if (typeof value === 'object') {
    const result = {};
    for (const [key, item] of Object.entries(value)) result[cleanText(key)] = sanitizeValue(item, depth + 1);
    return result;
  }
  return cleanText(value);
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function normalizeTimestamp(value, fallback = new Date().toISOString()) {
  if (!value) return fallback;
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? fallback : parsed.toISOString();
}

function validExternalId(value) {
  const text = cleanText(value);
  return /^[A-Za-z0-9._:@/-]{1,200}$/.test(text) ? text : '';
}

function parseJson(value, fallback = {}) {
  try {
    return JSON.parse(value || '');
  } catch {
    return fallback;
  }
}

function wantsSuperseded(filters = {}) {
  return Boolean(filters.includeSuperseded || filters.include_superseded || filters.includeHistory);
}

function safeSqlAlias(alias) {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(alias) ? alias : 'e';
}

function supersededEventSql(alias = 'e') {
  const safeAlias = safeSqlAlias(alias);
  return `EXISTS (
    SELECT 1 FROM memory_event_supersessions supersession
    WHERE supersession.superseded_event_id = ${safeAlias}.id
      AND NOT EXISTS (
        SELECT 1 FROM memory_event_supersession_cancellations cancellation
        WHERE cancellation.superseded_event_id = supersession.superseded_event_id
          AND cancellation.superseding_event_id = supersession.superseding_event_id
      )
  )`;
}

function lifecycleControlEventSql(alias = 'e') {
  const safeAlias = safeSqlAlias(alias);
  const eventTypes = LIFECYCLE_CONTROL_EVENT_TYPES.map((value) => `'${value}'`).join(', ');
  const metadata = `CASE WHEN json_valid(${safeAlias}.metadata_json) THEN ${safeAlias}.metadata_json ELSE '{}' END`;
  return `(
    ${safeAlias}.event_type IN (${eventTypes})
    OR COALESCE(json_extract(${metadata}, '$.lifecycle_control'), 0) = 1
  )`;
}

function appendCurrentEventClauses(clauses, filters = {}, alias = 'e') {
  if (filters.unscopedOnly) clauses.push(unscopedEventSql(alias));
  if (wantsSuperseded(filters)) return;
  clauses.push(`NOT ${supersededEventSql(alias)}`);
  clauses.push(`NOT ${lifecycleControlEventSql(alias)}`);
}

function unscopedEventSql(alias = 'e') {
  const name = safeSqlAlias(alias);
  const scopedKeys = SCOPED_EVENT_FIELDS.flatMap((field) => [
    field,
    field.replace(/_([a-z])/g, (_, character) => character.toUpperCase()),
  ]).map((key) => `'${key}'`).join(', ');
  const metadataClauses = [`${name}.metadata_json`, `${name}.provenance_json`].map((expression) => {
    const value = `CASE WHEN json_valid(${expression}) THEN ${expression} ELSE '{}' END`;
    return `json_valid(${expression}) AND NOT EXISTS (
      SELECT 1 FROM json_tree(${value}) label
      WHERE (label.key IN (${scopedKeys}) AND COALESCE(CAST(label.value AS TEXT), '') NOT IN ('', '0'))
         OR (label.key IN ('source', 'event_source', 'eventSource', 'producer')
             AND lower(trim(CAST(label.value AS TEXT))) IN ('hermes', 'hermes-mempalace'))
    )`;
  });
  const structuredClauses = SCOPED_EVENT_FIELDS.map((field) => (
    `COALESCE(CAST(${name}.${field} AS TEXT), '') IN ('', '0')`
  ));
  return `(${[
    `${name}.id IS NOT NULL`,
    `lower(trim(COALESCE(${name}.source, ''))) NOT IN ('hermes', 'hermes-mempalace')`,
    `lower(trim(COALESCE(${name}.producer, ''))) NOT IN ('hermes', 'hermes-mempalace')`,
    `${name}.privacy_scope = 'local'`,
    `${name}.status IN ('captured', 'current')`,
    ...structuredClauses,
    ...metadataClauses,
  ].join('\n    AND ')})`;
}

function memoryStoreError(code, message, cause) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.code = code;
  return error;
}

function validateReadOnlySchema(db) {
  const currentVersion = Number(db.prepare('PRAGMA user_version').get().user_version || 0);
  if (currentVersion !== SCHEMA_VERSION) {
    throw memoryStoreError(
      'memory_store_invalid',
      `memory store schema ${currentVersion} does not match required schema ${SCHEMA_VERSION}`,
    );
  }
  const requiredTables = [
    'memory_events',
    'memory_events_fts',
    'memory_event_supersessions',
    'memory_event_supersession_cancellations',
    'memory_event_embeddings',
    'memory_retrieval_traces',
    'memory_served_items',
  ];
  const placeholders = requiredTables.map(() => '?').join(', ');
  const found = new Set(db.prepare(`
    SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name IN (${placeholders})
  `).all(...requiredTables).map((row) => row.name));
  const missing = requiredTables.filter((name) => !found.has(name));
  if (missing.length) {
    throw memoryStoreError('memory_store_invalid', `memory store is missing required tables: ${missing.join(', ')}`);
  }
}

function openMemoryStore(options = {}) {
  const dbPath = resolveMemoryDbPath(options);
  const busyTimeoutMs = Math.max(1, Number(options.busyTimeoutMs || DEFAULT_BUSY_TIMEOUT_MS));
  if (options.readOnly) {
    if (!fs.existsSync(dbPath)) {
      throw memoryStoreError('memory_store_unavailable', 'memory store is unavailable');
    }
    let db;
    try {
      db = new DatabaseSync(dbPath, { readOnly: true, timeout: busyTimeoutMs });
      db.exec(`
        PRAGMA busy_timeout = ${busyTimeoutMs};
        PRAGMA query_only = ON;
      `);
      validateReadOnlySchema(db);
      return db;
    } catch (error) {
      try { db?.close(); } catch {}
      if (error?.code === 'memory_store_invalid' || error?.code === 'memory_store_unavailable') throw error;
      throw memoryStoreError('memory_store_invalid', 'memory store failed read-only validation', error);
    }
  }
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = ${busyTimeoutMs};
    PRAGMA foreign_keys = ON;
  `);
  initializeSchema(db);
  return db;
}

function initializeSchema(db) {
  const freshStore = !db.prepare("SELECT 1 FROM sqlite_master WHERE name = 'memory_events'").get();
  const currentVersion = Number(db.prepare('PRAGMA user_version').get().user_version || 0);
  if (currentVersion > SCHEMA_VERSION) {
    throw new Error(`memory store schema ${currentVersion} is newer than supported ${SCHEMA_VERSION}`);
  }
  const hadEventFts = Boolean(db.prepare("SELECT 1 AS found FROM sqlite_master WHERE type = 'table' AND name = 'memory_events_fts'").get());
  const hadDocumentFts = Boolean(db.prepare("SELECT 1 AS found FROM sqlite_master WHERE type = 'table' AND name = 'mempalace_documents_fts'").get());
  migrateEmbeddingSchema(db);
  db.exec(`
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
      metadata_json TEXT NOT NULL DEFAULT '{}',
      source_profile TEXT NOT NULL DEFAULT '',
      source_platform TEXT NOT NULL DEFAULT '',
      source_chat_id TEXT NOT NULL DEFAULT '',
      source_user_id TEXT NOT NULL DEFAULT '',
      source_topic_id TEXT NOT NULL DEFAULT '',
      source_session_id TEXT NOT NULL DEFAULT '',
      scope_kind TEXT NOT NULL DEFAULT '',
      authorization_version INTEGER NOT NULL DEFAULT 0
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
      vector_blob BLOB,
      projected_at TEXT NOT NULL,
      metadata_json TEXT NOT NULL DEFAULT '{}',
      PRIMARY KEY(event_id, model, model_digest)
    );
    CREATE INDEX IF NOT EXISTS memory_event_embeddings_model_idx
      ON memory_event_embeddings(model, model_digest, dimensions, projected_at);

    CREATE TABLE IF NOT EXISTS memory_event_embedding_vectors (
      event_id TEXT NOT NULL REFERENCES memory_events(id),
      model TEXT NOT NULL,
      model_digest TEXT NOT NULL CHECK(length(model_digest) = 64),
      dimensions INTEGER NOT NULL CHECK(dimensions > 0),
      vector_sha256 TEXT NOT NULL CHECK(length(vector_sha256) = 64),
      vector_blob BLOB NOT NULL,
      PRIMARY KEY(event_id, model, model_digest)
    );
    CREATE INDEX IF NOT EXISTS memory_event_embedding_vectors_model_idx
      ON memory_event_embedding_vectors(model, model_digest, dimensions);

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

    CREATE TABLE IF NOT EXISTS memory_shared_grants (
      grant_id TEXT PRIMARY KEY,
      event_id TEXT NOT NULL REFERENCES memory_events(id),
      grantee_profile TEXT NOT NULL,
      grantee_platform TEXT NOT NULL,
      grantee_chat_id TEXT NOT NULL,
      grantee_user_id TEXT NOT NULL,
      grantee_topic_id TEXT NOT NULL DEFAULT '',
      grant_kind TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL DEFAULT '',
      authorization_version INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS memory_shared_grants_lookup_idx ON memory_shared_grants(
      event_id, grantee_profile, grantee_platform, grantee_chat_id,
      grantee_user_id, grantee_topic_id, expires_at
    );

    CREATE TABLE IF NOT EXISTS memory_write_proposals (
      nonce TEXT PRIMARY KEY,
      payload_hash TEXT NOT NULL CHECK(length(payload_hash) = 64),
      payload_json TEXT NOT NULL,
      source_profile TEXT NOT NULL,
      source_platform TEXT NOT NULL,
      source_chat_id TEXT NOT NULL,
      source_user_id TEXT NOT NULL,
      source_topic_id TEXT NOT NULL DEFAULT '',
      source_session_key_hash TEXT NOT NULL CHECK(length(source_session_key_hash) = 64),
      source_session_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      consumed_at TEXT NOT NULL DEFAULT '',
      event_id TEXT NOT NULL DEFAULT '',
      authorization_version INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS memory_write_proposals_expiry_idx
      ON memory_write_proposals(expires_at, consumed_at);

    CREATE TABLE IF NOT EXISTS memory_write_audit (
      audit_id TEXT PRIMARY KEY,
      nonce TEXT NOT NULL,
      payload_hash TEXT NOT NULL CHECK(length(payload_hash) = 64),
      event_id TEXT NOT NULL REFERENCES memory_events(id),
      source_profile TEXT NOT NULL,
      source_platform TEXT NOT NULL,
      source_chat_id TEXT NOT NULL,
      source_user_id TEXT NOT NULL,
      source_topic_id TEXT NOT NULL DEFAULT '',
      source_session_id TEXT NOT NULL,
      action TEXT NOT NULL,
      created_at TEXT NOT NULL,
      authorization_version INTEGER NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS memory_write_audit_nonce_idx
      ON memory_write_audit(nonce);
    CREATE UNIQUE INDEX IF NOT EXISTS memory_write_audit_event_idx
      ON memory_write_audit(event_id);

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
    CREATE TRIGGER IF NOT EXISTS memory_shared_grants_no_update BEFORE UPDATE ON memory_shared_grants BEGIN
      SELECT RAISE(ABORT, 'memory_shared_grants is append-only');
    END;
    CREATE TRIGGER IF NOT EXISTS memory_shared_grants_no_delete BEFORE DELETE ON memory_shared_grants BEGIN
      SELECT RAISE(ABORT, 'memory_shared_grants is append-only');
    END;
    CREATE TRIGGER IF NOT EXISTS memory_write_proposals_restrict_update BEFORE UPDATE ON memory_write_proposals
      WHEN NOT (
        old.consumed_at = '' AND new.consumed_at <> '' AND new.event_id <> ''
        AND old.nonce IS new.nonce
        AND old.payload_hash IS new.payload_hash
        AND old.payload_json IS new.payload_json
        AND old.source_profile IS new.source_profile
        AND old.source_platform IS new.source_platform
        AND old.source_chat_id IS new.source_chat_id
        AND old.source_user_id IS new.source_user_id
        AND old.source_topic_id IS new.source_topic_id
        AND old.source_session_key_hash IS new.source_session_key_hash
        AND old.source_session_id IS new.source_session_id
        AND old.created_at IS new.created_at
        AND old.expires_at IS new.expires_at
        AND old.authorization_version IS new.authorization_version
      ) BEGIN
        SELECT RAISE(ABORT, 'memory_write_proposals may only be consumed once');
    END;
    CREATE TRIGGER IF NOT EXISTS memory_write_proposals_no_delete BEFORE DELETE ON memory_write_proposals BEGIN
      SELECT RAISE(ABORT, 'memory_write_proposals cannot be deleted');
    END;
    CREATE TRIGGER IF NOT EXISTS memory_write_audit_no_update BEFORE UPDATE ON memory_write_audit BEGIN
      SELECT RAISE(ABORT, 'memory_write_audit is append-only');
    END;
    CREATE TRIGGER IF NOT EXISTS memory_write_audit_no_delete BEFORE DELETE ON memory_write_audit BEGIN
      SELECT RAISE(ABORT, 'memory_write_audit is append-only');
    END;
  `);
  addColumnIfMissing(db, 'memory_events', 'privacy_scope', "TEXT NOT NULL DEFAULT 'local'");
  addColumnIfMissing(db, 'memory_events', 'status', "TEXT NOT NULL DEFAULT 'captured'");
  addColumnIfMissing(db, 'memory_events', 'provenance_json', "TEXT NOT NULL DEFAULT '{}'");
  addColumnIfMissing(db, 'memory_events', 'source_profile', "TEXT NOT NULL DEFAULT ''");
  addColumnIfMissing(db, 'memory_events', 'source_platform', "TEXT NOT NULL DEFAULT ''");
  addColumnIfMissing(db, 'memory_events', 'source_chat_id', "TEXT NOT NULL DEFAULT ''");
  addColumnIfMissing(db, 'memory_events', 'source_user_id', "TEXT NOT NULL DEFAULT ''");
  addColumnIfMissing(db, 'memory_events', 'source_topic_id', "TEXT NOT NULL DEFAULT ''");
  addColumnIfMissing(db, 'memory_events', 'source_session_id', "TEXT NOT NULL DEFAULT ''");
  addColumnIfMissing(db, 'memory_events', 'scope_kind', "TEXT NOT NULL DEFAULT ''");
  addColumnIfMissing(db, 'memory_events', 'authorization_version', 'INTEGER NOT NULL DEFAULT 0');
  addColumnIfMissing(db, 'memory_retrieval_traces', 'query_sha256', "TEXT NOT NULL DEFAULT ''");
  addColumnIfMissing(db, 'memory_retrieval_traces', 'query_preview', "TEXT NOT NULL DEFAULT ''");
  db.exec(`
    CREATE INDEX IF NOT EXISTS memory_events_hermes_scope_idx ON memory_events(
      authorization_version, scope_kind, source_profile, source_platform,
      source_chat_id, source_user_id, source_topic_id, created_at
    );

    CREATE TRIGGER IF NOT EXISTS memory_write_audit_validate_insert
      BEFORE INSERT ON memory_write_audit
      WHEN NOT EXISTS (
        SELECT 1
        FROM memory_write_proposals proposal
        JOIN memory_events event_row ON event_row.id = new.event_id
        WHERE proposal.nonce = new.nonce
          AND proposal.payload_hash = new.payload_hash
          AND proposal.consumed_at = ''
          AND proposal.event_id = ''
          AND proposal.source_profile = new.source_profile
          AND proposal.source_platform = new.source_platform
          AND proposal.source_chat_id = new.source_chat_id
          AND proposal.source_user_id = new.source_user_id
          AND proposal.source_topic_id = new.source_topic_id
          AND proposal.source_session_id = new.source_session_id
          AND proposal.authorization_version = new.authorization_version
          AND new.action = 'confirmed'
          AND event_row.event_type = json_extract(proposal.payload_json, '$.eventType')
          AND event_row.content = json_extract(proposal.payload_json, '$.content')
          AND event_row.producer = 'hermes-mempalace'
          AND event_row.source = 'hermes'
          AND event_row.session_id = proposal.source_session_id
          AND event_row.source_profile = proposal.source_profile
          AND event_row.source_platform = proposal.source_platform
          AND event_row.source_chat_id = proposal.source_chat_id
          AND event_row.source_user_id = proposal.source_user_id
          AND event_row.source_topic_id = proposal.source_topic_id
          AND event_row.source_session_id = proposal.source_session_id
          AND event_row.scope_kind = 'profile_topic'
          AND event_row.authorization_version = proposal.authorization_version
      ) BEGIN
        SELECT RAISE(ABORT, 'memory_write_audit requires a matching unconsumed proposal and event');
      END;

    CREATE TRIGGER IF NOT EXISTS memory_write_proposals_require_event_audit
      BEFORE UPDATE OF consumed_at, event_id ON memory_write_proposals
      WHEN old.consumed_at = '' AND old.event_id = ''
        AND new.consumed_at <> '' AND new.event_id <> ''
        AND NOT EXISTS (
          SELECT 1 FROM memory_write_audit audit_row
          WHERE audit_row.nonce = old.nonce
            AND audit_row.payload_hash = old.payload_hash
            AND audit_row.event_id = new.event_id
            AND audit_row.source_profile = old.source_profile
            AND audit_row.source_platform = old.source_platform
            AND audit_row.source_chat_id = old.source_chat_id
            AND audit_row.source_user_id = old.source_user_id
            AND audit_row.source_topic_id = old.source_topic_id
            AND audit_row.source_session_id = old.source_session_id
            AND audit_row.action = 'confirmed'
            AND audit_row.authorization_version = old.authorization_version
        ) BEGIN
          SELECT RAISE(ABORT, 'memory_write_proposals consume requires matching event and audit');
        END;
  `);
  backfillSupersessions(db);
  backfillSupersessionCancellations(db);
  if (!hadEventFts) db.exec("INSERT INTO memory_events_fts(memory_events_fts) VALUES ('rebuild')");
  if (!hadDocumentFts) db.exec("INSERT INTO mempalace_documents_fts(mempalace_documents_fts) VALUES ('rebuild')");
  db.prepare('INSERT OR REPLACE INTO memory_contract_meta(key, value) VALUES (?, ?)').run('contract_version', String(CONTRACT_VERSION));
  db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
  if (freshStore) db.exec(`
    CREATE INDEX memory_events_source_ref_created_idx ON memory_events(source_ref, created_at DESC, id ASC) WHERE source_ref <> '';
    CREATE INDEX memory_events_objective_created_idx ON memory_events(json_extract(CASE WHEN json_valid(metadata_json) THEN metadata_json ELSE '{}' END, '$.objective_id'), created_at DESC, id ASC);
  `);
}

function backfillSupersessions(db) {
  const completed = db.prepare("SELECT value FROM memory_contract_meta WHERE key = 'supersessions_backfilled_v1'").get();
  if (completed && completed.value === '1') return;
  const metadata = "CASE WHEN json_valid(e.metadata_json) THEN e.metadata_json ELSE '{}' END";
  db.exec('BEGIN IMMEDIATE');
  try {
    for (const jsonPath of ['$.supersedes', '$.extensions.supersedes']) {
      db.prepare(`
        INSERT OR IGNORE INTO memory_event_supersessions(
          superseded_event_id, superseding_event_id, recorded_at, metadata_json
        )
        SELECT CAST(supersession.value AS TEXT), e.id, e.captured_at, '{"source":"metadata_backfill"}'
        FROM memory_events e, json_each(${metadata}, ?) supersession
        WHERE supersession.type IN ('text', 'integer')
          AND length(CAST(supersession.value AS TEXT)) BETWEEN 1 AND 200
          AND CAST(supersession.value AS TEXT) <> e.id
      `).run(jsonPath);
    }
    db.prepare('INSERT OR REPLACE INTO memory_contract_meta(key, value) VALUES (?, ?)')
      .run('supersessions_backfilled_v1', '1');
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

function backfillSupersessionCancellations(db) {
  const completed = db.prepare("SELECT value FROM memory_contract_meta WHERE key = 'supersession_cancellations_backfilled_v1'").get();
  if (completed && completed.value === '1') return;
  const metadata = "CASE WHEN json_valid(e.metadata_json) THEN e.metadata_json ELSE '{}' END";
  db.exec('BEGIN IMMEDIATE');
  try {
    for (const jsonPath of ['$.cancels_supersessions', '$.extensions.cancels_supersessions']) {
      db.prepare(`
        INSERT OR IGNORE INTO memory_event_supersession_cancellations(
          superseded_event_id, superseding_event_id, cancellation_event_id, recorded_at, metadata_json
        )
        SELECT
          CAST(json_extract(cancellation.value, '$.superseded_event_id') AS TEXT),
          CAST(json_extract(cancellation.value, '$.superseding_event_id') AS TEXT),
          e.id,
          e.captured_at,
          '{"source":"metadata_backfill"}'
        FROM memory_events e, json_each(${metadata}, ?) cancellation
        WHERE cancellation.type = 'object'
          AND length(CAST(json_extract(cancellation.value, '$.superseded_event_id') AS TEXT)) BETWEEN 1 AND 200
          AND length(CAST(json_extract(cancellation.value, '$.superseding_event_id') AS TEXT)) BETWEEN 1 AND 200
          AND CAST(json_extract(cancellation.value, '$.superseded_event_id') AS TEXT)
              <> CAST(json_extract(cancellation.value, '$.superseding_event_id') AS TEXT)
      `).run(jsonPath);
    }
    db.prepare('INSERT OR REPLACE INTO memory_contract_meta(key, value) VALUES (?, ?)')
      .run('supersession_cancellations_backfilled_v1', '1');
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

function addColumnIfMissing(db, table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all().map((row) => row.name);
  if (!columns.includes(column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

function migrateEmbeddingSchema(db) {
  const exists = db.prepare("SELECT 1 AS found FROM sqlite_master WHERE type = 'table' AND name = 'memory_event_embeddings'").get();
  if (!exists) return;
  const columns = new Set(db.prepare('PRAGMA table_info(memory_event_embeddings)').all().map((row) => row.name));
  if (!columns.has('model_digest') || !columns.has('vector_sha256')) {
    db.exec('BEGIN IMMEDIATE');
    try {
      db.exec(`
        DROP INDEX IF EXISTS memory_event_embeddings_model_idx;
        ALTER TABLE memory_event_embeddings RENAME TO memory_event_embeddings_legacy;
        CREATE TABLE memory_event_embeddings (
          event_id TEXT NOT NULL REFERENCES memory_events(id),
          model TEXT NOT NULL,
          model_digest TEXT NOT NULL CHECK(length(model_digest) = 64),
          dimensions INTEGER NOT NULL CHECK(dimensions > 0),
          vector_sha256 TEXT NOT NULL CHECK(length(vector_sha256) = 64),
          vector_json TEXT NOT NULL,
          vector_blob BLOB,
          projected_at TEXT NOT NULL,
          metadata_json TEXT NOT NULL DEFAULT '{}',
          PRIMARY KEY(event_id, model, model_digest)
        );
        INSERT INTO memory_event_embeddings(
          event_id, model, model_digest, dimensions, vector_sha256, vector_json, projected_at, metadata_json
        )
        SELECT event_id, model,
          '0000000000000000000000000000000000000000000000000000000000000000',
          dimensions, digest, vector_json, projected_at, metadata_json
        FROM memory_event_embeddings_legacy;
        DROP TABLE memory_event_embeddings_legacy;
        CREATE INDEX memory_event_embeddings_model_idx
          ON memory_event_embeddings(model, model_digest, dimensions, projected_at);
      `);
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }
  addColumnIfMissing(db, 'memory_event_embeddings', 'vector_blob', 'BLOB');
}

function withStore(options, callback) {
  if (options && options.db) return callback(options.db);
  const db = openMemoryStore(options);
  try {
    return callback(db);
  } finally {
    db.close();
  }
}

function withImmediateTransaction(db, operation) {
  const ownsTransaction = !db.isTransaction;
  const savepoint = ownsTransaction ? null : `memory_capture_${captureSavepointCounter += 1}`;
  if (ownsTransaction) db.exec('BEGIN IMMEDIATE');
  else db.exec(`SAVEPOINT ${savepoint}`);
  try {
    const result = operation();
    if (ownsTransaction) db.exec('COMMIT');
    else db.exec(`RELEASE SAVEPOINT ${savepoint}`);
    return result;
  } catch (error) {
    if (ownsTransaction) {
      try { db.exec('ROLLBACK'); } catch {}
    } else {
      try {
        db.exec(`ROLLBACK TO SAVEPOINT ${savepoint}`);
        db.exec(`RELEASE SAVEPOINT ${savepoint}`);
      } catch {}
    }
    throw error;
  }
}

function withReadSnapshot(db, operation) {
  const ownsTransaction = !db.isTransaction;
  const savepoint = ownsTransaction ? null : `memory_read_${readSnapshotCounter += 1}`;
  if (ownsTransaction) db.exec('BEGIN');
  else db.exec(`SAVEPOINT ${savepoint}`);
  try {
    const result = operation();
    if (ownsTransaction) db.exec('COMMIT');
    else db.exec(`RELEASE SAVEPOINT ${savepoint}`);
    return result;
  } catch (error) {
    if (ownsTransaction) {
      try { db.exec('ROLLBACK'); } catch {}
    } else {
      try {
        db.exec(`ROLLBACK TO SAVEPOINT ${savepoint}`);
        db.exec(`RELEASE SAVEPOINT ${savepoint}`);
      } catch {}
    }
    throw error;
  }
}

const KNOWN_EVENT_FIELDS = new Set([
  'eventId', 'id', 'eventType', 'producer', 'source', 'sourceRef', 'sessionId', 'messageId', 'role',
  'wing', 'room', 'privacyScope', 'privacy_scope', 'content', 'text', 'createdAt', 'capturedAt',
  'metadata', 'status', 'provenance', 'sourceProfile', 'source_profile', 'sourcePlatform',
  'source_platform', 'sourceChatId', 'source_chat_id', 'sourceUserId', 'source_user_id',
  'sourceTopicId', 'source_topic_id', 'sourceSessionId', 'source_session_id', 'scopeKind',
  'scope_kind', 'authorizationVersion', 'authorization_version',
]);

function normalizeSupersessionCancellations(...values) {
  const pairs = new Map();
  const visit = (value) => {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (!value || typeof value !== 'object') return;
    const supersededEventId = validExternalId(value.superseded_event_id);
    const supersedingEventId = validExternalId(value.superseding_event_id);
    if (!supersededEventId || !supersedingEventId || supersededEventId === supersedingEventId) return;
    pairs.set(`${supersededEventId}\u0000${supersedingEventId}`, {
      superseded_event_id: supersededEventId,
      superseding_event_id: supersedingEventId,
    });
  };
  values.forEach(visit);
  return [...pairs.values()].sort((left, right) => (
    left.superseded_event_id.localeCompare(right.superseded_event_id)
      || left.superseding_event_id.localeCompare(right.superseding_event_id)
  ));
}

function canonicalizeCancellationMetadata(metadata) {
  const extensions = metadata.extensions && typeof metadata.extensions === 'object'
    && !Array.isArray(metadata.extensions)
    ? { ...metadata.extensions }
    : null;
  const cancellations = normalizeSupersessionCancellations(
    metadata.cancels_supersessions,
    extensions?.cancels_supersessions,
  );
  if (cancellations.length) metadata.cancels_supersessions = cancellations;
  else delete metadata.cancels_supersessions;
  if (extensions) {
    delete extensions.cancels_supersessions;
    if (Object.keys(extensions).length) metadata.extensions = extensions;
    else delete metadata.extensions;
  }
  return metadata;
}

function normalizeEvent(payload = {}, defaults = {}) {
  const source = cleanText(payload.source ?? defaults.source);
  const sessionId = cleanText(payload.sessionId ?? defaults.sessionId);
  const messageId = cleanText(payload.messageId ?? defaults.messageId);
  const role = cleanText(payload.role ?? defaults.role ?? 'unknown').toLowerCase();
  const content = sanitizeForMemory(String(payload.content ?? payload.text ?? '').replace(/\u0000/g, '\uFFFD')).text.trim();
  if (!source) throw new Error('memory event source is required');
  if (!sessionId) throw new Error('memory event sessionId is required');
  if (!messageId) throw new Error('memory event messageId is required');
  if (!content) throw new Error('memory event content is required');

  const contentSha256 = sha256(content);
  const eventType = cleanText(payload.eventType ?? defaults.eventType ?? 'message').toLowerCase() || 'message';
  const producer = cleanText(payload.producer ?? defaults.producer ?? source) || source;
  const sourceRef = cleanText(payload.sourceRef ?? defaults.sourceRef);
  const wing = cleanText(payload.wing ?? defaults.wing);
  const room = cleanText(payload.room ?? defaults.room);
  const privacyScope = cleanText(payload.privacyScope ?? payload.privacy_scope ?? defaults.privacyScope ?? defaults.privacy_scope ?? 'local') || 'local';
  const status = cleanText(payload.status ?? defaults.status ?? 'captured') || 'captured';
  const provenance = sanitizeValue(payload.provenance ?? defaults.provenance ?? {});
  const sourceProfile = cleanText(payload.sourceProfile ?? payload.source_profile ?? defaults.sourceProfile ?? defaults.source_profile);
  const sourcePlatform = cleanText(payload.sourcePlatform ?? payload.source_platform ?? defaults.sourcePlatform ?? defaults.source_platform).toLowerCase();
  const sourceChatId = cleanText(payload.sourceChatId ?? payload.source_chat_id ?? defaults.sourceChatId ?? defaults.source_chat_id);
  const sourceUserId = cleanText(payload.sourceUserId ?? payload.source_user_id ?? defaults.sourceUserId ?? defaults.source_user_id);
  const sourceTopicId = cleanText(payload.sourceTopicId ?? payload.source_topic_id ?? defaults.sourceTopicId ?? defaults.source_topic_id);
  const sourceSessionId = cleanText(payload.sourceSessionId ?? payload.source_session_id ?? defaults.sourceSessionId ?? defaults.source_session_id);
  const scopeKind = cleanText(payload.scopeKind ?? payload.scope_kind ?? defaults.scopeKind ?? defaults.scope_kind);
  const rawAuthorizationVersion = payload.authorizationVersion ?? payload.authorization_version
    ?? defaults.authorizationVersion ?? defaults.authorization_version ?? 0;
  const authorizationVersion = Number.isSafeInteger(Number(rawAuthorizationVersion))
    && Number(rawAuthorizationVersion) >= 0
    ? Number(rawAuthorizationVersion)
    : 0;
  const createdAt = normalizeTimestamp(payload.createdAt ?? defaults.createdAt);
  const capturedAt = normalizeTimestamp(payload.capturedAt ?? defaults.capturedAt);
  const explicitId = validExternalId(payload.eventId ?? payload.id);
  const identityParts = [
    CONTRACT_VERSION, eventType, source, sessionId, messageId, role, contentSha256,
  ];
  if (
    sourceProfile || sourcePlatform || sourceChatId || sourceUserId || sourceTopicId
    || sourceSessionId || scopeKind || authorizationVersion
  ) {
    identityParts.push(
      sourceProfile, sourcePlatform, sourceChatId, sourceUserId, sourceTopicId,
      sourceSessionId, scopeKind, authorizationVersion,
    );
  }
  const deterministic = sha256(identityParts.join('\u001f'));

  const metadata = { ...(sanitizeValue(defaults.metadata || {})), ...(sanitizeValue(payload.metadata || {})) };
  if (payload.status !== undefined) metadata.status = sanitizeValue(payload.status);
  if (payload.provenance !== undefined) metadata.provenance = sanitizeValue(payload.provenance);
  const extensions = {};
  for (const [key, value] of Object.entries(payload)) {
    if (!KNOWN_EVENT_FIELDS.has(key) && value !== undefined) extensions[key] = sanitizeValue(value);
  }
  if (Object.keys(extensions).length) metadata.extensions = extensions;
  canonicalizeCancellationMetadata(metadata);

  return {
    id: explicitId || `mem_${deterministic}`,
    contractVersion: CONTRACT_VERSION,
    eventType,
    producer,
    source,
    sourceRef,
    sessionId,
    messageId,
    role,
    wing,
    room,
    privacyScope,
    status,
    provenance,
    content,
    contentSha256,
    createdAt,
    capturedAt,
    metadata,
    sourceProfile,
    sourcePlatform,
    sourceChatId,
    sourceUserId,
    sourceTopicId,
    sourceSessionId,
    scopeKind,
    authorizationVersion,
  };
}

function rowToEvent(row) {
  if (!row) return null;
  return {
    id: row.id,
    contractVersion: row.contract_version,
    eventType: row.event_type,
    producer: row.producer,
    source: row.source,
    sourceRef: row.source_ref,
    sessionId: row.session_id,
    messageId: row.message_id,
    role: row.role,
    wing: row.wing,
    room: row.room,
    privacyScope: row.privacy_scope,
    status: row.status,
    provenance: parseJson(row.provenance_json, {}),
    content: row.content,
    contentSha256: row.content_sha256,
    createdAt: row.created_at,
    capturedAt: row.captured_at,
    metadata: parseJson(row.metadata_json, {}),
    sourceProfile: row.source_profile || '',
    sourcePlatform: row.source_platform || '',
    sourceChatId: row.source_chat_id || '',
    sourceUserId: row.source_user_id || '',
    sourceTopicId: row.source_topic_id || '',
    sourceSessionId: row.source_session_id || '',
    scopeKind: row.scope_kind || '',
    authorizationVersion: Number(row.authorization_version || 0),
    projected: Boolean(row.projected),
    superseded: Boolean(row.superseded),
    lexicalScore: row.lexical_score === undefined ? undefined : Number(row.lexical_score),
    memoryKey: `content:${row.content_sha256}`,
  };
}

function supersededIdsFromEvent(event) {
  const metadata = event && event.metadata && typeof event.metadata === 'object' ? event.metadata : {};
  const values = [metadata.supersedes, metadata.extensions && metadata.extensions.supersedes];
  const ids = [];
  const visit = (value) => {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    const id = validExternalId(value);
    if (id && id !== event.id) ids.push(id);
  };
  values.forEach(visit);
  return [...new Set(ids)].sort();
}

function supersessionCancellationsFromEvent(event) {
  const metadata = event && event.metadata && typeof event.metadata === 'object' ? event.metadata : {};
  return normalizeSupersessionCancellations(
    metadata.cancels_supersessions,
    metadata.extensions && metadata.extensions.cancels_supersessions,
  );
}

function recordSupersessions(db, event) {
  const statement = db.prepare(`
    INSERT OR IGNORE INTO memory_event_supersessions(
      superseded_event_id, superseding_event_id, recorded_at, metadata_json
    ) VALUES (?, ?, ?, ?)
  `);
  for (const supersededId of supersededIdsFromEvent(event)) {
    statement.run(
      supersededId,
      event.id,
      event.capturedAt,
      stableJson({ source: 'event_metadata' }),
    );
  }
}

function recordSupersessionCancellations(db, event) {
  const statement = db.prepare(`
    INSERT OR IGNORE INTO memory_event_supersession_cancellations(
      superseded_event_id, superseding_event_id, cancellation_event_id, recorded_at, metadata_json
    ) VALUES (?, ?, ?, ?, ?)
  `);
  for (const cancellation of supersessionCancellationsFromEvent(event)) {
    statement.run(
      cancellation.superseded_event_id,
      cancellation.superseding_event_id,
      event.id,
      event.capturedAt,
      stableJson({ source: 'event_metadata' }),
    );
  }
}

function insertEvent(db, payload, defaults = {}) {
  const event = normalizeEvent(payload, defaults);
  const result = db.prepare(`
    INSERT OR IGNORE INTO memory_events(
      id, contract_version, event_type, producer, source, source_ref, session_id, message_id,
      role, wing, room, privacy_scope, status, provenance_json, content, content_sha256,
      created_at, captured_at, metadata_json, source_profile, source_platform, source_chat_id,
      source_user_id, source_topic_id, source_session_id, scope_kind, authorization_version
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    event.id, event.contractVersion, event.eventType, event.producer, event.source, event.sourceRef,
    event.sessionId, event.messageId, event.role, event.wing, event.room, event.privacyScope,
    event.status, stableJson(event.provenance), event.content, event.contentSha256,
    event.createdAt, event.capturedAt, stableJson(event.metadata), event.sourceProfile,
    event.sourcePlatform, event.sourceChatId, event.sourceUserId, event.sourceTopicId,
    event.sourceSessionId, event.scopeKind, event.authorizationVersion,
  );
  const row = db.prepare('SELECT * FROM memory_events WHERE id = ?').get(event.id);
  const expected = {
    contract_version: event.contractVersion,
    event_type: event.eventType,
    producer: event.producer,
    source: event.source,
    source_ref: event.sourceRef,
    session_id: event.sessionId,
    message_id: event.messageId,
    role: event.role,
    wing: event.wing,
    room: event.room,
    privacy_scope: event.privacyScope,
    status: event.status,
    provenance_json: stableJson(event.provenance),
    content: event.content,
    content_sha256: event.contentSha256,
    metadata_json: stableJson(event.metadata),
    source_profile: event.sourceProfile,
    source_platform: event.sourcePlatform,
    source_chat_id: event.sourceChatId,
    source_user_id: event.sourceUserId,
    source_topic_id: event.sourceTopicId,
    source_session_id: event.sourceSessionId,
    scope_kind: event.scopeKind,
    authorization_version: event.authorizationVersion,
  };
  if (payload.createdAt !== undefined || payload.created_at !== undefined
      || defaults.createdAt !== undefined || defaults.created_at !== undefined) {
    expected.created_at = event.createdAt;
  }
  if (payload.capturedAt !== undefined || payload.captured_at !== undefined) {
    expected.captured_at = event.capturedAt;
  }
  const mismatches = !row ? ['missing'] : Object.entries(expected)
    .filter(([field, value]) => row[field] !== value)
    .map(([field]) => field);
  if (mismatches.length) {
    throw new Error(`memory event id collision for ${event.id}: ${mismatches.join(', ')}`);
  }
  const storedEvent = rowToEvent(row);
  recordSupersessions(db, storedEvent);
  recordSupersessionCancellations(db, storedEvent);
  return { inserted: Number(result.changes || 0) === 1, event: storedEvent };
}

function captureEvent(payload, options = {}) {
  return withStore(options, (db) => withImmediateTransaction(db, () => insertEvent(db, payload)));
}

function captureMessage(payload, options = {}) {
  return captureEvent({ eventType: 'message', ...payload }, options);
}

function captureTurn(payload = {}, options = {}) {
  const messages = Array.isArray(payload.messages) ? payload.messages : [];
  if (!messages.length) throw new Error('captureTurn requires at least one message');
  return withStore(options, (db) => {
    db.exec('BEGIN IMMEDIATE');
    try {
      const defaults = {
        source: payload.source,
        producer: payload.producer,
        sourceRef: payload.sourceRef,
        sessionId: payload.sessionId,
        wing: payload.wing,
        room: payload.room,
        privacyScope: payload.privacyScope ?? payload.privacy_scope,
        status: payload.status,
        provenance: payload.provenance,
        eventType: payload.eventType || 'message',
        metadata: payload.metadata,
        createdAt: payload.createdAt,
      };
      const events = messages.map((message, index) => insertEvent(db, {
        ...message,
        messageId: message.messageId || `${payload.turnId || 'turn'}:${index + 1}`,
      }, defaults));
      db.exec('COMMIT');
      return {
        contractVersion: CONTRACT_VERSION,
        insertedCount: events.filter((item) => item.inserted).length,
        existingCount: events.filter((item) => !item.inserted).length,
        events: events.map((item) => item.event),
      };
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  });
}

function listPendingEvents(filters = {}, options = {}) {
  return withStore(options, (db) => {
    const target = cleanText(filters.target || 'mempalace');
    const limit = Math.max(1, Number(filters.limit || 1000));
    const supersededSql = supersededEventSql('e');
    const clauses = [`NOT EXISTS (
      SELECT 1 FROM memory_projections p
      WHERE p.event_id = e.id AND p.target = ? AND p.status = 'success'
    )`];
    const params = [target];
    appendCurrentEventClauses(clauses, filters, 'e');
    if (filters.source) { clauses.push('e.source = ?'); params.push(cleanText(filters.source)); }
    if (filters.eventType || filters.event_type) {
      clauses.push('e.event_type = ?');
      params.push(cleanText(filters.eventType || filters.event_type).toLowerCase());
    }
    params.push(limit);
    const rows = db.prepare(`
      SELECT e.*, 0 AS projected, ${supersededSql} AS superseded
      FROM memory_events e
      WHERE ${clauses.join(' AND ')}
      ORDER BY e.created_at, e.rowid
      LIMIT ?
    `).all(...params);
    return rows.map(rowToEvent);
  });
}

function markEventsProjected(eventIds, projection = {}, options = {}) {
  const ids = [...new Set((eventIds || []).map(cleanText).filter(Boolean))];
  return withStore(options, (db) => {
    const target = cleanText(projection.target || 'mempalace');
    const projectedAt = normalizeTimestamp(projection.projectedAt);
    const refs = projection.projectionRefs || {};
    const metadataJson = stableJson(sanitizeValue(projection.metadata || {}));
    const statement = db.prepare(`
      INSERT OR IGNORE INTO memory_projections(
        projection_id, event_id, target, status, projected_at, projection_ref, metadata_json
      ) VALUES (?, ?, ?, 'success', ?, ?, ?)
    `);
    db.exec('BEGIN IMMEDIATE');
    try {
      let insertedCount = 0;
      for (const eventId of ids) {
        const projectionId = `proj_${sha256([CONTRACT_VERSION, eventId, target, 'success'].join('\u001f'))}`;
        const projectionRef = cleanText(refs[eventId] || projection.projectionRef || '');
        insertedCount += Number(statement.run(
          projectionId, eventId, target, projectedAt, projectionRef, metadataJson,
        ).changes || 0);
      }
      db.exec('COMMIT');
      return { target, requestedCount: ids.length, insertedCount };
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  });
}

function normalizeVector(vector, dimensions) {
  if (!Array.isArray(vector) || !vector.length) throw new Error('embedding vector is required');
  const values = vector.map((value) => Number(value));
  if (values.some((value) => !Number.isFinite(value))) throw new Error('embedding vector must contain finite numbers');
  const expected = dimensions === undefined || dimensions === null ? values.length : Number(dimensions);
  if (!Number.isInteger(expected) || expected <= 0 || expected !== values.length) {
    throw new Error(`embedding dimensions ${expected} do not match vector length ${values.length}`);
  }
  return values;
}

function vectorBlob(vector) {
  const encoded = Buffer.allocUnsafe(vector.length * 8);
  vector.forEach((value, index) => encoded.writeDoubleLE(value, index * 8));
  return encoded;
}

function vectorFromBlob(blob, dimensions) {
  if (blob === null || blob === undefined) return null;
  let encoded = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
  const length = Number(dimensions);
  if (encoded.length !== length * 8) return null;
  if (encoded.byteOffset % 8 !== 0) {
    const aligned = Buffer.allocUnsafeSlow(encoded.length);
    encoded.copy(aligned);
    encoded = aligned;
  }
  return new Float64Array(encoded.buffer, encoded.byteOffset, length);
}

function vectorSha256(vector) {
  const buffer = Buffer.allocUnsafe(vector.length * 8);
  vector.forEach((value, index) => buffer.writeDoubleBE(value, index * 8));
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function requiredSha256(value, label) {
  const digest = cleanText(value).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(digest)) throw new Error(`${label} must be a 64-character SHA-256 digest`);
  return digest;
}

function upsertEventEmbedding(eventId, embedding = {}, options = {}) {
  const id = cleanText(eventId || embedding.eventId || embedding.event_id);
  const model = cleanText(embedding.model);
  if (!id) throw new Error('embedding eventId is required');
  if (!model) throw new Error('embedding model is required');
  const modelDigest = requiredSha256(
    embedding.modelDigest || embedding.model_digest || embedding.digest,
    'embedding model digest',
  );
  const vector = normalizeVector(embedding.vector, embedding.dimensions);
  const vectorChecksum = vectorSha256(vector);
  const suppliedVectorChecksum = cleanText(embedding.vectorSha256 || embedding.vector_sha256).toLowerCase();
  if (suppliedVectorChecksum && suppliedVectorChecksum !== vectorChecksum) {
    throw new Error('embedding vector_sha256 does not match vector');
  }
  return withStore(options, (db) => {
    if (!db.prepare('SELECT 1 AS found FROM memory_events WHERE id = ?').get(id)) {
      throw new Error(`memory event not found: ${id}`);
    }
    const encodedVector = vectorBlob(vector);
    db.prepare(`
      INSERT INTO memory_event_embeddings(
        event_id, model, model_digest, dimensions, vector_sha256, vector_json, vector_blob, projected_at, metadata_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(event_id, model, model_digest) DO UPDATE SET
        dimensions = excluded.dimensions,
        vector_sha256 = excluded.vector_sha256,
        vector_json = excluded.vector_json,
        vector_blob = excluded.vector_blob,
        projected_at = excluded.projected_at,
        metadata_json = excluded.metadata_json
    `).run(
      id, model, modelDigest, vector.length, vectorChecksum, JSON.stringify(vector), encodedVector,
      normalizeTimestamp(embedding.projectedAt || embedding.projected_at),
      stableJson(sanitizeValue(embedding.metadata || {})),
    );
    db.prepare(`
      INSERT INTO memory_event_embedding_vectors(
        event_id, model, model_digest, dimensions, vector_sha256, vector_blob
      ) VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(event_id, model, model_digest) DO UPDATE SET
        dimensions = excluded.dimensions,
        vector_sha256 = excluded.vector_sha256,
        vector_blob = excluded.vector_blob
    `).run(id, model, modelDigest, vector.length, vectorChecksum, encodedVector);
    return { eventId: id, model, modelDigest, dimensions: vector.length, vectorSha256: vectorChecksum };
  });
}

function backfillEventEmbeddingVectorBlobs(options = {}) {
  if (options.readOnly) throw new Error('embedding vector blobs require a writable memory store');
  const batchSize = Math.max(1, Math.min(1000, Number(options.batchSize || 250)));
  return withStore(options, (db) => {
    const select = db.prepare(`
      SELECT x.event_id, x.model, x.model_digest, x.dimensions, x.vector_json, x.vector_blob
      FROM memory_event_embeddings x
      LEFT JOIN memory_event_embedding_vectors v
        ON v.event_id = x.event_id AND v.model = x.model AND v.model_digest = x.model_digest
      WHERE x.vector_blob IS NULL OR length(x.vector_blob) <> x.dimensions * 8
        OR v.event_id IS NULL OR v.dimensions <> x.dimensions OR v.vector_sha256 <> x.vector_sha256
      LIMIT ?
    `);
    const updateBlob = db.prepare(`
      UPDATE memory_event_embeddings
      SET vector_blob = ?
      WHERE event_id = ? AND model = ? AND model_digest = ?
    `);
    const updateVector = db.prepare(`
      INSERT INTO memory_event_embedding_vectors(
        event_id, model, model_digest, dimensions, vector_sha256, vector_blob
      )
      SELECT event_id, model, model_digest, dimensions, vector_sha256, ?
      FROM memory_event_embeddings
      WHERE event_id = ? AND model = ? AND model_digest = ?
      ON CONFLICT(event_id, model, model_digest) DO UPDATE SET
        dimensions = excluded.dimensions,
        vector_sha256 = excluded.vector_sha256,
        vector_blob = excluded.vector_blob
    `);
    let updated = 0;
    while (true) {
      const rows = select.all(batchSize);
      if (!rows.length) break;
      db.exec('BEGIN IMMEDIATE');
      try {
        for (const row of rows) {
          const existing = vectorFromBlob(row.vector_blob, row.dimensions);
          const encodedVector = existing ? Buffer.from(row.vector_blob) : vectorBlob(
            normalizeVector(parseJson(row.vector_json, []), row.dimensions),
          );
          if (!existing) updateBlob.run(encodedVector, row.event_id, row.model, row.model_digest);
          updateVector.run(encodedVector, row.event_id, row.model, row.model_digest);
          updated += 1;
        }
        db.exec('COMMIT');
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
    }
    return { updated };
  });
}

function listEmbeddableEvents(filters = {}, options = {}) {
  const model = cleanText(filters.model);
  if (!model) throw new Error('embedding model is required');
  const modelDigest = requiredSha256(filters.modelDigest || filters.model_digest || filters.digest, 'embedding model digest');
  const dimensions = Number(filters.dimensions);
  if (!Number.isInteger(dimensions) || dimensions <= 0) throw new Error('embedding dimensions must be a positive integer');
  return withStore(options, (db) => {
    const clauses = ['x.event_id IS NULL'];
    const params = [model, modelDigest, dimensions];
    const supersededSql = supersededEventSql('e');
    appendCurrentEventClauses(clauses, filters, 'e');
    if (filters.source) { clauses.push('e.source = ?'); params.push(cleanText(filters.source)); }
    if (filters.status) { clauses.push('e.status = ?'); params.push(cleanText(filters.status)); }
    params.push(Math.max(1, Number(filters.limit || 100)));
    return db.prepare(`
      SELECT e.*, 0 AS projected, ${supersededSql} AS superseded
      FROM memory_events e
      LEFT JOIN memory_event_embeddings x
        ON x.event_id = e.id AND x.model = ? AND x.model_digest = ? AND x.dimensions = ?
      WHERE ${clauses.join(' AND ')}
      ORDER BY e.created_at, e.rowid
      LIMIT ?
    `).all(...params).map(rowToEvent);
  });
}

function cosineSimilarity(left, right) {
  if (!right || right.length !== left.length) {
    throw new Error('embedding dimensions do not match');
  }
  let dot = 0;
  let leftMagnitude = 0;
  let rightMagnitude = 0;
  for (let index = 0; index < left.length; index += 1) {
    const rightValue = right[index];
    if (!Number.isFinite(rightValue)) throw new Error('embedding vector must contain finite numbers');
    dot += left[index] * rightValue;
    leftMagnitude += left[index] * left[index];
    rightMagnitude += rightValue * rightValue;
  }
  if (!leftMagnitude || !rightMagnitude) return 0;
  return dot / (Math.sqrt(leftMagnitude) * Math.sqrt(rightMagnitude));
}

function semanticRankingRows(db, vector, model, modelDigest, filters = {}) {
  const hasCompactVectors = Boolean(db.prepare(
    "SELECT 1 AS found FROM sqlite_master WHERE type = 'table' AND name = 'memory_event_embedding_vectors'",
  ).get());
  const hasVectorBlob = db.prepare('PRAGMA table_info(memory_event_embeddings)').all()
    .some((column) => column.name === 'vector_blob');
  const clauses = ['x.model = ?', 'x.model_digest = ?', 'x.dimensions = ?'];
  const params = [model, modelDigest, vector.length];
  const supersededSql = supersededEventSql('e');
  appendCurrentEventClauses(clauses, filters, 'e');
  if (filters.wing) { clauses.push('e.wing = ?'); params.push(cleanText(filters.wing)); }
  if (filters.room) { clauses.push('e.room = ?'); params.push(cleanText(filters.room)); }
  for (const sessionId of [...new Set(filters.excludeSessionIds || [])]) {
    clauses.push('e.session_id <> ?'); params.push(cleanText(sessionId));
  }
  for (const source of [...new Set(filters.excludeSources || [])]) {
    clauses.push('e.source <> ?'); params.push(cleanText(source));
  }
  const candidateEventIds = [...new Set(Array.isArray(filters.candidateEventIds)
    ? filters.candidateEventIds.map(cleanText).filter(Boolean).slice(0, 100)
    : [])];
  if (Array.isArray(filters.candidateEventIds) && !candidateEventIds.length) return [];
  if (candidateEventIds.length) {
    clauses.push(`e.id IN (${candidateEventIds.map(() => '?').join(', ')})`);
    params.push(...candidateEventIds);
  }
  const compactBlob = hasCompactVectors
    ? `CASE WHEN v.event_id IS NOT NULL
        AND v.dimensions = x.dimensions
        AND v.vector_sha256 = x.vector_sha256
        AND length(v.vector_blob) = x.dimensions * 8
      THEN v.vector_blob ELSE NULL END`
    : 'NULL';
  const canonicalBlob = hasVectorBlob
    ? 'CASE WHEN length(x.vector_blob) = x.dimensions * 8 THEN x.vector_blob ELSE NULL END'
    : 'NULL';
  const rows = db.prepare(`
    SELECT e.id, x.model AS embedding_model, x.dimensions AS embedding_dimensions,
      x.model_digest AS embedding_model_digest, x.vector_sha256,
      ${filters.markCurrent ? `CASE WHEN NOT ${supersededSql} AND NOT ${lifecycleControlEventSql('e')} THEN 1 ELSE 0 END` : '1'} AS is_current,
      COALESCE(${compactBlob}, ${canonicalBlob}) AS vector_blob,
      CASE WHEN COALESCE(${compactBlob}, ${canonicalBlob}) IS NULL THEN x.vector_json ELSE NULL END AS vector_json
    FROM ${candidateEventIds.length ? 'memory_events e CROSS JOIN memory_event_embeddings x ON e.id = x.event_id' : 'memory_event_embeddings x'}
    ${hasCompactVectors ? `LEFT JOIN memory_event_embedding_vectors v
      ON v.event_id = x.event_id AND v.model = x.model AND v.model_digest = x.model_digest` : ''}
    ${candidateEventIds.length ? '' : 'JOIN memory_events e ON e.id = x.event_id'}
    WHERE ${clauses.join(' AND ')}
  `).all(...params);
  return rows.map((row) => {
    let storedVector = vectorFromBlob(row.vector_blob, row.embedding_dimensions);
    if (!storedVector || vectorSha256(storedVector) !== row.vector_sha256) {
      const canonicalJson = row.vector_json ?? db.prepare(`
        SELECT vector_json FROM memory_event_embeddings
        WHERE event_id = ? AND model = ? AND model_digest = ?
      `).get(row.id, model, modelDigest)?.vector_json;
      storedVector = normalizeVector(parseJson(canonicalJson, []), row.embedding_dimensions);
    }
    const similarity = cosineSimilarity(vector, storedVector);
    return {
      id: row.id,
      _current: Boolean(row.is_current),
      semanticSimilarity: Number(similarity.toFixed(6)),
      embedding: {
        model: row.embedding_model,
        modelDigest: row.embedding_model_digest,
        dimensions: row.embedding_dimensions,
        vectorSha256: row.vector_sha256,
      },
    };
  }).sort((left, right) => right.semanticSimilarity - left.semanticSimilarity);
}

function hydrateSemanticCandidates(db, ranked) {
  if (!ranked.length) return [];
  const placeholders = ranked.map(() => '?').join(', ');
  const supersededSql = supersededEventSql('e');
  const byId = new Map(db.prepare(`
    SELECT e.*, ${supersededSql} AS superseded,
      EXISTS(SELECT 1 FROM memory_projections p WHERE p.event_id = e.id AND p.target = 'mempalace' AND p.status = 'success') AS projected
    FROM memory_events e
    WHERE e.id IN (${placeholders})
  `).all(...ranked.map((row) => row.id)).map((row) => [row.id, row]));
  return ranked.map(({ _current, ...row }) => ({ ...rowToEvent(byId.get(row.id)), ...row }));
}

function semanticSearchEvents(queryVector, filters = {}, options = {}) {
  const model = cleanText(filters.model);
  if (!model) throw new Error('embedding model is required');
  const modelDigest = requiredSha256(filters.modelDigest || filters.model_digest || filters.digest, 'embedding model digest');
  const vector = normalizeVector(queryVector, filters.dimensions);
  return withStore(options, (db) => withReadSnapshot(db, () => hydrateSemanticCandidates(
    db,
    semanticRankingRows(db, vector, model, modelDigest, filters)
      .slice(0, Math.max(1, Number(filters.limit || DEFAULT_SEARCH_LIMIT))),
  )));
}

function ftsQuery(value) {
  const terms = cleanText(value).toLowerCase().match(/[\p{L}\p{N}_]{2,}/gu) || [];
  return [...new Set(terms)].slice(0, 16).map((term) => `"${term.replace(/"/g, '""')}"`).join(' OR ');
}

function normalizedLexicalScore(rank) {
  const quality = Math.max(0, -Number(rank || 0));
  return Number((quality / (1 + quality)).toFixed(6));
}

function rankedLexicalRows(db, clauses, params, limit, supersededSql) {
  const iterator = db.prepare("SELECT rowid, rank FROM memory_events_fts WHERE memory_events_fts MATCH ? AND rank MATCH 'bm25()' ORDER BY rank").iterate(params[0]);
  let selected = [];
  try {
    while (true) {
      const batch = [];
      let exhausted = false;
      for (let i = 0; i < 64; i += 1) {
        const item = iterator.next();
        if (item.done) { exhausted = true; break; }
        batch.push(item.value);
      }
      if (!batch.length) break;
      const filtered = clauses.slice(1);
      const rows = db.prepare(`
        WITH candidate(rowid, rank) AS (VALUES ${batch.map(() => '(?, ?)').join(',')})
        SELECT e.*, candidate.rank, ${supersededSql} AS superseded,
          EXISTS(SELECT 1 FROM memory_projections p WHERE p.event_id=e.id AND p.target='mempalace' AND p.status='success') AS projected
        FROM candidate CROSS JOIN memory_events e ON e.rowid=candidate.rowid
        ${filtered.length ? 'WHERE ' + filtered.join(' AND ') : ''}
        ORDER BY candidate.rank, e.created_at DESC
      `).all(...batch.flatMap(row => [row.rowid, row.rank]), ...params.slice(1));
      selected.push(...rows);
      selected.sort((a, b) => a.rank - b.rank || Buffer.compare(Buffer.from(b.created_at), Buffer.from(a.created_at)));
      selected = selected.slice(0, limit);
      // Exhaustion is terminal: never advance a completed native iterator again.
      // A strict score boundary preserves the whole tie group after filtering.
      if (exhausted || (selected.length >= limit && batch.at(-1).rank > selected.at(-1).rank)) break;
    }
    return selected;
  } finally { iterator.return?.(); }
}

function lexicalSearchEvents(query, filters = {}, options = {}) {
  const match = ftsQuery(query);
  if (!match) return [];
  return withStore(options, (db) => withReadSnapshot(db, () => {
    const clauses = ['memory_events_fts MATCH ?'];
    const params = [match];
    const supersededSql = supersededEventSql('e');
    appendCurrentEventClauses(clauses, filters, 'e');
    if (filters.wing) { clauses.push('e.wing = ?'); params.push(cleanText(filters.wing)); }
    if (filters.room) { clauses.push('e.room = ?'); params.push(cleanText(filters.room)); }
    if (filters.pendingOnly) {
      clauses.push("NOT EXISTS (SELECT 1 FROM memory_projections px WHERE px.event_id = e.id AND px.target = ? AND px.status = 'success')");
      params.push(cleanText(filters.target || 'mempalace'));
    }
    for (const sessionId of [...new Set(filters.excludeSessionIds || [])]) {
      clauses.push('e.session_id <> ?'); params.push(cleanText(sessionId));
    }
    for (const source of [...new Set(filters.excludeSources || [])]) {
      clauses.push('e.source <> ?'); params.push(cleanText(source));
    }
    const limit = Math.max(1, Number(filters.limit || DEFAULT_SEARCH_LIMIT));
    const rows = rankedLexicalRows(db, clauses, params, limit, supersededSql);
    return rows.map((row) => rowToEvent({ ...row, lexical_score: normalizedLexicalScore(row.rank) }));
  }));
}

function upsertMempalaceDocuments(documents, options = {}) {
  return withStore(options, (db) => {
    const statement = db.prepare(`
      INSERT INTO mempalace_documents(
        doc_id, content, content_sha256, wing, room, source_file, event_id, event_source,
        event_session_id, indexed_at, metadata_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(doc_id) DO UPDATE SET
        content = excluded.content,
        content_sha256 = excluded.content_sha256,
        wing = excluded.wing,
        room = excluded.room,
        source_file = excluded.source_file,
        event_id = excluded.event_id,
        event_source = excluded.event_source,
        event_session_id = excluded.event_session_id,
        indexed_at = excluded.indexed_at,
        metadata_json = excluded.metadata_json
    `);
    db.exec('BEGIN IMMEDIATE');
    try {
      let upsertedCount = 0;
      for (const document of documents || []) {
        const content = sanitizeForMemory(String(document.text ?? document.content ?? '')).text.trim();
        if (!content) continue;
        const id = cleanText(document.id || document.docId) || `doc_${sha256(content)}`;
        statement.run(
          id, content, sha256(content), cleanText(document.wing), cleanText(document.room),
          cleanText(document.sourceFile || document.source_file), cleanText(document.eventId || document.event_id),
          cleanText(document.eventSource || document.event_source),
          cleanText(document.eventSessionId || document.event_session_id),
          normalizeTimestamp(document.indexedAt), stableJson(sanitizeValue(document.metadata || {})),
        );
        upsertedCount += 1;
      }
      db.exec('COMMIT');
      return { upsertedCount };
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  });
}

function lexicalSearchDocuments(query, filters = {}, options = {}) {
  const match = ftsQuery(query);
  if (!match) return [];
  return withStore(options, (db) => {
    const clauses = ['mempalace_documents_fts MATCH ?'];
    const params = [match];
    const supersededSql = supersededEventSql('e');
    clauses.push("NOT (COALESCE(e.source, '') = 'llm-wiki' AND COALESCE(e.event_type, '') = 'fact')");
    if (!wantsSuperseded(filters)) {
      clauses.push(`(e.id IS NULL OR (NOT ${supersededSql} AND NOT ${lifecycleControlEventSql('e')}))`);
    }
    if (filters.wing) { clauses.push('d.wing = ?'); params.push(cleanText(filters.wing)); }
    if (filters.room) { clauses.push('d.room = ?'); params.push(cleanText(filters.room)); }
    for (const sessionId of [...new Set(filters.excludeSessionIds || [])]) {
      clauses.push("(d.event_session_id = '' OR d.event_session_id <> ?)"); params.push(cleanText(sessionId));
    }
    for (const source of [...new Set(filters.excludeSources || [])]) {
      clauses.push("(d.event_source = '' OR d.event_source <> ?)"); params.push(cleanText(source));
    }
    params.push(Math.max(1, Number(filters.limit || DEFAULT_SEARCH_LIMIT)));
    return db.prepare(`
      SELECT d.*, bm25(mempalace_documents_fts) AS rank
      FROM mempalace_documents_fts
      JOIN mempalace_documents d ON d.rowid = mempalace_documents_fts.rowid
      LEFT JOIN memory_events e ON e.id = d.event_id
      WHERE ${clauses.join(' AND ')}
      ORDER BY rank, d.indexed_at DESC
      LIMIT ?
    `).all(...params).map((row) => ({
      id: row.doc_id,
      text: row.content,
      contentSha256: row.content_sha256,
      wing: row.wing,
      room: row.room,
      sourceFile: row.source_file,
      eventId: row.event_id,
      eventSource: row.event_source,
      eventSessionId: row.event_session_id,
      indexedAt: row.indexed_at,
      metadata: parseJson(row.metadata_json, {}),
      lexicalScore: normalizedLexicalScore(row.rank),
      memoryKey: `content:${row.content_sha256}`,
    }));
  });
}

function recordRetrievalTrace(trace = {}, options = {}) {
  const sanitizedQuery = cleanText(trace.query);
  const queryDigest = queryHmacSha256(sanitizedQuery, options);
  return withStore(options, (db) => {
    const traceId = validExternalId(trace.traceId) || `trace_${crypto.randomUUID()}`;
    const resultIds = (trace.resultIds || []).map(cleanText).filter(Boolean);
    const storePreview = ['1', 'true', 'yes'].includes(String(process.env.MEMORY_TRACE_STORE_QUERY || '').toLowerCase());
    const queryPreview = storePreview ? sanitizedQuery.slice(0, 240) : '';
    const metadata = {
      ...sanitizeValue(trace.metadata || {}),
      queryDigestAlgorithm: 'hmac-sha256-v1',
    };
    db.prepare(`
      INSERT OR IGNORE INTO memory_retrieval_traces(
        trace_id, contract_version, query, query_sha256, query_preview, consumer, session_id,
        source, result_ids_json, result_count, filters_json, metadata_json, created_at
      ) VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      traceId, CONTRACT_VERSION, queryDigest, queryPreview, cleanText(trace.consumer || 'unknown'),
      cleanText(trace.sessionId), cleanText(trace.source), stableJson(resultIds), resultIds.length,
      stableJson(sanitizeValue(trace.filters || {})), stableJson(metadata),
      normalizeTimestamp(trace.createdAt),
    );
    return {
      traceId,
      querySha256: queryDigest,
      queryDigestAlgorithm: 'hmac-sha256-v1',
      queryPreview,
      resultCount: resultIds.length,
    };
  });
}

function servedMemoryKeys(db, consumer, sessionId) {
  return new Set(db.prepare(`
    SELECT memory_key FROM memory_served_items WHERE consumer = ? AND session_id = ?
  `).all(cleanText(consumer), cleanText(sessionId)).map((row) => row.memory_key));
}

function markItemsServed(items, serving = {}, options = {}) {
  return withStore(options, (db) => {
    const consumer = cleanText(serving.consumer || 'unknown');
    const sessionId = cleanText(serving.sessionId);
    if (!sessionId) throw new Error('markItemsServed sessionId is required');
    const statement = db.prepare(`
      INSERT OR IGNORE INTO memory_served_items(
        serve_id, memory_key, consumer, session_id, source, trace_id, served_at, metadata_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    let insertedCount = 0;
    for (const item of items || []) {
      const memoryKey = cleanText(item.memoryKey || item.memory_key);
      if (!memoryKey) continue;
      const serveId = `serve_${sha256([memoryKey, consumer, sessionId].join('\u001f'))}`;
      insertedCount += Number(statement.run(
        serveId, memoryKey, consumer, sessionId, cleanText(serving.source), cleanText(serving.traceId),
        normalizeTimestamp(serving.servedAt), stableJson(sanitizeValue(serving.metadata || {})),
      ).changes || 0);
    }
    return { insertedCount };
  });
}

function mergeRankedEventCandidates(semanticCandidates, lexicalCandidates) {
  const reciprocalRankConstant = 60;
  const byKey = new Map();
  const addChannel = (candidates, channel) => {
    const seenKeys = new Set();
    candidates.forEach((candidate, index) => {
      const key = candidate.memoryKey;
      if (!key || seenKeys.has(key)) return;
      seenKeys.add(key);
      const contribution = 1 / (reciprocalRankConstant + index + 1);
      const current = byKey.get(key);
      if (!current) {
        byKey.set(key, {
          ...candidate,
          retrievalChannels: [channel],
          _rankScore: contribution,
          _bestChannelContribution: contribution,
        });
        return;
      }
      current._rankScore += contribution;
      if (!current.retrievalChannels.includes(channel)) current.retrievalChannels.push(channel);
      if (contribution > current._bestChannelContribution
          || (contribution === current._bestChannelContribution
            && String(candidate.createdAt).localeCompare(String(current.createdAt)) > 0)) {
        const rankScore = current._rankScore;
        const retrievalChannels = current.retrievalChannels;
        Object.assign(current, candidate, {
          retrievalChannels,
          _rankScore: rankScore,
          _bestChannelContribution: contribution,
        });
      }
    });
  };
  addChannel(semanticCandidates, 'event_embedding');
  addChannel(lexicalCandidates, 'event_fts');
  return [...byKey.values()].sort((left, right) => (
    right._rankScore - left._rankScore
      || right._bestChannelContribution - left._bestChannelContribution
      || String(right.createdAt).localeCompare(String(left.createdAt))
      || String(left.id).localeCompare(String(right.id))
  )).map(({ _bestChannelContribution, ...candidate }) => candidate);
}

const STRUCTURAL_STOP_WORDS = new Set([
  'and', 'are', 'for', 'from', 'that', 'the', 'this', 'with',
  'без', 'для', 'или', 'как', 'при', 'что', 'это',
]);

function structuralTokens(value) {
  return new Set((cleanText(value).toLowerCase().match(/[\p{L}\p{N}_]{3,}/gu) || [])
    .filter((token) => !STRUCTURAL_STOP_WORDS.has(token)));
}

function hasRetrievalSupport(query, candidate) {
  const normalized = (text) => structuralTokens(String(text || '').normalize('NFD').replace(/\p{M}/gu, ''));
  const wanted = normalized(query);
  if (!wanted.size) return true;
  const present = normalized(candidate.content);
  let overlap = 0;
  for (const token of wanted) if (present.has(token)) overlap += 1;
  return overlap >= Math.min(2, wanted.size) || Number(candidate.semanticSimilarity || 0) >= 0.88;
}

function structuralTextSimilarity(left, right) {
  const leftTokens = structuralTokens(left);
  const rightTokens = structuralTokens(right);
  if (!leftTokens.size || !rightTokens.size) return 0;
  let intersection = 0;
  for (const token of leftTokens) {
    if (rightTokens.has(token)) intersection += 1;
  }
  return intersection / Math.sqrt(leftTokens.size * rightTokens.size);
}

function structuralTemporalProximity(leftCreatedAt, rightCreatedAt) {
  const left = Date.parse(String(leftCreatedAt || ''));
  const right = Date.parse(String(rightCreatedAt || ''));
  if (!Number.isFinite(left) || !Number.isFinite(right)) return 0;
  const hours = Math.abs(left - right) / (60 * 60 * 1000);
  return 1 / (1 + hours);
}

function structuralRankScore(query, anchor, candidate, relationScore) {
  const context = `${cleanText(query)} ${cleanText(anchor.content)}`;
  const textBonus = structuralTextSimilarity(context, candidate.content) * 0.09;
  const proximityBonus = structuralTemporalProximity(anchor.createdAt, candidate.createdAt) * 0.03;
  return Number((relationScore + textBonus + proximityBonus).toFixed(6));
}

function clippedExperimentalText(value, maximumChars) {
  const text = cleanText(value);
  if (text.length <= maximumChars) return text;
  const marker = '\n[truncated for pack]';
  const prefix = text.slice(0, Math.max(0, maximumChars - marker.length)).trimEnd();
  return prefix ? `${prefix}${marker}` : '';
}

function successorExclusions(exclusions) {
  const sessions = exclusions.sessionIds || [];
  const sources = exclusions.sources || [];
  return {
    sql: [
      ...sessions.map(() => 'AND e.session_id <> ?'),
      ...sources.map(() => 'AND e.source <> ?'),
    ].join('\n'),
    params: [...sessions, ...sources],
  };
}

function buildAntiHits(db, query, request, exclusions, experimental, options = {}) {
  if (!experimental.antiHits.enabled || experimental.antiHits.limit < 1) return [];
  const filters = {
    limit: experimental.antiHits.maxCandidateScan,
    unscopedOnly: Boolean(request.unscopedOnly),
    excludeSessionIds: exclusions.sessionIds,
    excludeSources: exclusions.sources,
    includeSuperseded: true,
  };
  const lexicalCandidates = lexicalSearchEvents(query, filters, { ...options, db });
  const semanticCandidates = Array.isArray(options.antiSemanticCandidates)
    ? options.antiSemanticCandidates
    : request.queryVector && request.embeddingModel && request.embeddingModelDigest
      ? semanticSearchEvents(request.queryVector, {
      ...filters,
      model: request.embeddingModel,
      modelDigest: request.embeddingModelDigest,
    }, { ...options, db })
      : [];
  const matched = mergeRankedEventCandidates(semanticCandidates, lexicalCandidates)
    .filter((event) => !request.requireQuerySupport || hasRetrievalSupport(query, event))
    .slice(0, experimental.antiHits.maxCandidateScan);
  if (!matched.length) return [];
  const matchedById = new Map(matched.map((event) => [event.id, event]));
  const ids = [...matchedById.keys()];
  const placeholders = ids.map(() => '?').join(', ');
  const excluded = successorExclusions(exclusions);
  const rows = db.prepare(`
    SELECT
      s.superseded_event_id AS anchor_event_id,
      s.recorded_at AS relation_recorded_at,
      e.*,
      ${supersededEventSql('e')} AS superseded,
      EXISTS(
        SELECT 1 FROM memory_projections p
        WHERE p.event_id = e.id AND p.target = 'mempalace' AND p.status = 'success'
      ) AS projected
    FROM memory_event_supersessions s
    ${request.unscopedOnly ? 'CROSS JOIN' : 'JOIN'} memory_events e ON e.id = s.superseding_event_id
    WHERE s.superseded_event_id IN (${placeholders})
      ${request.unscopedOnly ? `AND ${unscopedEventSql('e')}` : ''}
      ${excluded.sql}
      AND NOT EXISTS (
        SELECT 1 FROM memory_event_supersession_cancellations cancellation
        WHERE cancellation.superseded_event_id = s.superseded_event_id
          AND cancellation.superseding_event_id = s.superseding_event_id
      )
      AND NOT ${supersededEventSql('e')}
    ORDER BY s.recorded_at DESC, e.created_at DESC, e.id ASC
  `).all(...ids, ...excluded.params);
  const hits = [];
  const seen = new Set();
  for (const row of rows) {
    const anchor = matchedById.get(row.anchor_event_id);
    if (!anchor) continue;
    const evidence = rowToEvent(row);
    const pairKey = `${anchor.id}\u0000${evidence.id}`;
    if (seen.has(pairKey)) continue;
    seen.add(pairKey);
    const relation = evidence.eventType === 'fact_retraction' ? 'retracted_by' : 'superseded_by';
    hits.push({
      id: `anti_${sha256([anchor.id, evidence.id, relation].join('\u001f'))}`,
      anchorEventId: anchor.id,
      evidenceEventId: evidence.id,
      relation,
      reason: 'query_matched_superseded_event',
      path: [anchor.id, evidence.id],
      text: clippedExperimentalText(evidence.content, experimental.antiHits.maxItemChars),
      source: evidence.source,
      createdAt: evidence.createdAt,
      provenance: evidence.provenance,
      _rankScore: Number(anchor._rankScore || 0),
    });
  }
  return hits.sort((left, right) => (
    right._rankScore - left._rankScore
      || String(right.createdAt).localeCompare(String(left.createdAt))
      || left.id.localeCompare(right.id)
  )).slice(0, experimental.antiHits.limit).map(({ _rankScore, ...hit }) => hit);
}

function objectiveIdForEvent(event) {
  return validExternalId(event?.metadata?.objective_id || event?.metadata?.extensions?.objective_id);
}

function directStructuralSuccessors(db, anchorId, limit, exclusions = {}) {
  const excluded = successorExclusions(exclusions);
  return db.prepare(`
    SELECT e.*, ${supersededEventSql('e')} AS superseded,
      EXISTS(
        SELECT 1 FROM memory_projections p
        WHERE p.event_id = e.id AND p.target = 'mempalace' AND p.status = 'success'
      ) AS projected
    FROM memory_event_supersessions s
    ${exclusions.unscopedOnly ? 'CROSS JOIN' : 'JOIN'} memory_events e ON e.id = s.superseding_event_id
    WHERE s.superseded_event_id = ?
      ${exclusions.unscopedOnly ? `AND ${unscopedEventSql('e')}` : ''}
      ${excluded.sql}
      AND NOT EXISTS (
        SELECT 1 FROM memory_event_supersession_cancellations cancellation
        WHERE cancellation.superseded_event_id = s.superseded_event_id
          AND cancellation.superseding_event_id = s.superseding_event_id
      )
      AND NOT ${supersededEventSql('e')}
      AND NOT ${lifecycleControlEventSql('e')}
    ORDER BY e.created_at DESC, e.id ASC
    LIMIT ?
  `).all(anchorId, ...excluded.params, limit).map(rowToEvent);
}

function structuralCandidatesForAnchor(db, anchor, exclusions, limit) {
  const relationClauses = [];
  const relationParams = [];
  const objectiveId = objectiveIdForEvent(anchor);
  if (objectiveId) {
    relationClauses.push("json_extract(CASE WHEN json_valid(e.metadata_json) THEN e.metadata_json ELSE '{}' END, '$.objective_id') = ?");
    relationParams.push(objectiveId);
  }
  if (anchor.sourceRef) {
    relationClauses.push("e.source_ref <> '' AND e.source_ref = ?");
    relationParams.push(anchor.sourceRef);
  }
  if (anchor.source && anchor.sessionId) {
    relationClauses.push('e.source = ? AND e.session_id = ?');
    relationParams.push(anchor.source, anchor.sessionId);
  }
  const candidates = new Map();
  if (relationClauses.length) {
    const clauses = [`e.id <> ?`, `(${relationClauses.join(' OR ')})`];
    const params = [anchor.id, ...relationParams];
    appendCurrentEventClauses(clauses, { unscopedOnly: exclusions.unscopedOnly }, 'e');
    for (const sessionId of exclusions.sessionIds) {
      clauses.push('e.session_id <> ?');
      params.push(sessionId);
    }
    for (const source of exclusions.sources) {
      clauses.push('e.source <> ?');
      params.push(source);
    }
    const anchorCreatedAt = cleanText(anchor.createdAt);
    const orderBy = anchorCreatedAt
      ? `CASE WHEN julianday(e.created_at) IS NULL THEN 1 ELSE 0 END,
        ABS(julianday(e.created_at) - julianday(?)), e.created_at DESC, e.id ASC`
      : 'e.created_at DESC, e.id ASC';
    if (anchorCreatedAt) params.push(anchorCreatedAt);
    params.push(limit);
    const rows = db.prepare(`
      SELECT e.*, ${supersededEventSql('e')} AS superseded,
        EXISTS(
          SELECT 1 FROM memory_projections p
          WHERE p.event_id = e.id AND p.target = 'mempalace' AND p.status = 'success'
        ) AS projected
      FROM memory_events e
      WHERE ${clauses.join(' AND ')}
      ORDER BY ${orderBy}
      LIMIT ?
    `).all(...params).map(rowToEvent);
    for (const event of rows) candidates.set(event.id, event);
  }
  for (const event of directStructuralSuccessors(db, anchor.id, limit, exclusions)) candidates.set(event.id, event);
  return [...candidates.values()];
}

function structuralRelation(anchor, candidate, db) {
  const direct = db.prepare(`
    SELECT 1 AS found
    FROM memory_event_supersessions s
    WHERE s.superseded_event_id = ? AND s.superseding_event_id = ?
      AND NOT EXISTS (
        SELECT 1 FROM memory_event_supersession_cancellations cancellation
        WHERE cancellation.superseded_event_id = s.superseded_event_id
          AND cancellation.superseding_event_id = s.superseding_event_id
      )
  `).get(anchor.id, candidate.id);
  if (direct) return { relation: 'direct_supersession', score: 1 };
  const anchorObjective = objectiveIdForEvent(anchor);
  if (anchorObjective && objectiveIdForEvent(candidate) === anchorObjective) {
    return { relation: 'same_objective', score: 0.85 };
  }
  if (anchor.sourceRef && candidate.sourceRef === anchor.sourceRef) {
    return { relation: 'same_source_ref', score: 0.7 };
  }
  if (anchor.source && anchor.sessionId
      && candidate.source === anchor.source && candidate.sessionId === anchor.sessionId) {
    return { relation: 'same_session', score: 0.55 };
  }
  return null;
}

function buildStructuralHits(db, query, primaryResults, consumer, sessionId, exclusions, experimental) {
  if (!experimental.structuralRecall.enabled || experimental.structuralRecall.limit < 1) return [];
  const primaryIds = new Set(primaryResults.map((event) => event.id));
  const served = servedMemoryKeys(db, consumer, sessionId);
  const selected = new Map();
  for (const anchor of primaryResults) {
    const candidates = structuralCandidatesForAnchor(
      db,
      anchor,
      exclusions,
      experimental.structuralRecall.maxCandidatesPerAnchor,
    );
    for (const candidate of candidates) {
      if (primaryIds.has(candidate.id) || candidate.memoryKey === anchor.memoryKey
          || served.has(candidate.memoryKey)) continue;
      const relation = structuralRelation(anchor, candidate, db);
      if (!relation) continue;
      const hit = {
        id: candidate.id,
        anchorEventId: anchor.id,
        relation: relation.relation,
        path: [anchor.id, candidate.id],
        score: structuralRankScore(query, anchor, candidate, relation.score),
        text: clippedExperimentalText(candidate.content, experimental.structuralRecall.maxItemChars),
        source: candidate.source,
        createdAt: candidate.createdAt,
        provenance: candidate.provenance,
      };
      const current = selected.get(candidate.id);
      if (!current || hit.score > current.score
          || (hit.score === current.score && hit.anchorEventId.localeCompare(current.anchorEventId) < 0)) {
        selected.set(candidate.id, hit);
      }
    }
  }
  return [...selected.values()].sort((left, right) => (
    right.score - left.score
      || String(right.createdAt).localeCompare(String(left.createdAt))
      || left.id.localeCompare(right.id)
  )).slice(0, experimental.structuralRecall.limit);
}

function buildExperimentalMemoryEnvelope(db, query, request, results, exclusions, options = {}) {
  const experimental = request.experimentalMemory;
  if (!experimental?.enabled) return null;
  const antiHits = buildAntiHits(db, query, request, exclusions, experimental, options);
  const structuralHits = buildStructuralHits(
    db,
    query,
    results,
    cleanText(request.consumer || 'codex'),
    cleanText(request.sessionId),
    exclusions,
    experimental,
  );
  return {
    version: Number(experimental.version || 1),
    antiHits,
    structuralHits,
  };
}

function normalizedExperimentalMemoryRequest(value) {
  if (!value || value === true) return value;
  if (typeof value !== 'object') return value;
  if (value.antiHits && typeof value.antiHits === 'object') {
    return {
      enabled: value.enabled === true,
      antiHits: value.antiHits.enabled !== false,
      antiHitLimit: value.antiHits.limit,
      maxCandidateScan: value.antiHits.maxCandidateScan,
      antiHitMaxItemChars: value.antiHits.maxItemChars,
      structuralRecall: value.structuralRecall?.enabled !== false,
      structuralLimit: value.structuralRecall?.limit,
      maxCandidatesPerAnchor: value.structuralRecall?.maxCandidatesPerAnchor,
      structuralMaxItemChars: value.structuralRecall?.maxItemChars,
    };
  }
  return value;
}

function buildNextTurnPack(request = {}, options = {}) {
  const query = cleanText(request.query || request.task);
  const consumer = cleanText(request.consumer || 'codex');
  const sessionId = cleanText(request.sessionId);
  const source = cleanText(request.source);
  if (!query) throw new Error('next-turn pack query is required');
  if (!sessionId) throw new Error('next-turn pack sessionId is required');
  const experimentalMemory = request.experimentalMemory
    ? resolveExperimentalMemoryPolicy(normalizedExperimentalMemoryRequest(request.experimentalMemory))
    : null;
  const shouldRecordTrace = options.recordTrace !== false && request.recordTrace !== false;
  if (options.readOnly && (shouldRecordTrace || request.markServed !== false)) {
    throw memoryStoreError(
      'memory_readonly_violation',
      'read-only next-turn lookup requires recordTrace=false and markServed=false',
    );
  }
  return withStore(options, (db) => {
    const excludeSessionIds = [...new Set([sessionId, ...(request.excludeSessionIds || [])].map(cleanText).filter(Boolean))];
    const excludeSources = [...new Set([source, ...(request.excludeSources || [])].map(cleanText).filter(Boolean))];
    const limit = Math.max(1, Number(request.limit || 5));
    const includeSuperseded = wantsSuperseded(request);
    const candidateLimit = Math.max(limit * 4, 20);
    const semanticCandidatePool = cleanText(request.semanticCandidatePool) === 'lexical';
    const requestedSemanticCandidateLimit = Number(request.semanticCandidateLimit);
    const semanticCandidateLimit = semanticCandidatePool
      ? Math.max(
        candidateLimit,
        Math.min(100, Number.isInteger(requestedSemanticCandidateLimit) ? requestedSemanticCandidateLimit : candidateLimit),
      )
      : candidateLimit;
    const lexicalCandidates = lexicalSearchEvents(query, {
      limit: semanticCandidateLimit, excludeSessionIds, excludeSources, includeSuperseded,
      unscopedOnly: Boolean(request.unscopedOnly),
    }, { ...options, db });
    const semanticCandidateIds = semanticCandidatePool
      ? lexicalCandidates.map((candidate) => candidate.id)
      : [];
    const canShareSemanticScan = Boolean(
      request.queryVector
      && request.embeddingModel
      && request.embeddingModelDigest
      && experimentalMemory?.antiHits?.enabled,
    );
    let antiSemanticCandidates = null;
    const semanticCandidates = canShareSemanticScan
      ? withReadSnapshot(db, () => {
        const allRanked = semanticRankingRows(
          db,
          normalizeVector(request.queryVector),
          cleanText(request.embeddingModel),
          requiredSha256(request.embeddingModelDigest, 'embedding model digest'),
          {
            excludeSessionIds,
            excludeSources,
            includeSuperseded: true,
            markCurrent: true,
            unscopedOnly: Boolean(request.unscopedOnly),
            ...(semanticCandidatePool ? { candidateEventIds: semanticCandidateIds } : {}),
          },
        );
        antiSemanticCandidates = hydrateSemanticCandidates(
          db,
          allRanked.slice(0, experimentalMemory.antiHits.maxCandidateScan),
        );
        return hydrateSemanticCandidates(
          db,
          (includeSuperseded ? allRanked : allRanked.filter((row) => row._current)).slice(0, candidateLimit),
        );
      })
      : request.queryVector && request.embeddingModel && request.embeddingModelDigest
        ? semanticSearchEvents(request.queryVector, {
        model: request.embeddingModel,
        modelDigest: request.embeddingModelDigest,
        limit: candidateLimit,
        excludeSessionIds,
        excludeSources,
        includeSuperseded,
        unscopedOnly: Boolean(request.unscopedOnly),
        ...(semanticCandidatePool ? { candidateEventIds: semanticCandidateIds } : {}),
      }, { ...options, db })
        : [];
    const candidates = mergeRankedEventCandidates(semanticCandidates, lexicalCandidates);
    const served = servedMemoryKeys(db, consumer, sessionId);
    const maxChars = Math.max(1, Number(request.maxChars || 2000));
    const maxItemChars = Math.min(maxChars, Math.max(1, Number(request.maxItemChars || maxChars)));
    const results = [];
    let usedChars = 0;
    for (const candidate of candidates) {
      if (request.requireQuerySupport && !hasRetrievalSupport(query, candidate)) continue;
      if (served.has(candidate.memoryKey) || results.length >= limit || usedChars >= maxChars) continue;
      const remaining = maxChars - usedChars;
      const text = clippedExperimentalText(candidate.content, Math.min(remaining, maxItemChars));
      if (!text) continue;
      const { _rankScore, ...result } = candidate;
      results.push({ ...result, text });
      usedChars += text.length;
    }
    const exclusions = { sessionIds: excludeSessionIds, sources: excludeSources, unscopedOnly: Boolean(request.unscopedOnly) };
    const experimentalEnvelope = buildExperimentalMemoryEnvelope(
      db,
      query,
      { ...request, experimentalMemory },
      results,
      exclusions,
      { ...options, antiSemanticCandidates },
    );
    const trace = shouldRecordTrace ? recordRetrievalTrace({
      query, consumer, sessionId, source,
      resultIds: results.map((item) => item.id),
      filters: { excludeSessionIds, excludeSources, servedDedupe: true, includeSuperseded },
      metadata: {
        kind: 'next_turn_pack',
        maxChars,
        limit,
        channels: [...new Set(results.flatMap((item) => item.retrievalChannels || []))],
        embeddingModel: cleanText(request.embeddingModel),
        embeddingModelDigest: cleanText(request.embeddingModelDigest),
        ...(experimentalEnvelope ? {
          experimentalMemory: {
            version: experimentalEnvelope.version,
            antiHitIds: experimentalEnvelope.antiHits.map((item) => item.id),
            structuralHitIds: experimentalEnvelope.structuralHits.map((item) => item.id),
          },
        } : {}),
      },
    }, { ...options, db }) : { traceId: null };
    const servedResult = request.markServed === false
      ? { insertedCount: 0 }
      : markItemsServed(results, { consumer, sessionId, source, traceId: trace.traceId }, { ...options, db });
    return {
      contractVersion: CONTRACT_VERSION,
      query,
      consumer,
      sessionId,
      source,
      exclusions,
      maxChars,
      usedChars,
      traceId: trace.traceId,
      servedCount: servedResult.insertedCount,
      retrievalMode: semanticCandidates.length ? 'event_embedding+fts' : 'event_fts',
      results,
      ...(experimentalEnvelope ? { experimentalMemory: experimentalEnvelope } : {}),
    };
  });
}

function listLedgerEvents(filters = {}, options = {}) {
  assertAdapterOperation('memory-objectives', 'observe');
  return withStore(options, (db) => {
    const clauses = [];
    const params = [];
    const eventTypes = (filters.eventTypes || filters.event_types || [])
      .map((value) => cleanText(value).toLowerCase())
      .filter(Boolean);
    if (eventTypes.length) {
      clauses.push(`event_type IN (${eventTypes.map(() => '?').join(', ')})`);
      params.push(...eventTypes);
    }
    if (filters.source) {
      clauses.push('source = ?');
      params.push(cleanText(filters.source));
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const limit = filters.limit ? Math.max(1, Number(filters.limit)) : null;
    const newestFirst = Boolean(filters.newestFirst || filters.newest_first);
    const sql = [
      'SELECT * FROM memory_events',
      where,
      newestFirst ? 'ORDER BY created_at DESC, rowid DESC' : 'ORDER BY created_at ASC, rowid ASC',
      limit ? 'LIMIT ?' : '',
    ].filter(Boolean).join('\n');
    if (limit) params.push(limit);
    return db.prepare(sql).all(...params).map(rowToEvent);
  });
}

function objectiveEventId(kind, identity) {
  return `${kind}_${sha256(stableJson(identity))}`;
}

function captureObjective(payload = {}, options = {}) {
  assertAdapterOperation('memory-objectives', 'local_write');
  const objectiveId = validExternalId(payload.objectiveId || payload.objective_id);
  const source = cleanText(payload.source || 'codex');
  const sessionId = cleanText(payload.sessionId || payload.session_id);
  const title = cleanText(payload.title);
  if (!objectiveId || !sessionId || !title) {
    throw new Error('objectiveId, sessionId, and title are required');
  }
  const metadata = {
    objective_id: objectiveId,
    title,
    status: cleanText(payload.status || 'active'),
    detail: cleanText(payload.detail),
    constraints: sanitizeValue(payload.constraints || []),
    provenance: sanitizeValue(payload.provenance || {}),
  };
  const identity = { source, sessionId, metadata };
  return captureEvent({
    eventId: objectiveEventId('objective', identity),
    eventType: 'objective',
    producer: cleanText(payload.producer || source),
    source,
    sessionId,
    messageId: objectiveId,
    role: 'system',
    privacyScope: cleanText(payload.privacyScope || 'local'),
    content: title,
    createdAt: payload.createdAt,
    capturedAt: payload.capturedAt,
    metadata,
  }, options);
}

function captureExternalRunReference(payload = {}, options = {}) {
  assertAdapterOperation('memory-objectives', 'local_write');
  const objectiveId = validExternalId(payload.objectiveId || payload.objective_id);
  const executor = validExternalId(payload.executor);
  const runId = validExternalId(payload.runId || payload.run_id);
  const source = cleanText(payload.source || 'codex');
  const sessionId = cleanText(payload.sessionId || payload.session_id);
  if (!objectiveId || !executor || !runId || !sessionId) {
    throw new Error('objectiveId, executor, runId, and sessionId are required');
  }
  const metadata = {
    objective_id: objectiveId,
    executor,
    run_id: runId,
    authority: 'executor',
  };
  const identity = { source, sessionId, metadata };
  return captureEvent({
    eventId: objectiveEventId('run_ref', identity),
    eventType: 'external_run_reference',
    producer: cleanText(payload.producer || source),
    source,
    sourceRef: `${executor}:${runId}`,
    sessionId,
    messageId: `${objectiveId}:${executor}:${runId}`,
    role: 'system',
    privacyScope: cleanText(payload.privacyScope || 'local'),
    content: `External run ${executor}:${runId} for objective ${objectiveId}`,
    createdAt: payload.createdAt,
    capturedAt: payload.capturedAt,
    metadata,
  }, options);
}

function replayObjectiveRegistry(options = {}) {
  assertAdapterOperation('memory-objectives', 'observe');
  const objectives = new Map();
  const events = listLedgerEvents({
    eventTypes: ['objective', 'external_run_reference'],
  }, options);
  for (const event of events) {
    const objectiveId = validExternalId(event.metadata?.objective_id);
    if (!objectiveId) continue;
    const current = objectives.get(objectiveId) || {
      objectiveId,
      title: '',
      status: 'unknown',
      source: event.source,
      externalRuns: [],
    };
    if (event.eventType === 'objective') {
      current.title = cleanText(event.metadata.title || event.content);
      current.status = cleanText(event.metadata.status || 'active');
      current.source = event.source;
    } else {
      const reference = {
        executor: validExternalId(event.metadata.executor),
        runId: validExternalId(event.metadata.run_id),
        authority: 'executor',
      };
      if (reference.executor && reference.runId && !current.externalRuns.some((item) => (
        item.executor === reference.executor && item.runId === reference.runId
      ))) current.externalRuns.push(reference);
    }
    current.externalRuns.sort((left, right) => (
      left.executor.localeCompare(right.executor) || left.runId.localeCompare(right.runId)
    ));
    objectives.set(objectiveId, current);
  }
  return [...objectives.values()].sort((left, right) => left.objectiveId.localeCompare(right.objectiveId));
}

function getStoreStats(options = {}) {
  return withStore(options, (db) => {
    const supersededSql = supersededEventSql('e');
    return {
      contractVersion: CONTRACT_VERSION,
      schemaVersion: Number(db.prepare('PRAGMA user_version').get().user_version || 0),
      events: Number(db.prepare('SELECT COUNT(*) AS count FROM memory_events').get().count || 0),
      superseded: Number(db.prepare(`SELECT COUNT(*) AS count FROM memory_events e WHERE ${supersededSql}`).get().count || 0),
      pending: Number(db.prepare(`
      SELECT COUNT(*) AS count FROM memory_events e
      WHERE NOT EXISTS (
        SELECT 1 FROM memory_projections p
        WHERE p.event_id = e.id AND p.target = 'mempalace' AND p.status = 'success'
      )
      AND NOT ${supersededSql}
      AND NOT ${lifecycleControlEventSql('e')}
    `).get().count || 0),
      documents: Number(db.prepare('SELECT COUNT(*) AS count FROM mempalace_documents').get().count || 0),
      embeddings: Number(db.prepare('SELECT COUNT(*) AS count FROM memory_event_embeddings').get().count || 0),
      traces: Number(db.prepare('SELECT COUNT(*) AS count FROM memory_retrieval_traces').get().count || 0),
    };
  });
}

function hermesMemoryError(code, message, cause) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.code = code;
  return error;
}

function normalizeHermesTopicId(value) {
  const topic = cleanText(value);
  return ['', '0', '1'].includes(topic) ? '' : topic.slice(0, 200);
}

function normalizeHermesMemoryContext(context = {}) {
  if (!context || typeof context !== 'object' || Array.isArray(context)) {
    throw hermesMemoryError('route_denied', 'trusted Hermes memory context is required');
  }
  const normalized = {
    profile: cleanText(context.profile).toLowerCase(),
    platform: cleanText(context.platform).toLowerCase(),
    chatId: cleanText(context.chatId ?? context.chat_id),
    chatType: cleanText(context.chatType ?? context.chat_type).toLowerCase(),
    userId: cleanText(context.userId ?? context.user_id),
    topicId: normalizeHermesTopicId(context.topicId ?? context.topic_id ?? context.threadId ?? context.thread_id),
    sessionKey: cleanText(context.sessionKey ?? context.session_key),
    sessionId: cleanText(context.sessionId ?? context.session_id),
  };
  if (
    !/^[a-z0-9][a-z0-9_-]{0,63}$/u.test(normalized.profile)
    || normalized.platform !== 'telegram'
    || !['dm', 'private'].includes(normalized.chatType)
    || !/^[1-9][0-9]*$/u.test(normalized.chatId)
    || normalized.chatId !== normalized.userId
    || !normalized.sessionKey
    || normalized.sessionKey.length > 1000
    || !normalized.sessionId
    || normalized.sessionId.length > 500
  ) {
    throw hermesMemoryError('route_denied', 'trusted Hermes memory route is not authorized');
  }
  return normalized;
}

function ensureHermesMemoryStorePermissions(options = {}) {
  if (options.db) return;
  const dbPath = resolveMemoryDbPath(options);
  const parent = path.dirname(dbPath);
  if (options.readOnly) {
    try {
      if ((fs.statSync(parent).mode & 0o777) !== 0o700
          || (fs.statSync(dbPath).mode & 0o777) !== 0o600
          || [`${dbPath}-wal`, `${dbPath}-shm`].some((candidate) => (
            fs.existsSync(candidate) && (fs.statSync(candidate).mode & 0o777) !== 0o600
          ))) throw new Error('unsafe permissions');
    } catch {
      throw hermesMemoryError('memory_store_invalid', 'read-only memory store permissions are unavailable or unsafe');
    }
    return;
  }
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  fs.chmodSync(parent, 0o700);
  for (const candidate of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) {
    if (fs.existsSync(candidate)) fs.chmodSync(candidate, 0o600);
  }
}

function validateHermesMemorySchema(db, options = {}) {
  const requiredTables = [
    'memory_contract_meta',
    'memory_events',
    'memory_events_fts',
    'memory_shared_grants',
    'memory_write_proposals',
    'memory_write_audit',
  ];
  const requiredTriggers = [
    'memory_events_no_update',
    'memory_events_no_delete',
    'memory_shared_grants_no_update',
    'memory_shared_grants_no_delete',
    'memory_write_audit_validate_insert',
    'memory_write_proposals_restrict_update',
    'memory_write_proposals_require_event_audit',
    'memory_write_proposals_no_delete',
    'memory_write_audit_no_update',
    'memory_write_audit_no_delete',
  ];
  const requiredIndexes = [
    'memory_events_hermes_scope_idx',
    'memory_shared_grants_lookup_idx',
    'memory_write_proposals_expiry_idx',
    'memory_write_audit_nonce_idx',
    'memory_write_audit_event_idx',
  ];
  const requiredObjects = new Map([
    ...requiredTables.map((name) => [name, 'table']),
    ...requiredTriggers.map((name) => [name, 'trigger']),
    ...requiredIndexes.map((name) => [name, 'index']),
  ]);
  const names = [...requiredObjects.keys()];
  const foundObjects = new Map(db.prepare(`
    SELECT name, type FROM sqlite_master
    WHERE name IN (${names.map(() => '?').join(', ')})
  `).all(...names).map((row) => [row.name, row.type]));
  const missingObjects = names.filter((name) => foundObjects.get(name) !== requiredObjects.get(name));
  const requiredColumns = {
    memory_events: [
      'id', 'event_type', 'producer', 'source', 'session_id', 'content',
      'source_profile', 'source_platform', 'source_chat_id', 'source_user_id',
      'source_topic_id', 'source_session_id', 'scope_kind', 'authorization_version',
    ],
    memory_shared_grants: [
      'grant_id', 'event_id', 'grantee_profile', 'grantee_platform', 'grantee_chat_id',
      'grantee_user_id', 'grantee_topic_id', 'grant_kind', 'created_at', 'expires_at',
      'authorization_version',
    ],
    memory_write_proposals: [
      'nonce', 'payload_hash', 'payload_json', 'source_profile', 'source_platform',
      'source_chat_id', 'source_user_id', 'source_topic_id', 'source_session_key_hash',
      'source_session_id', 'created_at', 'expires_at', 'consumed_at', 'event_id',
      'authorization_version',
    ],
    memory_write_audit: [
      'audit_id', 'nonce', 'payload_hash', 'event_id', 'source_profile',
      'source_platform', 'source_chat_id', 'source_user_id', 'source_topic_id',
      'source_session_id', 'action', 'created_at', 'authorization_version',
    ],
  };
  const missingColumns = [];
  for (const [table, columns] of Object.entries(requiredColumns)) {
    const foundColumns = new Set(db.prepare(`PRAGMA table_info(${table})`).all().map((row) => row.name));
    for (const column of columns) {
      if (!foundColumns.has(column)) missingColumns.push(`${table}.${column}`);
    }
  }
  const integrityResult = options.quickCheck === false
    ? 'ok'
    : (() => {
      const integrity = db.prepare('PRAGMA quick_check').get();
      return integrity && Object.values(integrity)[0];
    })();
  if (
    Number(db.prepare('PRAGMA user_version').get().user_version || 0) !== SCHEMA_VERSION
    || missingObjects.length
    || missingColumns.length
    || integrityResult !== 'ok'
  ) {
    throw hermesMemoryError('memory_store_invalid', 'Hermes memory consent schema is incomplete');
  }
}

function initializeHermesMemoryStore(options = {}) {
  ensureHermesMemoryStorePermissions(options);
  const result = withStore(options, (db) => {
    validateHermesMemorySchema(db);
    return {
      schemaVersion: Number(db.prepare('PRAGMA user_version').get().user_version || 0),
      authorizationVersion: HERMES_MEMORY_AUTHORIZATION_VERSION,
    };
  });
  ensureHermesMemoryStorePermissions(options);
  return result;
}

function normalizeHermesWritePayload(payload = {}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw hermesMemoryError('proposal_invalid', 'memory proposal must be an object');
  }
  const allowed = new Set(['eventType', 'event_type', 'content', 'tags']);
  const unknown = Object.keys(payload).filter((key) => !allowed.has(key));
  if (unknown.length) throw hermesMemoryError('proposal_invalid', 'memory proposal contains unsupported fields');
  const eventType = cleanText(payload.eventType ?? payload.event_type ?? 'user_memory').toLowerCase();
  if (!/^[a-z][a-z0-9._-]{0,63}$/u.test(eventType)) {
    throw hermesMemoryError('proposal_invalid', 'memory proposal event_type is invalid');
  }
  const content = sanitizeForMemory(String(payload.content ?? '').replace(/\u0000/g, '\uFFFD')).text.trim();
  if (!content || content.length > HERMES_MEMORY_MAX_CONTENT_CHARS) {
    throw hermesMemoryError('proposal_invalid', `memory proposal content must be 1-${HERMES_MEMORY_MAX_CONTENT_CHARS} characters`);
  }
  const rawTags = payload.tags === undefined ? [] : payload.tags;
  if (!Array.isArray(rawTags) || rawTags.length > 8) {
    throw hermesMemoryError('proposal_invalid', 'memory proposal tags must contain at most 8 items');
  }
  const tags = [...new Set(rawTags.map((tag) => cleanText(tag).toLowerCase()).filter(Boolean))];
  if (tags.some((tag) => tag.length > 64 || !/^[\p{L}\p{N}][\p{L}\p{N}._-]*$/u.test(tag))) {
    throw hermesMemoryError('proposal_invalid', 'memory proposal tag is invalid');
  }
  return { eventType, content, tags };
}

function exactHashMatch(left, right) {
  if (!/^[a-f0-9]{64}$/u.test(String(left || '')) || !/^[a-f0-9]{64}$/u.test(String(right || ''))) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function hermesNow(options = {}) {
  const value = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  if (Number.isNaN(value.valueOf())) throw hermesMemoryError('clock_invalid', 'memory clock is invalid');
  return value;
}

function searchAuthorizedHermesMemory(context, query, options = {}) {
  const trusted = normalizeHermesMemoryContext(context);
  const normalizedQuery = cleanText(query);
  if (!normalizedQuery || normalizedQuery.length > HERMES_MEMORY_MAX_QUERY_CHARS) {
    throw hermesMemoryError('query_invalid', `memory query must be 1-${HERMES_MEMORY_MAX_QUERY_CHARS} characters`);
  }
  const match = ftsQuery(normalizedQuery);
  const observedAt = hermesNow(options).toISOString();
  if (!match) {
    return { version: 1, ok: true, items: [], observed_at: observedAt, truncated: false, error: null };
  }
  const limit = Math.min(8, Math.max(1, Number(options.limit || 5)));
  const maxCharsPerItem = Math.min(1200, Math.max(100, Number(options.maxCharsPerItem || 900)));
  const maxTotalChars = Math.min(6000, Math.max(maxCharsPerItem, Number(options.maxTotalChars || 4000)));
  ensureHermesMemoryStorePermissions({ ...options, readOnly: true });
  const rows = withStore({ ...options, readOnly: options.db ? undefined : true }, (db) => {
    validateHermesMemorySchema(db, { quickCheck: false });
    const supersededSql = supersededEventSql('e');
    const lifecycleSql = lifecycleControlEventSql('e');
    return db.prepare(`
      SELECT e.*, bm25(memory_events_fts) AS rank
      FROM memory_events_fts
      JOIN memory_events e ON e.rowid = memory_events_fts.rowid
      WHERE memory_events_fts MATCH ?
        AND e.authorization_version = ?
        AND e.scope_kind = 'profile_topic'
        AND e.source_profile <> ''
        AND e.source_platform <> ''
        AND e.source_chat_id <> ''
        AND e.source_user_id <> ''
        AND e.source_session_id <> ''
        AND NOT ${supersededSql}
        AND NOT ${lifecycleSql}
        AND (
          (
            e.source_profile = ? AND e.source_platform = ? AND e.source_chat_id = ?
            AND e.source_user_id = ? AND e.source_topic_id = ?
          )
          OR EXISTS (
            SELECT 1 FROM memory_shared_grants grant_row
            WHERE grant_row.event_id = e.id
              AND grant_row.authorization_version = ?
              AND grant_row.grantee_profile = ?
              AND grant_row.grantee_platform = ?
              AND grant_row.grantee_chat_id = ?
              AND grant_row.grantee_user_id = ?
              AND grant_row.grantee_topic_id = ?
              AND grant_row.grant_kind = 'profile_topic'
              AND (grant_row.expires_at = '' OR grant_row.expires_at > ?)
          )
        )
      ORDER BY rank, e.created_at DESC, e.id
      LIMIT ?
    `).all(
      match,
      HERMES_MEMORY_AUTHORIZATION_VERSION,
      trusted.profile,
      trusted.platform,
      trusted.chatId,
      trusted.userId,
      trusted.topicId,
      HERMES_MEMORY_AUTHORIZATION_VERSION,
      trusted.profile,
      trusted.platform,
      trusted.chatId,
      trusted.userId,
      trusted.topicId,
      observedAt,
      limit + 1,
    );
  });
  const truncatedByCount = rows.length > limit;
  let total = 0;
  let truncatedBySize = false;
  const items = [];
  for (const row of rows.slice(0, limit)) {
    const owner = row.source_profile === trusted.profile
      && row.source_platform === trusted.platform
      && row.source_chat_id === trusted.chatId
      && row.source_user_id === trusted.userId
      && row.source_topic_id === trusted.topicId;
    let text = String(row.content || '');
    if (text.length > maxCharsPerItem) {
      text = `${text.slice(0, maxCharsPerItem - 1)}…`;
      truncatedBySize = true;
    }
    if (total + text.length > maxTotalChars) {
      const remaining = maxTotalChars - total;
      if (remaining < 100) {
        truncatedBySize = true;
        break;
      }
      text = `${text.slice(0, remaining - 1)}…`;
      truncatedBySize = true;
    }
    total += text.length;
    items.push({
      text,
      event_id: row.id,
      event_type: row.event_type,
      created_at: row.created_at,
      source_profile: row.source_profile,
      source_topic_id: row.source_topic_id,
      grant_kind: owner ? 'owner' : 'explicit',
    });
  }
  return {
    version: 1,
    ok: true,
    items,
    observed_at: observedAt,
    truncated: truncatedByCount || truncatedBySize,
    error: null,
  };
}

function proposeHermesMemoryWrite(context, payload, options = {}) {
  const trusted = normalizeHermesMemoryContext(context);
  const normalized = normalizeHermesWritePayload(payload);
  const now = hermesNow(options);
  const ttlSeconds = HERMES_MEMORY_PROPOSAL_TTL_SECONDS;
  const expiresAt = new Date(now.valueOf() + ttlSeconds * 1000).toISOString();
  const payloadJson = stableJson(normalized);
  const payloadHash = sha256(payloadJson);
  const nonceFactory = options.nonceFactory || (() => crypto.randomBytes(24).toString('base64url'));
  ensureHermesMemoryStorePermissions(options);
  const nonce = withStore(options, (db) => withImmediateTransaction(db, () => {
    validateHermesMemorySchema(db, { quickCheck: false });
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const candidate = String(nonceFactory()).trim();
      if (!/^[A-Za-z0-9_-]{24,128}$/u.test(candidate)) {
        throw hermesMemoryError('proposal_invalid', 'memory proposal nonce generator returned an invalid value');
      }
      const result = db.prepare(`
        INSERT OR IGNORE INTO memory_write_proposals(
          nonce, payload_hash, payload_json, source_profile, source_platform,
          source_chat_id, source_user_id, source_topic_id, source_session_key_hash,
          source_session_id, created_at, expires_at, authorization_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        candidate,
        payloadHash,
        payloadJson,
        trusted.profile,
        trusted.platform,
        trusted.chatId,
        trusted.userId,
        trusted.topicId,
        sha256(trusted.sessionKey),
        trusted.sessionId,
        now.toISOString(),
        expiresAt,
        HERMES_MEMORY_AUTHORIZATION_VERSION,
      );
      if (Number(result.changes || 0) === 1) return candidate;
    }
    throw hermesMemoryError('proposal_conflict', 'memory proposal nonce collision');
  }));
  ensureHermesMemoryStorePermissions(options);
  return {
    version: 1,
    nonce,
    payload_hash: payloadHash,
    expires_at: expiresAt,
    summary: `${normalized.eventType}: ${normalized.content.slice(0, 180)}`,
    confirmation_command: `/memory-confirm ${nonce} ${payloadHash}`,
  };
}

function confirmHermesMemoryWrite(context, nonce, payloadHash, options = {}) {
  const trusted = normalizeHermesMemoryContext(context);
  const normalizedNonce = String(nonce || '').trim();
  const normalizedHash = String(payloadHash || '').trim().toLowerCase();
  if (!/^[A-Za-z0-9_-]{24,128}$/u.test(normalizedNonce) || !/^[a-f0-9]{64}$/u.test(normalizedHash)) {
    throw hermesMemoryError('confirmation_invalid', 'memory confirmation is invalid');
  }
  const now = hermesNow(options);
  ensureHermesMemoryStorePermissions(options);
  const result = withStore(options, (db) => withImmediateTransaction(db, () => {
    validateHermesMemorySchema(db, { quickCheck: false });
    const proposal = db.prepare('SELECT * FROM memory_write_proposals WHERE nonce = ?').get(normalizedNonce);
    if (!proposal || proposal.authorization_version !== HERMES_MEMORY_AUTHORIZATION_VERSION) {
      throw hermesMemoryError('confirmation_invalid', 'memory confirmation is invalid');
    }
    const contextMatches = proposal.source_profile === trusted.profile
      && proposal.source_platform === trusted.platform
      && proposal.source_chat_id === trusted.chatId
      && proposal.source_user_id === trusted.userId
      && proposal.source_topic_id === trusted.topicId
      && exactHashMatch(proposal.source_session_key_hash, sha256(trusted.sessionKey))
      && proposal.source_session_id === trusted.sessionId;
    if (!contextMatches || !exactHashMatch(proposal.payload_hash, normalizedHash)) {
      throw hermesMemoryError('confirmation_invalid', 'memory confirmation is invalid');
    }
    if (proposal.consumed_at || proposal.event_id || proposal.expires_at <= now.toISOString()) {
      throw hermesMemoryError('confirmation_invalid', 'memory confirmation is invalid');
    }
    const payload = normalizeHermesWritePayload(parseJson(proposal.payload_json, null));
    if (!exactHashMatch(sha256(stableJson(payload)), normalizedHash)) {
      throw hermesMemoryError('confirmation_invalid', 'memory confirmation payload changed');
    }
    const eventId = `hermesmem_${sha256(normalizedNonce).slice(0, 48)}`;
    const inserted = insertEvent(db, {
      eventId,
      eventType: payload.eventType,
      producer: 'hermes-mempalace',
      source: 'hermes',
      sourceRef: `memory-confirm:${sha256(normalizedNonce).slice(0, 16)}`,
      sessionId: trusted.sessionId,
      messageId: `memory-confirm:${sha256(normalizedNonce).slice(0, 24)}`,
      role: 'user',
      privacyScope: 'local',
      status: 'confirmed',
      content: payload.content,
      metadata: { tags: payload.tags, consent: 'exact_direct_command' },
      provenance: { transport: 'telegram', confirmation: 'direct' },
      sourceProfile: trusted.profile,
      sourcePlatform: trusted.platform,
      sourceChatId: trusted.chatId,
      sourceUserId: trusted.userId,
      sourceTopicId: trusted.topicId,
      sourceSessionId: trusted.sessionId,
      scopeKind: 'profile_topic',
      authorizationVersion: HERMES_MEMORY_AUTHORIZATION_VERSION,
      createdAt: now.toISOString(),
      capturedAt: now.toISOString(),
    });
    if (!inserted.inserted) throw hermesMemoryError('confirmation_invalid', 'memory confirmation was already applied');
    const auditId = `memaudit_${sha256(`${normalizedNonce}\u0000${eventId}`).slice(0, 48)}`;
    db.prepare(`
      INSERT INTO memory_write_audit(
        audit_id, nonce, payload_hash, event_id, source_profile, source_platform,
        source_chat_id, source_user_id, source_topic_id, source_session_id,
        action, created_at, authorization_version
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      auditId,
      normalizedNonce,
      normalizedHash,
      eventId,
      trusted.profile,
      trusted.platform,
      trusted.chatId,
      trusted.userId,
      trusted.topicId,
      trusted.sessionId,
      'confirmed',
      now.toISOString(),
      HERMES_MEMORY_AUTHORIZATION_VERSION,
    );
    const consumed = db.prepare(`
      UPDATE memory_write_proposals
      SET consumed_at = ?, event_id = ?
      WHERE nonce = ? AND consumed_at = '' AND event_id = ''
    `).run(now.toISOString(), eventId, normalizedNonce);
    if (Number(consumed.changes || 0) !== 1) {
      throw hermesMemoryError('confirmation_invalid', 'memory confirmation was already applied');
    }
    return { version: 1, ok: true, event_id: eventId, confirmed_at: now.toISOString(), error: null };
  }));
  ensureHermesMemoryStorePermissions(options);
  return result;
}

function createHermesMemoryGrant(eventId, granteeContext, options = {}) {
  const trusted = normalizeHermesMemoryContext(granteeContext);
  const normalizedEventId = validExternalId(eventId);
  if (!normalizedEventId) throw hermesMemoryError('grant_invalid', 'memory grant event id is invalid');
  const now = hermesNow(options);
  const expiresAt = options.expiresAt ? normalizeTimestamp(options.expiresAt) : '';
  if (expiresAt && expiresAt <= now.toISOString()) {
    throw hermesMemoryError('grant_invalid', 'memory grant expiry must be in the future');
  }
  const grantKind = cleanText(options.grantKind || 'profile_topic');
  if (grantKind !== 'profile_topic') throw hermesMemoryError('grant_invalid', 'memory grant kind is unsupported');
  const grantId = validExternalId(options.grantId)
    || `memgrant_${sha256(`${normalizedEventId}\u0000${trusted.profile}\u0000${trusted.chatId}\u0000${trusted.topicId}\u0000${now.toISOString()}`).slice(0, 48)}`;
  ensureHermesMemoryStorePermissions(options);
  return withStore(options, (db) => withImmediateTransaction(db, () => {
    validateHermesMemorySchema(db, { quickCheck: false });
    if (!db.prepare(`
      SELECT 1 AS found FROM memory_events
      WHERE id = ?
        AND authorization_version = ?
        AND scope_kind = 'profile_topic'
        AND source_profile <> ''
        AND source_platform <> ''
        AND source_chat_id <> ''
        AND source_user_id <> ''
        AND source_session_id <> ''
    `).get(normalizedEventId, HERMES_MEMORY_AUTHORIZATION_VERSION)) {
      throw hermesMemoryError('grant_invalid', 'memory grant event does not exist');
    }
    db.prepare(`
      INSERT INTO memory_shared_grants(
        grant_id, event_id, grantee_profile, grantee_platform, grantee_chat_id,
        grantee_user_id, grantee_topic_id, grant_kind, created_at, expires_at,
        authorization_version
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      grantId,
      normalizedEventId,
      trusted.profile,
      trusted.platform,
      trusted.chatId,
      trusted.userId,
      trusted.topicId,
      grantKind,
      now.toISOString(),
      expiresAt,
      HERMES_MEMORY_AUTHORIZATION_VERSION,
    );
    return { grantId, eventId: normalizedEventId, expiresAt };
  }));
}

module.exports = {
  CONTRACT_VERSION,
  SCHEMA_VERSION,
  DEFAULT_BUSY_TIMEOUT_MS,
  resolveMemoryDbPath,
  openMemoryStore,
  captureEvent,
  captureMessage,
  captureTurn,
  listPendingEvents,
  markEventsProjected,
  upsertEventEmbedding,
  backfillEventEmbeddingVectorBlobs,
  listEmbeddableEvents,
  semanticSearchEvents,
  lexicalSearchEvents,
  upsertMempalaceDocuments,
  lexicalSearchDocuments,
  recordRetrievalTrace,
  markItemsServed,
  buildNextTurnPack,
  listLedgerEvents,
  captureObjective,
  captureExternalRunReference,
  replayObjectiveRegistry,
  getStoreStats,
  HERMES_MEMORY_AUTHORIZATION_VERSION,
  HERMES_MEMORY_PROPOSAL_TTL_SECONDS,
  initializeHermesMemoryStore,
  validateHermesMemorySchema,
  normalizeHermesMemoryContext,
  normalizeHermesTopicId,
  searchAuthorizedHermesMemory,
  proposeHermesMemoryWrite,
  confirmHermesMemoryWrite,
  createHermesMemoryGrant,
};
