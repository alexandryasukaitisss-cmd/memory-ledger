import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

export const FACT_LINEAGE_SCHEMA_VERSION = 2;
export const ASK_TELEMETRY_VERSION = 2;
export const FACT_LINEAGE_EVENTS_TABLE = 'sidecar_fact_lineage_events';
export const FACT_MEMORY_OUTBOX_TABLE = 'sidecar_fact_memory_outbox';

const CURRENT_STATUS = 'current';
const SUPERSEDED_STATUS = 'superseded';
const RETRACTED_STATUS = 'retracted';
const CONFLICT_STATUS = 'conflict';
const MATERIALIZED_FACTS_TABLE = 'sidecar_entity_facts';
const FACT_EVENT_ID_VERSION = 1;
const FACT_MEMORY_TRANSITION_ID_VERSION = 2;
const DEFAULT_OUTBOX_BATCH_LIMIT = 50;
const MAX_OUTBOX_BATCH_LIMIT = 500;
const LINEAGE_KEY_RE = /^[a-z0-9][a-z0-9._:-]{0,95}$/;
const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

let memoryContractOverride;
let memoryContractCache;
let telemetrySaltCache;
let transactionSavepointCounter = 0;

function tableExists(db, tableName) {
  return Boolean(
    db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?").get(tableName),
  );
}

function tableColumns(db, tableName) {
  return new Set(db.prepare(`PRAGMA table_info(${tableName})`).all().map((row) => row.name));
}

function boundedBatchLimit(value, fallback = DEFAULT_OUTBOX_BATCH_LIMIT) {
  const parsed = Math.floor(Number(value));
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(parsed, MAX_OUTBOX_BATCH_LIMIT);
}

function ensureFactMemoryOutboxSchema(db) {
  const created = !tableExists(db, FACT_MEMORY_OUTBOX_TABLE);
  db.exec(`
    CREATE TABLE IF NOT EXISTS ${FACT_MEMORY_OUTBOX_TABLE}(
      id                INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id          TEXT NOT NULL UNIQUE,
      fact_event_id     TEXT NOT NULL,
      lifecycle_kind    TEXT NOT NULL,
      payload_json      TEXT NOT NULL,
      created_at        TEXT NOT NULL,
      attempts          INTEGER NOT NULL DEFAULT 0,
      last_attempt_at   TEXT,
      last_error        TEXT,
      delivered_at      TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_fact_memory_outbox_pending
      ON ${FACT_MEMORY_OUTBOX_TABLE}(delivered_at, id);
    CREATE INDEX IF NOT EXISTS idx_fact_memory_outbox_source
      ON ${FACT_MEMORY_OUTBOX_TABLE}(fact_event_id, lifecycle_kind);
  `);
  return created;
}

function withImmediateTransaction(db, operation) {
  const ownsTransaction = !db.isTransaction;
  const savepoint = ownsTransaction
    ? null
    : `fact_lineage_${transactionSavepointCounter += 1}`;
  if (ownsTransaction) db.exec('BEGIN IMMEDIATE;');
  else db.exec(`SAVEPOINT ${savepoint};`);
  try {
    const result = operation();
    if (ownsTransaction) db.exec('COMMIT;');
    else db.exec(`RELEASE SAVEPOINT ${savepoint};`);
    return result;
  } catch (error) {
    if (ownsTransaction) {
      try { db.exec('ROLLBACK;'); } catch {}
    } else {
      try {
        db.exec(`ROLLBACK TO SAVEPOINT ${savepoint};`);
        db.exec(`RELEASE SAVEPOINT ${savepoint};`);
      } catch {}
    }
    throw error;
  }
}

function sha256(value, length = 24) {
  return createHash('sha256').update(String(value ?? ''), 'utf8').digest('hex').slice(0, length);
}

function parseInstant(value) {
  const timestamp = Date.parse(String(value || ''));
  return Number.isFinite(timestamp) ? timestamp : null;
}

function canonicalInstant(value, fallback = '') {
  const timestamp = parseInstant(value);
  if (timestamp !== null) return new Date(timestamp).toISOString();
  const fallbackTimestamp = parseInstant(fallback);
  return fallbackTimestamp !== null ? new Date(fallbackTimestamp).toISOString() : '';
}

function effectiveFrom(fact) {
  return canonicalInstant(fact?.valid_from || fact?.said_at || fact?.created_at || '');
}

function currentFact(fact) {
  const status = String(fact?.status || '').toLowerCase();
  return status === CURRENT_STATUS && !String(fact?.valid_to || '').trim();
}

function factEventId(fact, legacyId = '') {
  const material = [
    FACT_EVENT_ID_VERSION,
    legacyId,
    fact.entity_id,
    fact.kind,
    fact.value,
    fact.source_ref,
    fact.said_at,
    fact.valid_from,
  ].map((value) => String(value ?? '')).join('\u0000');
  return `fact_${sha256(material, 32)}`;
}

export function normalizeLineageKey(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.normalize('NFKC').trim().toLowerCase();
  return LINEAGE_KEY_RE.test(normalized) ? normalized : null;
}

export function ensureFactLineageSchema(db) {
  if (!tableExists(db, MATERIALIZED_FACTS_TABLE)) {
    return {
      migrated: false,
      backfilled: 0,
      eventsBackfilled: 0,
      eventTableCreated: false,
      outboxTableCreated: false,
      lineagesReconciled: 0,
      unkeyedValuesReconciled: 0,
      materializedValuesReconciled: 0,
      columnsAdded: [],
    };
  }

  const ownsTransaction = !db.isTransaction;
  if (ownsTransaction) db.exec('BEGIN IMMEDIATE;');
  try {
    const eventTableCreated = !tableExists(db, FACT_LINEAGE_EVENTS_TABLE);
    const outboxTableCreated = ensureFactMemoryOutboxSchema(db);
    const columns = new Set(
      db.prepare(`PRAGMA table_info(${MATERIALIZED_FACTS_TABLE})`).all().map((row) => row.name),
    );
    const additions = [
      ['event_id', 'TEXT'],
      ['lineage_key', 'TEXT'],
      ['valid_from', 'TEXT'],
      ['valid_to', 'TEXT'],
      ['superseded_by', 'TEXT'],
      ['status', `TEXT NOT NULL DEFAULT '${CURRENT_STATUS}'`],
    ];
    const columnsAdded = [];
    for (const [name, declaration] of additions) {
      if (columns.has(name)) continue;
      db.exec(`ALTER TABLE ${MATERIALIZED_FACTS_TABLE} ADD COLUMN ${name} ${declaration};`);
      columns.add(name);
      columnsAdded.push(name);
    }

    const rows = db.prepare(`
      SELECT id, entity_id, kind, value, source_ref, said_at, created_at,
             event_id, valid_from, status
      FROM ${MATERIALIZED_FACTS_TABLE}
      WHERE COALESCE(event_id, '') = ''
         OR COALESCE(valid_from, '') = ''
         OR COALESCE(status, '') = ''
    `).all();
    const update = db.prepare(`
      UPDATE ${MATERIALIZED_FACTS_TABLE}
      SET event_id = ?, valid_from = ?, status = ?
      WHERE id = ?
    `);
    for (const row of rows) {
      const validFrom = effectiveFrom(row);
      update.run(
        row.event_id || factEventId({ ...row, valid_from: validFrom }, `legacy:${row.id}`),
        row.valid_from || validFrom || null,
        row.status || CURRENT_STATUS,
        row.id,
      );
    }

    db.exec(`
      CREATE TABLE IF NOT EXISTS ${FACT_LINEAGE_EVENTS_TABLE}(
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id       TEXT NOT NULL UNIQUE,
        entity_id      TEXT NOT NULL,
        kind           TEXT NOT NULL,
        value          TEXT NOT NULL,
        evidence       TEXT NOT NULL DEFAULT '',
        source_ref     TEXT NOT NULL DEFAULT '',
        said_at        TEXT NOT NULL DEFAULT '',
        said_by        TEXT NOT NULL DEFAULT 'owner',
        confidence     REAL NOT NULL DEFAULT 1.0,
        created_at     TEXT NOT NULL,
        lineage_key    TEXT,
        valid_from     TEXT,
        valid_to       TEXT,
        superseded_by  TEXT,
        status         TEXT NOT NULL DEFAULT '${CURRENT_STATUS}'
      );

      CREATE UNIQUE INDEX IF NOT EXISTS idx_sef_event_id
        ON ${MATERIALIZED_FACTS_TABLE}(event_id)
        WHERE event_id IS NOT NULL AND event_id != '';
      CREATE INDEX IF NOT EXISTS idx_sef_lineage
        ON ${MATERIALIZED_FACTS_TABLE}(entity_id, lineage_key, status, valid_from);
      CREATE INDEX IF NOT EXISTS idx_sfle_entity_lineage
        ON ${FACT_LINEAGE_EVENTS_TABLE}(entity_id, lineage_key, status, valid_from);
      CREATE INDEX IF NOT EXISTS idx_sfle_source_ref
        ON ${FACT_LINEAGE_EVENTS_TABLE}(source_ref);
    `);
    const eventBackfill = db.prepare(`
      INSERT INTO ${FACT_LINEAGE_EVENTS_TABLE}(
        event_id, entity_id, kind, value, evidence, source_ref, said_at, said_by,
        confidence, created_at, lineage_key, valid_from, valid_to, superseded_by, status
      )
      SELECT event_id, entity_id, kind, value, evidence, source_ref, said_at, said_by,
             confidence, created_at, lineage_key, valid_from, valid_to, superseded_by, status
      FROM ${MATERIALIZED_FACTS_TABLE}
      WHERE COALESCE(event_id, '') != ''
      ON CONFLICT(event_id) DO NOTHING
    `).run();
    const backfillCollision = db.prepare(`
      SELECT materialized.event_id
      FROM ${MATERIALIZED_FACTS_TABLE} AS materialized
      JOIN ${FACT_LINEAGE_EVENTS_TABLE} AS event
        ON event.event_id = materialized.event_id
      WHERE event.entity_id IS NOT materialized.entity_id
         OR event.kind IS NOT materialized.kind
         OR event.value IS NOT materialized.value
         OR event.evidence IS NOT materialized.evidence
         OR event.source_ref IS NOT materialized.source_ref
         OR event.said_at IS NOT materialized.said_at
         OR event.said_by IS NOT materialized.said_by
         OR event.confidence IS NOT materialized.confidence
         OR event.lineage_key IS NOT materialized.lineage_key
         OR event.valid_from IS NOT materialized.valid_from
      LIMIT 1
    `).get();
    if (backfillCollision) {
      throw new Error(`fact event id collision for ${backfillCollision.event_id}`);
    }
    const lineages = db.prepare(`
      SELECT DISTINCT entity_id, lineage_key
      FROM ${FACT_LINEAGE_EVENTS_TABLE}
      WHERE COALESCE(lineage_key, '') != ''
    `).all();
    for (const lineage of lineages) {
      reconcileLineageInTable(
        db,
        FACT_LINEAGE_EVENTS_TABLE,
        lineage.entity_id,
        lineage.lineage_key,
      );
      syncMaterializedLineage(db, lineage.entity_id, lineage.lineage_key);
    }
    const materializedProjectionRepairs = db.prepare(`
      WITH ranked AS (
        SELECT event.*,
               ROW_NUMBER() OVER (
                 PARTITION BY entity_id, kind, value
                 ORDER BY COALESCE(NULLIF(valid_from, ''), NULLIF(said_at, ''), created_at, '') DESC,
                          id DESC
               ) AS occurrence_rank
        FROM ${FACT_LINEAGE_EVENTS_TABLE} AS event
      )
      SELECT ranked.*
      FROM ranked
      LEFT JOIN ${MATERIALIZED_FACTS_TABLE} AS materialized
        ON materialized.entity_id = ranked.entity_id
       AND materialized.kind = ranked.kind
       AND materialized.value = ranked.value
      WHERE ranked.occurrence_rank = 1
        AND COALESCE(ranked.lineage_key, '') = ''
        AND (
          materialized.id IS NULL
          OR materialized.event_id IS NOT ranked.event_id
          OR materialized.evidence IS NOT ranked.evidence
          OR materialized.source_ref IS NOT ranked.source_ref
          OR materialized.said_at IS NOT ranked.said_at
          OR materialized.said_by IS NOT ranked.said_by
          OR materialized.confidence IS NOT ranked.confidence
          OR materialized.created_at IS NOT ranked.created_at
          OR materialized.lineage_key IS NOT ranked.lineage_key
          OR materialized.valid_from IS NOT ranked.valid_from
          OR materialized.valid_to IS NOT ranked.valid_to
          OR materialized.superseded_by IS NOT ranked.superseded_by
          OR materialized.status IS NOT ranked.status
        )
    `).all();
    for (const event of materializedProjectionRepairs) writeMaterializedProjection(db, event);
    if (ownsTransaction) db.exec('COMMIT;');
    return {
      migrated:
        columnsAdded.length > 0 || rows.length > 0 || eventTableCreated || outboxTableCreated
        || eventBackfill.changes > 0,
      backfilled: rows.length,
      eventsBackfilled: Number(eventBackfill.changes || 0),
      eventTableCreated,
      outboxTableCreated,
      lineagesReconciled: lineages.length,
      unkeyedValuesReconciled: materializedProjectionRepairs.filter(
        (event) => !String(event.lineage_key || '').trim(),
      ).length,
      materializedValuesReconciled: materializedProjectionRepairs.length,
      columnsAdded,
    };
  } catch (error) {
    if (ownsTransaction) {
      try { db.exec('ROLLBACK;'); } catch {}
    }
    throw error;
  }
}

function reconcileLineageInTable(db, tableName, entityId, lineageKey) {
  const rows = db.prepare(`
    SELECT id, event_id, valid_from, said_at, created_at, status
    FROM ${tableName}
    WHERE entity_id = ? AND lineage_key = ?
    ORDER BY COALESCE(NULLIF(valid_from, ''), NULLIF(said_at, ''), created_at, '') ASC, id ASC
  `).all(entityId, lineageKey);
  const update = db.prepare(`
    UPDATE ${tableName}
    SET status = ?, valid_to = ?, superseded_by = ?
    WHERE id = ?
  `);
  const supersededLinks = [];
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    const rowStatus = String(row.status || CURRENT_STATUS).toLowerCase();
    if (rowStatus === RETRACTED_STATUS || rowStatus === CONFLICT_STATUS) continue;
    const next = rows.slice(index + 1).find((candidate) =>
      String(candidate.status || CURRENT_STATUS).toLowerCase() !== CONFLICT_STATUS,
    );
    if (!next) {
      update.run(CURRENT_STATUS, null, null, row.id);
      continue;
    }
    const nextFrom = effectiveFrom(next);
    update.run(SUPERSEDED_STATUS, nextFrom || null, next.event_id || null, row.id);
    if (row.event_id) {
      supersededLinks.push({ eventId: row.event_id, supersededBy: next.event_id || null });
    }
  }
  return supersededLinks;
}

function latestEventForValue(db, entityId, kind, value) {
  return db.prepare(`
    SELECT *
    FROM ${FACT_LINEAGE_EVENTS_TABLE}
    WHERE entity_id = ? AND kind = ? AND value = ?
    ORDER BY COALESCE(NULLIF(valid_from, ''), NULLIF(said_at, ''), created_at, '') DESC, id DESC
    LIMIT 1
  `).get(entityId, kind, value);
}

function writeMaterializedProjection(db, event) {
  if (!event) return;
  db.prepare(`
    INSERT INTO ${MATERIALIZED_FACTS_TABLE}(
      entity_id, kind, value, evidence, source_ref, said_at, said_by, confidence, created_at,
      event_id, lineage_key, valid_from, valid_to, superseded_by, status
    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(entity_id, kind, value) DO NOTHING
  `).run(
    event.entity_id,
    event.kind,
    event.value,
    event.evidence || '',
    event.source_ref || '',
    event.said_at || '',
    event.said_by || 'owner',
    Number(event.confidence ?? 1),
    event.created_at,
    event.event_id,
    event.lineage_key || null,
    event.valid_from || null,
    event.valid_to || null,
    event.superseded_by || null,
    event.status || CURRENT_STATUS,
  );
  db.prepare(`
    UPDATE ${MATERIALIZED_FACTS_TABLE}
    SET evidence = ?, source_ref = ?, said_at = ?, said_by = ?, confidence = ?, created_at = ?,
        event_id = ?, lineage_key = ?, valid_from = ?, valid_to = ?, superseded_by = ?, status = ?
    WHERE entity_id = ? AND kind = ? AND value = ?
  `).run(
    event.evidence || '',
    event.source_ref || '',
    event.said_at || '',
    event.said_by || 'owner',
    Number(event.confidence ?? 1),
    event.created_at,
    event.event_id,
    event.lineage_key || null,
    event.valid_from || null,
    event.valid_to || null,
    event.superseded_by || null,
    event.status || CURRENT_STATUS,
    event.entity_id,
    event.kind,
    event.value,
  );
}

function syncMaterializedValue(db, entityId, kind, value) {
  writeMaterializedProjection(db, latestEventForValue(db, entityId, kind, value));
}

function syncMaterializedLineage(db, entityId, lineageKey) {
  const rows = db.prepare(`
    SELECT *
    FROM ${FACT_LINEAGE_EVENTS_TABLE}
    WHERE entity_id = ? AND lineage_key = ?
    ORDER BY COALESCE(NULLIF(valid_from, ''), NULLIF(said_at, ''), created_at, '') ASC, id ASC
  `).all(entityId, lineageKey);
  const values = new Map();
  for (const row of rows) values.set(`${row.kind}\u0000${row.value}`, row);
  for (const row of values.values()) {
    syncMaterializedValue(db, row.entity_id, row.kind, row.value);
  }
}

function syncMaterializedForEvent(db, event) {
  if (!event) return;
  if (event.lineage_key) syncMaterializedLineage(db, event.entity_id, event.lineage_key);
  else syncMaterializedValue(db, event.entity_id, event.kind, event.value);
}

function findEventStoreRow(db, eventId) {
  if (tableExists(db, FACT_LINEAGE_EVENTS_TABLE)) {
    const event = db.prepare(
      `SELECT * FROM ${FACT_LINEAGE_EVENTS_TABLE} WHERE event_id = ?`,
    ).get(eventId);
    if (event) return { tableName: FACT_LINEAGE_EVENTS_TABLE, row: event };
  }
  if (!tableExists(db, MATERIALIZED_FACTS_TABLE)) return null;
  const row = db.prepare(
    `SELECT * FROM ${MATERIALIZED_FACTS_TABLE} WHERE event_id = ?`,
  ).get(eventId);
  return row ? { tableName: MATERIALIZED_FACTS_TABLE, row } : null;
}

function terminalTransition(stored, requestedStatus, eventId) {
  const existingStatus = String(stored?.row?.status || CURRENT_STATUS).toLowerCase();
  if (existingStatus === requestedStatus) return 'unchanged';
  if (existingStatus === RETRACTED_STATUS || existingStatus === CONFLICT_STATUS) {
    throw new Error(
      `fact ${eventId} is already ${existingStatus}; cannot change terminal status to ${requestedStatus}`,
    );
  }
  return 'update';
}

function terminalInstant(stored, atISO, eventId) {
  const explicit = atISO !== undefined && atISO !== null && String(atISO).trim() !== '';
  const validTo = explicit ? canonicalInstant(atISO) : new Date().toISOString();
  if (!validTo) throw new Error(`invalid terminal timestamp for ${eventId}`);
  const validFromTimestamp = parseInstant(effectiveFrom(stored?.row));
  const validToTimestamp = parseInstant(validTo);
  if (validFromTimestamp !== null && validToTimestamp < validFromTimestamp) {
    throw new Error(`terminal timestamp for ${eventId} precedes valid_from`);
  }
  return validTo;
}

function markFactTerminal(db, eventId, status, atISO) {
  const stored = findEventStoreRow(db, eventId);
  if (!stored) return false;
  const validTo = terminalInstant(stored, atISO, eventId);
  if (terminalTransition(stored, status, eventId) === 'unchanged') {
    if (stored.tableName === FACT_LINEAGE_EVENTS_TABLE) syncMaterializedForEvent(db, stored.row);
    return true;
  }
  const result = db.prepare(`
    UPDATE ${stored.tableName}
    SET status = ?, valid_to = COALESCE(NULLIF(valid_to, ''), ?), superseded_by = NULL
    WHERE event_id = ?
  `).run(status, validTo, eventId);
  if (result.changes > 0 && stored.tableName === FACT_LINEAGE_EVENTS_TABLE) {
    const event = db.prepare(
      `SELECT * FROM ${FACT_LINEAGE_EVENTS_TABLE} WHERE event_id = ?`,
    ).get(eventId);
    syncMaterializedForEvent(db, event);
  }
  return result.changes > 0;
}

/** Local DB transition only. Use retractFactWithMemoryBestEffort at a shared-ledger boundary. */
export function retractFact(db, eventId, atISO) {
  return withImmediateTransaction(
    db,
    () => markFactTerminal(db, eventId, RETRACTED_STATUS, atISO),
  );
}

function markFactConflictInternal(db, eventId, atISO) {
  const stored = findEventStoreRow(db, eventId);
  if (!stored) return false;
  const validTo = terminalInstant(stored, atISO, eventId);
  if (terminalTransition(stored, CONFLICT_STATUS, eventId) === 'unchanged') {
    if (stored.row.lineage_key) {
      reconcileLineageInTable(db, stored.tableName, stored.row.entity_id, stored.row.lineage_key);
    }
    if (stored.tableName === FACT_LINEAGE_EVENTS_TABLE) syncMaterializedForEvent(db, stored.row);
    return true;
  }
  const changed = db.prepare(`
    UPDATE ${stored.tableName}
    SET status = ?, valid_to = COALESCE(NULLIF(valid_to, ''), ?), superseded_by = NULL
    WHERE event_id = ?
  `).run(CONFLICT_STATUS, validTo, eventId).changes > 0;
  if (!changed) return false;
  if (stored.row.lineage_key) {
    reconcileLineageInTable(db, stored.tableName, stored.row.entity_id, stored.row.lineage_key);
  }
  if (stored.tableName === FACT_LINEAGE_EVENTS_TABLE) {
    syncMaterializedForEvent(db, {
      ...stored.row,
      status: CONFLICT_STATUS,
      valid_to: validTo,
      superseded_by: null,
    });
  }
  return true;
}

/** Local DB transition only. Use markFactConflictWithMemoryBestEffort at a shared-ledger boundary. */
export function markFactConflict(db, eventId, atISO) {
  return withImmediateTransaction(db, () => markFactConflictInternal(db, eventId, atISO));
}

function directConflictPredecessorIds(db, stored) {
  if (!stored?.row?.lineage_key) return [];
  return db.prepare(`
    SELECT event_id
    FROM ${stored.tableName}
    WHERE entity_id = ?
      AND lineage_key = ?
      AND superseded_by = ?
      AND COALESCE(status, ?) = ?
      AND COALESCE(event_id, '') <> ''
    ORDER BY COALESCE(NULLIF(valid_from, ''), NULLIF(said_at, ''), created_at, '') ASC, id ASC
  `).all(
    stored.row.entity_id,
    stored.row.lineage_key,
    stored.row.event_id,
    CURRENT_STATUS,
    SUPERSEDED_STATUS,
  ).map((row) => row.event_id);
}

function restoredConflictCancellationPairs(db, stored, directPredecessorIds) {
  if (!stored?.row?.lineage_key) return [];
  const restoredIds = [];
  for (const predecessorId of directPredecessorIds) {
    const predecessor = db.prepare(`
      SELECT event_id, status
      FROM ${stored.tableName}
      WHERE event_id = ?
    `).get(predecessorId);
    if (String(predecessor?.status || '').toLowerCase() === CURRENT_STATUS) {
      restoredIds.push(predecessor.event_id);
    }
  }
  if (!restoredIds.length) {
    const rows = db.prepare(`
      SELECT event_id, status
      FROM ${stored.tableName}
      WHERE entity_id = ? AND lineage_key = ?
      ORDER BY COALESCE(NULLIF(valid_from, ''), NULLIF(said_at, ''), created_at, '') ASC, id ASC
    `).all(stored.row.entity_id, stored.row.lineage_key);
    const targetIndex = rows.findIndex((row) => row.event_id === stored.row.event_id);
    const restored = targetIndex > 0
      ? rows.slice(0, targetIndex).reverse().find(
        (row) => String(row.status || CURRENT_STATUS).toLowerCase() === CURRENT_STATUS,
      )
      : null;
    if (restored?.event_id) restoredIds.push(restored.event_id);
  }
  return [...new Set(restoredIds)].sort().map((supersededEventId) => ({
    superseded_event_id: supersededEventId,
    superseding_event_id: stored.row.event_id,
  }));
}

async function transitionFactWithMemoryBestEffort(db, eventId, status, atISO, options = {}) {
  const local = withImmediateTransaction(db, () => {
    const before = findEventStoreRow(db, eventId);
    if (!before) return { changed: false, row: null, cancelsSupersessions: [] };
    const directPredecessorIds = status === CONFLICT_STATUS
      ? directConflictPredecessorIds(db, before)
      : [];
    const changed = status === RETRACTED_STATUS
      ? markFactTerminal(db, eventId, RETRACTED_STATUS, atISO)
      : markFactConflictInternal(db, eventId, atISO);
    if (!changed) return { changed: false, row: null, cancelsSupersessions: [] };
    const stored = findEventStoreRow(db, eventId);
    const cancelsSupersessions = status === CONFLICT_STATUS
      ? restoredConflictCancellationPairs(db, stored, directPredecessorIds)
      : [];
    const payload = buildFactStatusMemoryEvent(stored?.row || null, {
      ...options,
      cancelsSupersessions,
    });
    const outbox = payload
      ? enqueueFactMemoryEvent(db, payload, { nowISO: stored?.row?.valid_to })
      : null;
    return {
      changed: true,
      row: stored?.row || null,
      cancelsSupersessions,
      payload,
      outbox,
    };
  });
  if (!local.changed) return { changed: false, row: null, payload: null, memory: null };
  if (local.outbox?.delivered) {
    return {
      ...local,
      memory: { emitted: true, reason: 'already-delivered', result: { inserted: false } },
    };
  }
  const flushed = await flushFactMemoryOutbox(db, { limit: options.flushLimit });
  const memory = flushed.results.find((result) => result.eventId === local.payload?.eventId)?.memory
    || { emitted: false, reason: 'queued' };
  return { ...local, memory };
}

export async function retractFactWithMemoryBestEffort(
  db,
  eventId,
  atISO,
  options = {},
) {
  return transitionFactWithMemoryBestEffort(
    db,
    eventId,
    RETRACTED_STATUS,
    atISO,
    options,
  );
}

export async function markFactConflictWithMemoryBestEffort(
  db,
  eventId,
  atISO,
  options = {},
) {
  return transitionFactWithMemoryBestEffort(
    db,
    eventId,
    CONFLICT_STATUS,
    atISO,
    options,
  );
}

function insertFactWithLineageInternal(db, fact, nowISO) {
  if (!tableExists(db, FACT_LINEAGE_EVENTS_TABLE)) ensureFactLineageSchema(db);
  const lineageKey = normalizeLineageKey(fact.lineage_key);
  const validFrom = canonicalInstant(fact.valid_from || fact.said_at, nowISO);
  const eventId = fact.event_id || factEventId({ ...fact, valid_from: validFrom });
  const confidence = typeof fact.confidence === 'number' ? fact.confidence : 1.0;
  const createdAt = canonicalInstant(nowISO) || String(nowISO || new Date().toISOString());

  const insert = db.prepare(`
    INSERT INTO ${FACT_LINEAGE_EVENTS_TABLE}(
      event_id, entity_id, kind, value, evidence, source_ref, said_at, said_by, confidence,
      created_at, lineage_key, valid_from, valid_to, superseded_by, status
    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
    ON CONFLICT(event_id) DO NOTHING
  `).run(
    eventId,
    fact.entity_id,
    fact.kind,
    fact.value,
    fact.evidence || '',
    fact.source_ref || '',
    fact.said_at || '',
    fact.said_by || 'owner',
    confidence,
    createdAt,
    lineageKey,
    validFrom || null,
    CURRENT_STATUS,
  );

  let row = db.prepare(
    `SELECT * FROM ${FACT_LINEAGE_EVENTS_TABLE} WHERE event_id = ?`,
  ).get(eventId);
  const expected = {
    entity_id: String(fact.entity_id || ''),
    kind: String(fact.kind || ''),
    value: String(fact.value || ''),
    evidence: String(fact.evidence || ''),
    source_ref: String(fact.source_ref || ''),
    said_at: String(fact.said_at || ''),
    said_by: String(fact.said_by || 'owner'),
    confidence,
    lineage_key: lineageKey,
    valid_from: validFrom || null,
  };
  const collision = row && (
    String(row.entity_id || '') !== expected.entity_id ||
    String(row.kind || '') !== expected.kind ||
    String(row.value || '') !== expected.value ||
    String(row.evidence || '') !== expected.evidence ||
    String(row.source_ref || '') !== expected.source_ref ||
    String(row.said_at || '') !== expected.said_at ||
    String(row.said_by || 'owner') !== expected.said_by ||
    Number(row.confidence ?? 1) !== expected.confidence ||
    (row.lineage_key || null) !== expected.lineage_key ||
    (row.valid_from || null) !== expected.valid_from
  );
  if (collision) {
    throw new Error(`fact event id collision for ${eventId}`);
  }

  const supersededLinks = lineageKey
    ? reconcileLineageInTable(db, FACT_LINEAGE_EVENTS_TABLE, fact.entity_id, lineageKey)
    : [];
  row = db.prepare(
    `SELECT * FROM ${FACT_LINEAGE_EVENTS_TABLE} WHERE event_id = ?`,
  ).get(eventId);
  syncMaterializedForEvent(db, row);

  return {
    inserted: insert.changes > 0,
    eventId,
    lineageKey,
    row,
    supersededEventIds: supersededLinks
      .filter((link) => link.supersededBy === (row?.event_id || eventId))
      .map((link) => link.eventId),
  };
}

export function insertFactWithLineage(db, fact, nowISO) {
  return withImmediateTransaction(db, () => insertFactWithLineageInternal(db, fact, nowISO));
}

/** Inserts a new occurrence and its shared-memory event in one local transaction. */
export function insertFactWithMemoryOutbox(db, fact, nowISO) {
  return withImmediateTransaction(db, () => {
    const result = insertFactWithLineageInternal(db, fact, nowISO);
    if (!result.inserted) return { ...result, payload: null, outbox: null };
    const payload = buildFactMemoryEvent(result.row, result.supersededEventIds);
    const outbox = payload
      ? enqueueFactMemoryEvent(db, payload, { nowISO })
      : null;
    return { ...result, payload, outbox };
  });
}

export function loadFactRowsForEntities(db, entityIds, { limit } = {}) {
  const ids = [...new Set((Array.isArray(entityIds) ? entityIds : [entityIds]).filter(Boolean))];
  if (!ids.length) return [];
  const limitValue = Number(limit);
  const query = (tableName) => {
    const columns = tableColumns(db, tableName);
    const order = [
      columns.has('said_at') ? 'said_at DESC' : null,
      columns.has('created_at') ? 'created_at DESC' : null,
      columns.has('id') ? 'id DESC' : null,
    ].filter(Boolean).join(', ');
    return db.prepare(`
      SELECT *
      FROM ${tableName}
      WHERE entity_id IN (${ids.map(() => '?').join(', ')})
      ${order ? `ORDER BY ${order}` : ''}
    `).all(...ids);
  };

  const events = tableExists(db, FACT_LINEAGE_EVENTS_TABLE)
    ? query(FACT_LINEAGE_EVENTS_TABLE)
    : [];
  const materialized = tableExists(db, MATERIALIZED_FACTS_TABLE)
    ? query(MATERIALIZED_FACTS_TABLE)
    : [];
  const merged = [...events];
  const seenEventIds = new Set(events.map((row) => row.event_id).filter(Boolean));
  const occurrenceKey = (row) => [
    row.entity_id, row.kind, row.value, row.source_ref, row.said_at, row.valid_from,
  ].map((value) => String(value ?? '')).join('\u0000');
  const seenOccurrences = new Set(events.map(occurrenceKey));
  for (const row of materialized) {
    const key = occurrenceKey(row);
    if ((row.event_id && seenEventIds.has(row.event_id)) || seenOccurrences.has(key)) continue;
    merged.push(row);
    if (row.event_id) seenEventIds.add(row.event_id);
    seenOccurrences.add(key);
  }
  merged.sort((a, b) => {
    const timeDelta = (parseInstant(effectiveFrom(b)) ?? 0) - (parseInstant(effectiveFrom(a)) ?? 0);
    if (timeDelta) return timeDelta;
    return Number(b.id || 0) - Number(a.id || 0);
  });
  return Number.isFinite(limitValue) && limitValue > 0
    ? merged.slice(0, Math.floor(limitValue))
    : merged;
}

const MONTHS_RU = new Map([
  ['января', 0], ['февраля', 1], ['марта', 2], ['апреля', 3], ['мая', 4], ['июня', 5],
  ['июля', 6], ['августа', 7], ['сентября', 8], ['октября', 9], ['ноября', 10], ['декабря', 11],
]);

function dateOnlyAsEndOfDay(year, month, day) {
  const value = new Date(Date.UTC(year, month, day, 23, 59, 59, 999));
  if (
    value.getUTCFullYear() !== year ||
    value.getUTCMonth() !== month ||
    value.getUTCDate() !== day
  ) return null;
  return value.toISOString();
}

function extractAsOf(text) {
  const normalized = String(text || '').normalize('NFKC').toLowerCase();
  const hasCue = /(?:по\s+состоянию\s+на|на\s+дату|as\s+of|--as-of|каким[аи]?\s+был[аи]?\s+на|что\s+было\s+на)/iu.test(normalized);
  if (!hasCue) return null;

  const isoTimestamp = normalized.match(/\b(\d{4}-\d{2}-\d{2}t\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?z?)\b/iu)?.[1];
  if (isoTimestamp) return canonicalInstant(isoTimestamp) || null;

  const isoDate = normalized.match(/\b(\d{4})-(\d{2})-(\d{2})\b/u);
  if (isoDate) {
    return dateOnlyAsEndOfDay(Number(isoDate[1]), Number(isoDate[2]) - 1, Number(isoDate[3]));
  }

  const dotted = normalized.match(/\b(\d{1,2})\.(\d{1,2})\.(\d{4})\b/u);
  if (dotted) {
    return dateOnlyAsEndOfDay(Number(dotted[3]), Number(dotted[2]) - 1, Number(dotted[1]));
  }

  const russian = normalized.match(
    /\b(\d{1,2})\s+(января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+(\d{4})\b/u,
  );
  if (russian) {
    return dateOnlyAsEndOfDay(Number(russian[3]), MONTHS_RU.get(russian[2]), Number(russian[1]));
  }
  return null;
}

export function detectTemporalIntent(text) {
  const value = String(text || '').normalize('NFKC').toLowerCase();
  const lexical = value.replace(/[^\p{L}\p{N}._:-]+/gu, ' ').trim();
  const asOf = extractAsOf(value);
  if (asOf) return { mode: 'as_of', asOf, explicit: true };
  if (
    /(?:--history|--all|(?:^|\s)истори[яию](?:\s|$)|(?:^|\s)раньше(?:\s|$)|(?:^|\s)в\s+прошлом(?:\s|$)|(?:^|\s)прежд[еян]\p{L}*|(?:^|\s)менял\p{L}*|(?:^|\s)за\s+вс[её]\s+время(?:\s|$)|\bhistor(?:y|ical)\b|\bpreviously\b|\bformerly\b)/iu.test(lexical)
  ) {
    return { mode: 'historical', asOf: null, explicit: true };
  }
  const explicitCurrent = /(?:--current|(?:^|\s)сейчас(?:\s|$)|(?:^|\s)теперь(?:\s|$)|(?:^|\s)текущ\p{L}*|(?:^|\s)актуальн\p{L}*|(?:^|\s)на\s+сегодня(?:\s|$)|\bcurrent(?:ly)?\b|\bnow\b)/iu.test(lexical);
  return { mode: 'current', asOf: null, explicit: explicitCurrent };
}

export function stripTemporalQualifier(text, intent = detectTemporalIntent(text)) {
  let value = String(text || '').trim();
  value = value
    .replace(/\s+--(?:history|all|current)\s*$/iu, '')
    .replace(/\s+--as-of\s+(?:\d{4}-\d{2}-\d{2}(?:t\S+)?|\d{1,2}\.\d{1,2}\.\d{4}|\d{1,2}\s+\p{L}+\s+\d{4})\s*$/iu, '')
    .replace(/\s+(?:по\s+состоянию\s+на|на\s+дату|as\s+of)\s+(?:\d{4}-\d{2}-\d{2}(?:t\S+)?|\d{1,2}\.\d{1,2}\.\d{4}|\d{1,2}\s+\p{L}+\s+\d{4})\s*$/iu, '')
    .replace(/\s+(?:сейчас|теперь|на\s+сегодня|раньше|в\s+прошлом|за\s+вс[её]\s+время|история)\s*$/iu, '')
    .trim();
  return value || (intent.mode === 'current' ? String(text || '').trim() : '');
}

export function filterFactsByTemporalIntent(facts, intent = { mode: 'current' }) {
  const rows = Array.isArray(facts) ? facts : [];
  if (intent?.mode === 'historical') return [...rows];
  if (intent?.mode === 'as_of') {
    const asOf = parseInstant(intent.asOf);
    if (asOf === null) return [];
    return rows.filter((fact) => {
      if (String(fact?.status || '').toLowerCase() === CONFLICT_STATUS) return false;
      const from = parseInstant(effectiveFrom(fact));
      const to = parseInstant(fact.valid_to);
      if (from !== null && from > asOf) return false;
      if (to !== null && asOf >= to) return false;
      return from !== null || currentFact(fact);
    });
  }
  return rows.filter(currentFact);
}

export function temporalLaneCounts(facts, selectedFacts = facts) {
  const rows = Array.isArray(facts) ? facts : [];
  const statusCount = (status) => rows.filter(
    (fact) => String(fact?.status || '').toLowerCase() === status,
  ).length;
  return {
    current: rows.filter(currentFact).length,
    historical: rows.filter((fact) => !currentFact(fact)).length,
    superseded: statusCount(SUPERSEDED_STATUS),
    retracted: statusCount(RETRACTED_STATUS),
    conflict: statusCount(CONFLICT_STATUS),
    selected: Array.isArray(selectedFacts) ? selectedFacts.length : 0,
  };
}

function telemetrySalt() {
  if (process.env.LLMWIKI_TELEMETRY_SALT) {
    return Buffer.from(process.env.LLMWIKI_TELEMETRY_SALT, 'utf8');
  }
  if (telemetrySaltCache) return telemetrySaltCache;
  const dir = path.join(os.homedir(), '.mempalace');
  const saltPath = path.join(dir, 'telemetry.salt');
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    try {
      const existing = fs.readFileSync(saltPath);
      if (existing.length >= 16) {
        try { fs.chmodSync(saltPath, 0o600); } catch {}
        telemetrySaltCache = existing;
        return existing;
      }
    } catch {}
    const generated = randomBytes(32);
    try {
      fs.writeFileSync(saltPath, generated, { flag: 'wx', mode: 0o600 });
      telemetrySaltCache = generated;
      return generated;
    } catch {
      const existing = fs.readFileSync(saltPath);
      if (existing.length >= 16) {
        try { fs.chmodSync(saltPath, 0o600); } catch {}
        telemetrySaltCache = existing;
        return existing;
      }
    }
  } catch {
    // Read-only or unavailable home: keep a process-random, non-persistent salt.
  }
  telemetrySaltCache = randomBytes(32);
  return telemetrySaltCache;
}

export function privacySafeHash(value, namespace = 'value') {
  if (value === undefined || value === null || String(value) === '') return null;
  const digest = createHmac('sha256', telemetrySalt())
    .update(`${namespace}\u0000${String(value)}`, 'utf8')
    .digest('hex')
    .slice(0, 24);
  return `hmac256:${digest}`;
}

export function createCorrelationId() {
  return randomUUID();
}

export function buildAskTelemetryRow({
  ts,
  correlationId,
  question,
  chunks = [],
  entityFactsContext,
  resolvedEntities = [],
  temporalIntent,
  engine,
  model,
  scope,
  denied,
  retrievalMs,
  synthesisMs,
  totalMs,
  answerLength,
  outcome,
  error,
}) {
  const laneCounts = entityFactsContext?.laneCounts || { current: 0, historical: 0, selected: 0 };
  return {
    telemetry_version: ASK_TELEMETRY_VERSION,
    ts,
    correlation_id: correlationId || createCorrelationId(),
    question_hash: privacySafeHash(question, 'question'),
    question_length: String(question || '').length,
    chunks: chunks.length,
    factEntities: Array.isArray(entityFactsContext?.entities) ? entityFactsContext.entities.length : 0,
    lane_counts: {
      content: chunks.length,
      facts_current: Number(laneCounts.current || 0),
      facts_historical: Number(laneCounts.historical || 0),
      facts_selected: Number(laneCounts.selected || 0),
      facts_retracted: Number(laneCounts.retracted || 0),
      facts_conflict: Number(laneCounts.conflict || 0),
    },
    temporal_mode: temporalIntent?.mode || entityFactsContext?.temporalIntent?.mode || 'current',
    engine,
    model: model || null,
    scope: scope || null,
    denied: Boolean(denied),
    outcome: outcome || (error ? 'error' : 'unknown'),
    retrieval_ms: Number(retrievalMs || 0),
    synthesis_ms: Number(synthesisMs || 0),
    total_ms: Number(totalMs || 0),
    answer_length: Number(answerLength || 0),
    entity_hashes: resolvedEntities
      .map((entity) => privacySafeHash(entity?.id || entity?.name, 'entity'))
      .filter(Boolean)
      .slice(0, 5),
    source_hashes: chunks
      .map((chunk) => privacySafeHash(chunk?.id || chunk?.source_id, 'source'))
      .filter(Boolean)
      .slice(0, 6),
    error_type: error ? String(error?.name || 'Error').slice(0, 80) : null,
    error_hash: error ? privacySafeHash(error?.message || error, 'error') : null,
  };
}

export function buildFactMemoryEvent(fact, supersededEventIds = []) {
  if (!fact?.event_id) return null;
  return {
    eventId: fact.event_id,
    eventType: 'fact',
    producer: 'llm-wiki',
    source: 'llm-wiki',
    sourceRef: fact.source_ref || fact.event_id,
    sessionId: 'llm-wiki:entity-facts',
    messageId: fact.event_id,
    role: 'system',
    content: `[${fact.kind}] ${fact.value}`,
    createdAt: fact.valid_from || fact.said_at || fact.created_at || undefined,
    status: fact.status || CURRENT_STATUS,
    provenance: {
      evidence: fact.evidence || '',
      source_ref: fact.source_ref || '',
      said_at: fact.said_at || '',
      said_by: fact.said_by || 'owner',
      confidence: Number(fact.confidence ?? 1),
    },
    metadata: {
      event_version: FACT_LINEAGE_SCHEMA_VERSION,
      source_id: fact.source_ref || '',
      source_ref: fact.source_ref || '',
      entity_id: fact.entity_id,
      lineage_key: fact.lineage_key || null,
      valid_from: fact.valid_from || null,
      valid_to: fact.valid_to || null,
      superseded_by: fact.superseded_by || null,
      supersedes: supersededEventIds,
    },
  };
}

function normalizeSupersessionCancellationPairs(values) {
  const pairs = new Map();
  const visit = (value) => {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (!value || typeof value !== 'object') return;
    const supersededEventId = String(value.superseded_event_id || '').trim();
    const supersedingEventId = String(value.superseding_event_id || '').trim();
    const validId = (id) => /^[A-Za-z0-9._:@/-]{1,200}$/.test(id);
    if (!validId(supersededEventId) || !validId(supersedingEventId)
        || supersededEventId === supersedingEventId) return;
    pairs.set(`${supersededEventId}\u0000${supersedingEventId}`, {
      superseded_event_id: supersededEventId,
      superseding_event_id: supersedingEventId,
    });
  };
  visit(values);
  return [...pairs.values()].sort((left, right) => (
    left.superseded_event_id.localeCompare(right.superseded_event_id)
      || left.superseding_event_id.localeCompare(right.superseding_event_id)
  ));
}

/**
 * Builds the append-only shared-ledger event required after a local retract/conflict.
 * The payload supersedes the original shared fact event; callers that cannot use the
 * best-effort wrappers can persist/retry this payload in their own outbox.
 */
export function buildFactStatusMemoryEvent(
  fact,
  { reason = '', cancelsSupersessions = [], cancels_supersessions = [] } = {},
) {
  if (!fact?.event_id) return null;
  const factStatus = String(fact.status || '').toLowerCase();
  if (factStatus !== RETRACTED_STATUS && factStatus !== CONFLICT_STATUS) return null;
  const eventType = factStatus === RETRACTED_STATUS ? 'fact_retraction' : 'fact_conflict';
  const reasonText = String(reason || '').trim();
  const transitionAt = canonicalInstant(fact.valid_to || '') || String(fact.valid_to || '');
  const cancellationPairs = factStatus === CONFLICT_STATUS
    ? normalizeSupersessionCancellationPairs([cancelsSupersessions, cancels_supersessions])
    : [];
  const transitionEventId = `fact_transition_${sha256([
    FACT_MEMORY_TRANSITION_ID_VERSION,
    fact.event_id,
    factStatus,
    transitionAt,
  ].join('\u0000'), 32)}`;
  const reasonSuffix = reasonText ? ` — ${reasonText}` : '';
  return {
    eventId: transitionEventId,
    eventType,
    producer: 'llm-wiki',
    source: 'llm-wiki',
    sourceRef: fact.source_ref || fact.event_id,
    sessionId: 'llm-wiki:entity-facts',
    messageId: transitionEventId,
    role: 'system',
    content: `[${eventType}] [${fact.kind}] ${fact.value}${reasonSuffix}`,
    createdAt: transitionAt || fact.created_at || undefined,
    status: 'captured',
    provenance: {
      evidence: fact.evidence || '',
      source_ref: fact.source_ref || '',
      said_at: fact.said_at || '',
      said_by: fact.said_by || 'owner',
      confidence: Number(fact.confidence ?? 1),
      reason: reasonText,
    },
    metadata: {
      event_version: FACT_LINEAGE_SCHEMA_VERSION,
      transition_contract_version: FACT_MEMORY_TRANSITION_ID_VERSION,
      lifecycle_control: true,
      source_id: fact.source_ref || '',
      source_ref: fact.source_ref || '',
      entity_id: fact.entity_id,
      lineage_key: fact.lineage_key || null,
      factId: fact.event_id,
      fact_status: factStatus,
      valid_from: fact.valid_from || null,
      valid_to: fact.valid_to || null,
      supersedes: [fact.event_id],
      reason: reasonText,
      ...(cancellationPairs.length ? { cancels_supersessions: cancellationPairs } : {}),
    },
  };
}

function factMemoryOutboxIdentity(payload) {
  const eventId = String(payload?.eventId || '').trim();
  if (!eventId) throw new Error('fact memory outbox eventId is required');
  const eventType = String(payload?.eventType || '').toLowerCase();
  const lifecycleKind = eventType === 'fact'
    ? 'occurrence'
    : String(payload?.metadata?.fact_status || eventType || '').toLowerCase();
  const factEventId = eventType === 'fact'
    ? eventId
    : String(payload?.metadata?.factId || '').trim();
  if (!factEventId || !lifecycleKind) {
    throw new Error(`invalid fact memory outbox payload for ${eventId}`);
  }
  return { eventId, factEventId, lifecycleKind };
}

export function enqueueFactMemoryEvent(db, payload, { nowISO } = {}) {
  ensureFactMemoryOutboxSchema(db);
  const identity = factMemoryOutboxIdentity(payload);
  const payloadJson = JSON.stringify(payload);
  const existing = db.prepare(`
    SELECT payload_json, delivered_at
    FROM ${FACT_MEMORY_OUTBOX_TABLE}
    WHERE event_id = ?
  `).get(identity.eventId);
  if (existing) {
    if (existing.payload_json !== payloadJson) {
      const error = new Error(`fact memory outbox event id collision for ${identity.eventId}`);
      error.code = 'FACT_MEMORY_OUTBOX_COLLISION';
      throw error;
    }
    const delivered = Boolean(existing.delivered_at);
    return {
      eventId: identity.eventId,
      inserted: false,
      queued: !delivered,
      delivered,
    };
  }
  const createdAt = canonicalInstant(nowISO)
    || canonicalInstant(payload?.createdAt)
    || new Date().toISOString();
  db.prepare(`
    INSERT INTO ${FACT_MEMORY_OUTBOX_TABLE}(
      event_id, fact_event_id, lifecycle_kind, payload_json, created_at
    ) VALUES(?, ?, ?, ?, ?)
  `).run(
    identity.eventId,
    identity.factEventId,
    identity.lifecycleKind,
    payloadJson,
    createdAt,
  );
  return {
    eventId: identity.eventId,
    inserted: true,
    queued: true,
    delivered: false,
  };
}

function canonicalOccurrenceSnapshot(db, event) {
  if (!event?.lineage_key) {
    return {
      row: { ...event, status: CURRENT_STATUS, valid_to: null, superseded_by: null },
      supersededEventIds: [],
    };
  }
  const insertedAt = parseInstant(event.created_at) ?? parseInstant(effectiveFrom(event));
  const rows = db.prepare(`
    SELECT *
    FROM ${FACT_LINEAGE_EVENTS_TABLE}
    WHERE entity_id = ? AND lineage_key = ? AND id <= ?
    ORDER BY COALESCE(NULLIF(valid_from, ''), NULLIF(said_at, ''), created_at, '') ASC, id ASC
  `).all(event.entity_id, event.lineage_key, event.id).map((row) => {
    const storedStatus = String(row.status || CURRENT_STATUS).toLowerCase();
    const terminalAt = parseInstant(row.valid_to);
    const terminalAlreadyApplied = row.id !== event.id
      && (storedStatus === RETRACTED_STATUS || storedStatus === CONFLICT_STATUS)
      && insertedAt !== null
      && terminalAt !== null
      && terminalAt <= insertedAt;
    return {
      ...row,
      status: terminalAlreadyApplied ? storedStatus : CURRENT_STATUS,
      valid_to: terminalAlreadyApplied ? row.valid_to : null,
      superseded_by: null,
    };
  });
  const supersededEventIds = [];
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    const rowStatus = String(row.status || CURRENT_STATUS).toLowerCase();
    if (rowStatus === RETRACTED_STATUS || rowStatus === CONFLICT_STATUS) continue;
    const next = rows.slice(index + 1).find((candidate) =>
      String(candidate.status || CURRENT_STATUS).toLowerCase() !== CONFLICT_STATUS,
    );
    if (!next) {
      row.status = CURRENT_STATUS;
      row.valid_to = null;
      row.superseded_by = null;
      continue;
    }
    row.status = SUPERSEDED_STATUS;
    row.valid_to = effectiveFrom(next) || null;
    row.superseded_by = next.event_id || null;
    if (next.event_id === event.event_id && row.event_id) {
      supersededEventIds.push(row.event_id);
    }
  }
  const snapshot = rows.find((row) => row.event_id === event.event_id) || event;
  return {
    row: snapshot,
    supersededEventIds: [...new Set(supersededEventIds)].sort(),
  };
}

function missingFactMemoryRowsSql(selectClause) {
  return `
    SELECT ${selectClause}
    FROM ${FACT_LINEAGE_EVENTS_TABLE} AS event
    WHERE NOT EXISTS (
      SELECT 1
      FROM ${FACT_MEMORY_OUTBOX_TABLE} AS occurrence
      WHERE occurrence.event_id = event.event_id
    )
       OR (
         event.status IN ('${RETRACTED_STATUS}', '${CONFLICT_STATUS}')
         AND NOT EXISTS (
           SELECT 1
           FROM ${FACT_MEMORY_OUTBOX_TABLE} AS terminal
           WHERE terminal.fact_event_id = event.event_id
             AND terminal.lifecycle_kind = event.status
         )
       )
  `;
}

/**
 * Bounded, repeatable backfill for pre-outbox occurrence and terminal rows.
 * Re-running until remaining=0 queues each stable lifecycle event exactly once.
 */
export function reconcileFactMemoryOutbox(db, { limit } = {}) {
  ensureFactMemoryOutboxSchema(db);
  if (!tableExists(db, FACT_LINEAGE_EVENTS_TABLE)) {
    return { scanned: 0, enqueued: 0, remaining: 0 };
  }
  const batchLimit = boundedBatchLimit(limit);
  return withImmediateTransaction(db, () => {
    const rows = db.prepare(`
      ${missingFactMemoryRowsSql('event.*')}
      ORDER BY event.id ASC
      LIMIT ?
    `).all(batchLimit);
    let enqueued = 0;
    for (const row of rows) {
      const occurrenceExists = db.prepare(`
        SELECT 1
        FROM ${FACT_MEMORY_OUTBOX_TABLE}
        WHERE event_id = ?
      `).get(row.event_id);
      if (!occurrenceExists) {
        const snapshot = canonicalOccurrenceSnapshot(db, row);
        const payload = buildFactMemoryEvent(snapshot.row, snapshot.supersededEventIds);
        if (payload && enqueueFactMemoryEvent(db, payload, { nowISO: row.created_at }).inserted) {
          enqueued += 1;
        }
      }
      const status = String(row.status || '').toLowerCase();
      if (status !== RETRACTED_STATUS && status !== CONFLICT_STATUS) continue;
      const terminalExists = db.prepare(`
        SELECT 1
        FROM ${FACT_MEMORY_OUTBOX_TABLE}
        WHERE fact_event_id = ? AND lifecycle_kind = ?
      `).get(row.event_id, status);
      if (terminalExists) continue;
      const stored = { tableName: FACT_LINEAGE_EVENTS_TABLE, row };
      const cancelsSupersessions = status === CONFLICT_STATUS
        ? restoredConflictCancellationPairs(db, stored, [])
        : [];
      const payload = buildFactStatusMemoryEvent(row, { cancelsSupersessions });
      if (payload && enqueueFactMemoryEvent(db, payload, { nowISO: row.valid_to }).inserted) {
        enqueued += 1;
      }
    }
    const remaining = Number(db.prepare(`
      SELECT COUNT(*) AS count
      FROM (${missingFactMemoryRowsSql('event.id')}) AS missing
    `).get().count || 0);
    return { scanned: rows.length, enqueued, remaining };
  });
}

export async function flushFactMemoryOutbox(db, { limit } = {}) {
  ensureFactMemoryOutboxSchema(db);
  const batchLimit = boundedBatchLimit(limit);
  const rows = db.prepare(`
    SELECT id, event_id, payload_json
    FROM ${FACT_MEMORY_OUTBOX_TABLE}
    WHERE delivered_at IS NULL
    ORDER BY id ASC
    LIMIT ?
  `).all(batchLimit);
  const results = [];
  for (const row of rows) {
    let memory;
    try {
      memory = await emitFactMemoryEventBestEffort(JSON.parse(row.payload_json));
    } catch (error) {
      memory = {
        emitted: false,
        reason: 'invalid-payload',
        errorType: String(error?.name || 'Error'),
      };
    }
    const attemptedAt = new Date().toISOString();
    const lastError = memory.emitted
      ? null
      : [memory.reason, memory.errorType].filter(Boolean).join(':');
    db.prepare(`
      UPDATE ${FACT_MEMORY_OUTBOX_TABLE}
      SET attempts = attempts + 1,
          last_attempt_at = ?,
          last_error = ?,
          delivered_at = CASE WHEN ? THEN COALESCE(delivered_at, ?) ELSE delivered_at END
      WHERE id = ?
    `).run(attemptedAt, lastError, memory.emitted ? 1 : 0, attemptedAt, row.id);
    results.push({ eventId: row.event_id, memory });
    if (!memory.emitted) break;
  }
  const delivered = results.filter((result) => result.memory.emitted).length;
  const failed = results.length - delivered;
  const remaining = Number(db.prepare(`
    SELECT COUNT(*) AS count
    FROM ${FACT_MEMORY_OUTBOX_TABLE}
    WHERE delivered_at IS NULL
  `).get().count || 0);
  return {
    selected: rows.length,
    attempted: results.length,
    delivered,
    failed,
    remaining,
    results,
  };
}

function loadMemoryContract() {
  if (memoryContractOverride !== undefined) return memoryContractOverride;
  if (memoryContractCache !== undefined) return memoryContractCache;
  const candidates = [
    process.env.MEMORY_CONTRACT_MODULE,
    path.resolve(__dirname, '../scripts/memory_contract.js'),
    path.resolve(__dirname, '../shared-memory/memory_contract.js'),
    path.resolve(__dirname, 'runtime/memory_contract.cjs'),
    path.resolve(__dirname, 'memory_contract.cjs'),
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      const resolved = path.isAbsolute(candidate) ? candidate : path.resolve(process.cwd(), candidate);
      if (!fs.existsSync(resolved)) continue;
      const adapter = require(resolved);
      if (typeof adapter?.captureEvent === 'function') {
        memoryContractCache = adapter;
        return adapter;
      }
    } catch {
      // Optional bridge: keep fact persistence independent from shared memory.
    }
  }
  memoryContractCache = null;
  return null;
}

export function setMemoryContractAdapterForTests(adapter) {
  memoryContractOverride = adapter;
}

export async function emitFactMemoryEventBestEffort(payload) {
  if (!payload) return { emitted: false, reason: 'empty-payload' };
  try {
    const adapter = loadMemoryContract();
    if (!adapter) return { emitted: false, reason: 'bridge-unavailable' };
    const result = await adapter.captureEvent(payload);
    return { emitted: true, result };
  } catch (error) {
    return {
      emitted: false,
      reason: 'bridge-error',
      errorType: String(error?.name || 'Error'),
    };
  }
}
