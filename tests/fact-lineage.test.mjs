import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import {
  ASK_TELEMETRY_VERSION,
  FACT_MEMORY_OUTBOX_TABLE,
  buildAskTelemetryRow,
  buildFactMemoryEvent,
  buildFactStatusMemoryEvent,
  detectTemporalIntent,
  enqueueFactMemoryEvent,
  emitFactMemoryEventBestEffort,
  ensureFactLineageSchema,
  filterFactsByTemporalIntent,
  flushFactMemoryOutbox,
  insertFactWithLineage,
  insertFactWithMemoryOutbox,
  loadFactRowsForEntities,
  markFactConflict,
  markFactConflictWithMemoryBestEffort,
  normalizeLineageKey,
  reconcileFactMemoryOutbox,
  retractFact,
  retractFactWithMemoryBestEffort,
  setMemoryContractAdapterForTests,
  stripTemporalQualifier,
  temporalLaneCounts,
} from '../wiki/fact-lineage.mjs';

const require = createRequire(import.meta.url);

function createLegacyFactsDb() {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE sidecar_entity_facts(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      entity_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      value TEXT NOT NULL,
      evidence TEXT NOT NULL DEFAULT '',
      source_ref TEXT NOT NULL DEFAULT '',
      said_at TEXT NOT NULL DEFAULT '',
      said_by TEXT NOT NULL DEFAULT 'owner',
      confidence REAL NOT NULL DEFAULT 1.0,
      created_at TEXT NOT NULL,
      UNIQUE(entity_id, kind, value)
    );
  `);
  return db;
}

function insert(db, overrides = {}) {
  return insertFactWithLineage(db, {
    entity_id: 'entity:alice',
    kind: 'preference',
    value: 'red',
    evidence: 'Alice explicitly chose the red option.',
    source_ref: 'note:1',
    said_at: '2026-01-01T10:00:00Z',
    said_by: 'owner',
    confidence: 0.9,
    lineage_key: 'preference.color',
    ...overrides,
  }, overrides.nowISO || '2026-01-01T11:00:00Z');
}

test('lineage migration is additive, idempotent, and safely leaves legacy lineage unknown', () => {
  const db = createLegacyFactsDb();
  db.prepare(`
    INSERT INTO sidecar_entity_facts(
      entity_id, kind, value, evidence, source_ref, said_at, said_by, confidence, created_at
    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    'entity:legacy', 'fact', 'legacy value', 'legacy evidence', 'note:legacy',
    '2025-12-03T10:00:00Z', 'owner', 1, '2025-12-03T11:00:00Z',
  );

  const first = ensureFactLineageSchema(db);
  const before = db.prepare('SELECT * FROM sidecar_entity_facts').get();
  const second = ensureFactLineageSchema(db);
  const after = db.prepare('SELECT * FROM sidecar_entity_facts').get();

  assert.deepEqual(first.columnsAdded, [
    'event_id', 'lineage_key', 'valid_from', 'valid_to', 'superseded_by', 'status',
  ]);
  assert.equal(second.columnsAdded.length, 0);
  assert.equal(first.eventTableCreated, true);
  assert.equal(first.eventsBackfilled, 1);
  assert.equal(second.eventTableCreated, false);
  assert.equal(second.eventsBackfilled, 0);
  assert.match(before.event_id, /^fact_[0-9a-f]{32}$/u);
  assert.equal(before.lineage_key, null);
  assert.equal(before.status, 'current');
  assert.equal(before.valid_from, '2025-12-03T10:00:00.000Z');
  assert.equal(after.event_id, before.event_id);
  assert.deepEqual(
    { ...db.prepare(`
      SELECT event_id, entity_id, value, status, valid_from
      FROM sidecar_fact_lineage_events
    `).get() },
    {
      event_id: before.event_id,
      entity_id: 'entity:legacy',
      value: 'legacy value',
      status: 'current',
      valid_from: '2025-12-03T10:00:00.000Z',
    },
  );
  db.close();
});

test('lineage migration backfills a 9k legacy table in one idempotent transaction', () => {
  const db = createLegacyFactsDb();
  db.exec('BEGIN;');
  const insertLegacy = db.prepare(`
    INSERT INTO sidecar_entity_facts(
      entity_id, kind, value, evidence, source_ref, said_at, said_by, confidence, created_at
    ) VALUES(?, 'fact', ?, 'legacy evidence', ?, '2026-01-01T00:00:00Z', 'owner', 1, '2026-01-01T00:00:01Z')
  `);
  for (let index = 0; index < 9_000; index += 1) {
    insertLegacy.run(`entity:${index % 20}`, `value:${index}`, `note:${index}`);
  }
  db.exec('COMMIT;');

  const migrated = ensureFactLineageSchema(db);
  assert.equal(migrated.backfilled, 9_000);
  assert.equal(db.isTransaction, false);
  assert.equal(
    db.prepare("SELECT COUNT(*) AS count FROM sidecar_entity_facts WHERE event_id != '' AND status = 'current'").get().count,
    9_000,
  );
  assert.equal(
    db.prepare('SELECT COUNT(*) AS count FROM sidecar_fact_lineage_events').get().count,
    9_000,
  );
  const second = ensureFactLineageSchema(db);
  assert.equal(second.backfilled, 0);
  assert.equal(second.eventsBackfilled, 0);
  db.close();
});

test('migration reconciles pre-existing lineage rows while backfilling the event table', () => {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE sidecar_entity_facts(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      entity_id TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
      evidence TEXT NOT NULL DEFAULT '', source_ref TEXT NOT NULL DEFAULT '',
      said_at TEXT NOT NULL DEFAULT '', said_by TEXT NOT NULL DEFAULT 'owner',
      confidence REAL NOT NULL DEFAULT 1.0, created_at TEXT NOT NULL,
      event_id TEXT, lineage_key TEXT, valid_from TEXT, valid_to TEXT,
      superseded_by TEXT, status TEXT NOT NULL DEFAULT 'current',
      UNIQUE(entity_id, kind, value)
    );
    INSERT INTO sidecar_entity_facts(
      entity_id, kind, value, evidence, source_ref, said_at, created_at,
      event_id, lineage_key, valid_from, status
    ) VALUES
      ('entity:alice', 'preference', 'red', 'red evidence', 'note:1',
       '2026-01-01T10:00:00Z', '2026-01-01T11:00:00Z', 'legacy:red',
       'preference.color', '2026-01-01T10:00:00.000Z', 'current'),
      ('entity:alice', 'preference', 'blue', 'blue evidence', 'note:2',
       '2026-02-01T10:00:00Z', '2026-02-01T11:00:00Z', 'legacy:blue',
       'preference.color', '2026-02-01T10:00:00.000Z', 'current');
  `);

  const migrated = ensureFactLineageSchema(db);
  assert.equal(migrated.eventsBackfilled, 2);
  assert.equal(migrated.lineagesReconciled, 1);
  const events = db.prepare(`
    SELECT event_id, status, valid_to, superseded_by
    FROM sidecar_fact_lineage_events
    ORDER BY valid_from
  `).all().map((row) => ({ ...row }));
  assert.deepEqual(events, [
    {
      event_id: 'legacy:red', status: 'superseded',
      valid_to: '2026-02-01T10:00:00.000Z', superseded_by: 'legacy:blue',
    },
    { event_id: 'legacy:blue', status: 'current', valid_to: null, superseded_by: null },
  ]);
  assert.deepEqual(
    db.prepare('SELECT value, status FROM sidecar_entity_facts ORDER BY valid_from').all()
      .map((row) => ({ ...row })),
    [{ value: 'red', status: 'superseded' }, { value: 'blue', status: 'current' }],
  );
  db.close();
});

test('a new value in the same lineage supersedes the prior current value', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  const red = insert(db);
  const blue = insert(db, {
    value: 'blue',
    evidence: 'Alice explicitly chose the blue option.',
    source_ref: 'note:2',
    said_at: '2026-02-01T10:00:00Z',
    nowISO: '2026-02-01T11:00:00Z',
  });
  const rows = db.prepare('SELECT * FROM sidecar_entity_facts ORDER BY valid_from').all();

  assert.equal(red.inserted, true);
  assert.equal(blue.inserted, true);
  assert.deepEqual(blue.supersededEventIds, [red.eventId]);
  assert.equal(rows[0].status, 'superseded');
  assert.equal(rows[0].valid_to, '2026-02-01T10:00:00.000Z');
  assert.equal(rows[0].superseded_by, rows[1].event_id);
  assert.equal(rows[1].status, 'current');
  assert.equal(rows[1].valid_to, null);
  assert.deepEqual(filterFactsByTemporalIntent(rows).map((row) => row.value), ['blue']);
  assert.deepEqual(
    filterFactsByTemporalIntent(rows, {
      mode: 'as_of',
      asOf: '2026-01-15T23:59:59.999Z',
    }).map((row) => row.value),
    ['red'],
  );
  assert.deepEqual(
    filterFactsByTemporalIntent(rows, { mode: 'historical' }).map((row) => row.value),
    ['red', 'blue'],
  );
  assert.deepEqual(temporalLaneCounts(rows, [rows[1]]), {
    current: 1,
    historical: 1,
    superseded: 1,
    retracted: 0,
    conflict: 0,
    selected: 1,
  });
  db.close();
});

test('generated occurrence event ids remain stable across lineage schema versions', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  assert.equal(insert(db).eventId, 'fact_d45448d308270ff788b128d635dd69d3');
  db.close();
});

test('append-only events preserve an exact A→B→A reversion for current, history, and as-of reads', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  const firstRed = insert(db);
  const blue = insert(db, {
    value: 'blue',
    evidence: 'Alice explicitly chose the blue option.',
    source_ref: 'note:2',
    said_at: '2026-02-01T10:00:00Z',
    nowISO: '2026-02-01T11:00:00Z',
  });
  const secondRed = insert(db, {
    evidence: 'Alice explicitly returned to the red option.',
    source_ref: 'note:3',
    said_at: '2026-03-01T10:00:00Z',
    nowISO: '2026-03-01T11:00:00Z',
  });

  assert.equal(secondRed.inserted, true);
  assert.notEqual(secondRed.eventId, firstRed.eventId);
  assert.deepEqual(secondRed.supersededEventIds, [blue.eventId]);

  const events = loadFactRowsForEntities(db, ['entity:alice'])
    .sort((a, b) => a.valid_from.localeCompare(b.valid_from));
  assert.deepEqual(events.map((row) => ({ value: row.value, status: row.status })), [
    { value: 'red', status: 'superseded' },
    { value: 'blue', status: 'superseded' },
    { value: 'red', status: 'current' },
  ]);
  assert.equal(events[0].superseded_by, blue.eventId);
  assert.equal(events[1].superseded_by, secondRed.eventId);
  assert.equal(events[2].valid_to, null);

  assert.deepEqual(
    filterFactsByTemporalIntent(events).map((row) => row.event_id),
    [secondRed.eventId],
  );
  assert.deepEqual(
    filterFactsByTemporalIntent(events, {
      mode: 'as_of', asOf: '2026-01-15T23:59:59.999Z',
    }).map((row) => row.event_id),
    [firstRed.eventId],
  );
  assert.deepEqual(
    filterFactsByTemporalIntent(events, {
      mode: 'as_of', asOf: '2026-02-15T23:59:59.999Z',
    }).map((row) => row.event_id),
    [blue.eventId],
  );
  assert.deepEqual(
    filterFactsByTemporalIntent(events, { mode: 'historical' }).map((row) => row.event_id),
    [firstRed.eventId, blue.eventId, secondRed.eventId],
  );

  const materialized = db.prepare(`
    SELECT value, event_id, status, source_ref
    FROM sidecar_entity_facts
    ORDER BY value
  `).all();
  assert.equal(materialized.length, 2);
  assert.deepEqual({ ...materialized.find((row) => row.value === 'red') }, {
    value: 'red', event_id: secondRed.eventId, status: 'current', source_ref: 'note:3',
  });
  db.close();
});

test('event ids are idempotent only for identical occurrence provenance', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  const original = insert(db, { event_id: 'fact:fixed' });
  assert.equal(original.inserted, true);
  const duplicate = insert(db, { event_id: 'fact:fixed' });
  assert.equal(duplicate.inserted, false);
  assert.throws(
    () => insert(db, {
      event_id: 'fact:fixed',
      evidence: 'A different provenance claim for the same external event id.',
    }),
    /fact event id collision/u,
  );
  assert.equal(
    db.prepare('SELECT COUNT(*) AS count FROM sidecar_fact_lineage_events').get().count,
    1,
  );
  db.close();
});

test('migration rejects an event id reused with different provenance', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  const original = insert(db, { event_id: 'fact:fixed' });
  db.prepare(`
    UPDATE sidecar_entity_facts
    SET evidence = 'different legacy evidence'
    WHERE event_id = ?
  `).run(original.eventId);

  assert.throws(() => ensureFactLineageSchema(db), /fact event id collision/u);
  assert.equal(
    db.prepare(`
      SELECT evidence
      FROM sidecar_fact_lineage_events
      WHERE event_id = ?
    `).get(original.eventId).evidence,
    'Alice explicitly chose the red option.',
  );
  db.close();
});

test('event reads merge missing legacy projections when the companion table is partial', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  const red = insert(db);
  const blue = insert(db, {
    value: 'blue',
    source_ref: 'note:2',
    said_at: '2026-02-01T10:00:00Z',
    nowISO: '2026-02-01T11:00:00Z',
  });
  db.prepare('DELETE FROM sidecar_fact_lineage_events WHERE event_id = ?').run(blue.eventId);

  const rows = loadFactRowsForEntities(db, ['entity:alice']);
  assert.deepEqual(new Set(rows.map((row) => row.event_id)), new Set([red.eventId, blue.eventId]));
  assert.equal(rows.find((row) => row.event_id === blue.eventId).status, 'current');
  db.close();
});

test('schema ensure repairs a missing materialized projection for unkeyed events', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  const event = insert(db, { lineage_key: null });
  db.prepare('DELETE FROM sidecar_entity_facts WHERE event_id = ?').run(event.eventId);

  const repaired = ensureFactLineageSchema(db);
  assert.equal(repaired.unkeyedValuesReconciled, 1);
  assert.deepEqual(
    { ...db.prepare(`
      SELECT event_id, status, source_ref
      FROM sidecar_entity_facts
      WHERE entity_id = ? AND kind = ? AND value = ?
    `).get('entity:alice', 'preference', 'red') },
    { event_id: event.eventId, status: 'current', source_ref: 'note:1' },
  );
  db.close();
});

test('schema ensure keeps the overall newest same-value occurrence across keyed and unkeyed events', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  insert(db, {
    lineage_key: null,
    value: 'red',
    source_ref: 'note:red-old',
    said_at: '2026-01-01T10:00:00Z',
    nowISO: '2026-01-01T11:00:00Z',
  });
  const redNewKeyed = insert(db, {
    lineage_key: 'preference.red',
    value: 'red',
    source_ref: 'note:red-new',
    said_at: '2026-02-01T10:00:00Z',
    nowISO: '2026-02-01T11:00:00Z',
  });
  insert(db, {
    lineage_key: 'preference.blue',
    value: 'blue',
    source_ref: 'note:blue-old',
    said_at: '2026-01-15T10:00:00Z',
    nowISO: '2026-01-15T11:00:00Z',
  });
  const blueNewUnkeyed = insert(db, {
    lineage_key: null,
    value: 'blue',
    source_ref: 'note:blue-new',
    said_at: '2026-03-01T10:00:00Z',
    nowISO: '2026-03-01T11:00:00Z',
  });
  db.prepare(`
    DELETE FROM sidecar_entity_facts
    WHERE entity_id = ? AND kind = ? AND value IN (?, ?)
  `).run('entity:alice', 'preference', 'red', 'blue');

  ensureFactLineageSchema(db);
  const materialized = db.prepare(`
    SELECT value, event_id, lineage_key, source_ref
    FROM sidecar_entity_facts
    ORDER BY value
  `).all().map((row) => ({ ...row }));
  assert.deepEqual(materialized, [
    {
      value: 'blue',
      event_id: blueNewUnkeyed.eventId,
      lineage_key: null,
      source_ref: 'note:blue-new',
    },
    {
      value: 'red',
      event_id: redNewKeyed.eventId,
      lineage_key: 'preference.red',
      source_ref: 'note:red-new',
    },
  ]);
  db.close();
});

test('facts without a validated lineage key never supersede one another', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  insert(db, { lineage_key: null, value: 'red' });
  insert(db, {
    lineage_key: 'Preference Color',
    value: 'blue',
    source_ref: 'note:2',
    said_at: '2026-02-01T10:00:00Z',
    nowISO: '2026-02-01T11:00:00Z',
  });
  const rows = db.prepare('SELECT lineage_key, status, valid_to FROM sidecar_entity_facts ORDER BY id').all()
    .map((row) => ({ ...row }));
  assert.deepEqual(rows, [
    { lineage_key: null, status: 'current', valid_to: null },
    { lineage_key: null, status: 'current', valid_to: null },
  ]);
  assert.equal(normalizeLineageKey('preference.color'), 'preference.color');
  assert.equal(normalizeLineageKey('Preference Color'), null);
  assert.equal(normalizeLineageKey('value/red'), null);
  db.close();
});

test('out-of-order extraction keeps the newest effective fact current', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  insert(db, {
    value: 'blue',
    source_ref: 'note:new',
    said_at: '2026-03-01T10:00:00Z',
    nowISO: '2026-03-01T11:00:00Z',
  });
  insert(db, {
    value: 'red',
    source_ref: 'note:old',
    said_at: '2026-01-01T10:00:00Z',
    nowISO: '2026-04-01T11:00:00Z',
  });
  const rows = db.prepare('SELECT value, status, valid_to FROM sidecar_entity_facts ORDER BY valid_from').all()
    .map((row) => ({ ...row }));
  assert.deepEqual(rows, [
    { value: 'red', status: 'superseded', valid_to: '2026-03-01T10:00:00.000Z' },
    { value: 'blue', status: 'current', valid_to: null },
  ]);
  db.close();
});

test('retracted and conflicted facts are excluded from current answers with distinct history semantics', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  const red = insert(db);
  const blue = insert(db, {
    value: 'blue',
    source_ref: 'note:2',
    said_at: '2026-02-01T10:00:00Z',
    nowISO: '2026-02-01T11:00:00Z',
  });
  assert.equal(retractFact(db, blue.eventId, '2026-03-01T10:00:00Z'), true);
  let rows = db.prepare('SELECT * FROM sidecar_entity_facts ORDER BY valid_from').all();
  assert.deepEqual(filterFactsByTemporalIntent(rows), []);
  assert.deepEqual(
    filterFactsByTemporalIntent(rows, {
      mode: 'as_of', asOf: '2026-02-15T00:00:00Z',
    }).map((row) => row.value),
    ['blue'],
  );
  assert.equal(rows.find((row) => row.event_id === blue.eventId).status, 'retracted');

  const green = insert(db, {
    value: 'green',
    source_ref: 'note:3',
    said_at: '2026-04-01T10:00:00Z',
    nowISO: '2026-04-01T11:00:00Z',
  });
  assert.equal(markFactConflict(db, green.eventId, '2026-04-01T12:00:00Z'), true);
  rows = db.prepare('SELECT * FROM sidecar_entity_facts ORDER BY valid_from').all();
  assert.deepEqual(filterFactsByTemporalIntent(rows), []);
  assert.ok(!filterFactsByTemporalIntent(rows, {
    mode: 'as_of', asOf: '2026-04-01T11:30:00Z',
  }).some((row) => row.event_id === green.eventId));
  assert.deepEqual(
    new Set(filterFactsByTemporalIntent(rows, { mode: 'historical' }).map((row) => row.status)),
    new Set(['superseded', 'retracted', 'conflict']),
  );
  assert.equal(rows.find((row) => row.event_id === red.eventId).status, 'superseded');
  db.close();
});

test('conflicting the latest lineage event restores the prior event as current', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  const red = insert(db);
  const blue = insert(db, {
    value: 'blue',
    source_ref: 'note:2',
    said_at: '2026-02-01T10:00:00Z',
    nowISO: '2026-02-01T11:00:00Z',
  });

  assert.equal(markFactConflict(db, blue.eventId, '2026-03-01T10:00:00Z'), true);
  const events = loadFactRowsForEntities(db, ['entity:alice']);
  assert.deepEqual(
    filterFactsByTemporalIntent(events).map((row) => row.event_id),
    [red.eventId],
  );
  assert.deepEqual(
    db.prepare(`
      SELECT event_id, status, valid_to
      FROM sidecar_entity_facts
      ORDER BY value
    `).all().map((row) => ({ ...row })),
    [
      { event_id: blue.eventId, status: 'conflict', valid_to: '2026-03-01T10:00:00.000Z' },
      { event_id: red.eventId, status: 'current', valid_to: null },
    ],
  );
  db.close();
});

test('terminal lineage statuses are idempotent and cannot be rewritten', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  const red = insert(db);
  assert.equal(retractFact(db, red.eventId, '2026-02-01T10:00:00Z'), true);
  assert.equal(retractFact(db, red.eventId, '2026-03-01T10:00:00Z'), true);
  assert.throws(
    () => markFactConflict(db, red.eventId, '2026-04-01T10:00:00Z'),
    /cannot change terminal status/u,
  );
  assert.deepEqual(
    { ...db.prepare(`
      SELECT status, valid_to
      FROM sidecar_fact_lineage_events
      WHERE event_id = ?
    `).get(red.eventId) },
    { status: 'retracted', valid_to: '2026-02-01T10:00:00.000Z' },
  );

  const blue = insert(db, {
    value: 'blue',
    source_ref: 'note:2',
    said_at: '2026-05-01T10:00:00Z',
    nowISO: '2026-05-01T11:00:00Z',
  });
  assert.equal(markFactConflict(db, blue.eventId, '2026-06-01T10:00:00Z'), true);
  assert.throws(
    () => retractFact(db, blue.eventId, '2026-07-01T10:00:00Z'),
    /cannot change terminal status/u,
  );
  assert.equal(
    db.prepare(`
      SELECT status
      FROM sidecar_fact_lineage_events
      WHERE event_id = ?
    `).get(blue.eventId).status,
    'conflict',
  );
  db.close();
});

test('terminal timestamps must be valid and cannot precede the fact interval', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  const red = insert(db, { lineage_key: null });
  assert.throws(
    () => retractFact(db, red.eventId, 'not-a-date'),
    /invalid terminal timestamp/u,
  );
  assert.throws(
    () => retractFact(db, red.eventId, '2025-12-31T23:59:59Z'),
    /precedes valid_from/u,
  );
  assert.equal(retractFact(db, red.eventId, '2026-01-01T10:00:00Z'), true);

  const blue = insert(db, {
    lineage_key: null,
    value: 'blue',
    source_ref: 'note:2',
    said_at: '2026-02-01T10:00:00Z',
    nowISO: '2026-02-01T11:00:00Z',
  });
  assert.throws(
    () => markFactConflict(db, blue.eventId, 'invalid'),
    /invalid terminal timestamp/u,
  );
  assert.throws(
    () => markFactConflict(db, blue.eventId, '2026-01-31T23:59:59Z'),
    /precedes valid_from/u,
  );
  assert.equal(markFactConflict(db, blue.eventId, '2026-02-01T10:00:00Z'), true);
  assert.deepEqual(
    db.prepare(`
      SELECT value, status, valid_to
      FROM sidecar_fact_lineage_events
      ORDER BY valid_from
    `).all().map((row) => ({ ...row })),
    [
      { value: 'red', status: 'retracted', valid_to: '2026-01-01T10:00:00.000Z' },
      { value: 'blue', status: 'conflict', valid_to: '2026-02-01T10:00:00.000Z' },
    ],
  );
  db.close();
});

test('standalone inserts roll back event and projection changes when projection sync fails', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  const red = insert(db);
  db.exec(`
    CREATE TRIGGER fail_projection_update
    BEFORE UPDATE ON sidecar_entity_facts
    BEGIN
      SELECT RAISE(ABORT, 'projection failed');
    END;
  `);

  assert.throws(
    () => insert(db, {
      value: 'blue',
      source_ref: 'note:2',
      said_at: '2026-02-01T10:00:00Z',
      nowISO: '2026-02-01T11:00:00Z',
    }),
    /projection failed/u,
  );
  assert.deepEqual(
    db.prepare(`
      SELECT event_id, status, valid_to
      FROM sidecar_fact_lineage_events
    `).all().map((row) => ({ ...row })),
    [{ event_id: red.eventId, status: 'current', valid_to: null }],
  );
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM sidecar_entity_facts').get().count, 1);
  db.close();
});

test('standalone terminal updates roll back when projection sync fails', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  const red = insert(db);
  db.exec(`
    CREATE TRIGGER fail_projection_update
    BEFORE UPDATE ON sidecar_entity_facts
    BEGIN
      SELECT RAISE(ABORT, 'projection failed');
    END;
  `);

  assert.throws(
    () => retractFact(db, red.eventId, '2026-02-01T10:00:00Z'),
    /projection failed/u,
  );
  assert.throws(
    () => markFactConflict(db, red.eventId, '2026-02-01T10:00:00Z'),
    /projection failed/u,
  );
  assert.deepEqual(
    { ...db.prepare(`
      SELECT status, valid_to
      FROM sidecar_fact_lineage_events
      WHERE event_id = ?
    `).get(red.eventId) },
    { status: 'current', valid_to: null },
  );
  assert.deepEqual(
    { ...db.prepare(`
      SELECT status, valid_to
      FROM sidecar_entity_facts
      WHERE event_id = ?
    `).get(red.eventId) },
    { status: 'current', valid_to: null },
  );
  db.close();
});

test('failed helper writes roll back to a savepoint inside a caller-owned transaction', () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  const red = insert(db);
  db.exec(`
    CREATE TRIGGER fail_projection_update
    BEFORE UPDATE ON sidecar_entity_facts
    BEGIN
      SELECT RAISE(ABORT, 'projection failed');
    END;
    BEGIN IMMEDIATE;
  `);
  assert.throws(
    () => insert(db, {
      value: 'blue',
      source_ref: 'note:2',
      said_at: '2026-02-01T10:00:00Z',
      nowISO: '2026-02-01T11:00:00Z',
    }),
    /projection failed/u,
  );
  assert.equal(db.isTransaction, true);
  db.exec('COMMIT;');

  assert.deepEqual(
    db.prepare(`
      SELECT event_id, status, valid_to
      FROM sidecar_fact_lineage_events
    `).all().map((row) => ({ ...row })),
    [{ event_id: red.eventId, status: 'current', valid_to: null }],
  );
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM sidecar_entity_facts').get().count, 1);
  db.close();
});

test('temporal intent detects current, history, and explicit as-of dates', () => {
  assert.deepEqual(detectTemporalIntent('Что актуально сейчас?'), {
    mode: 'current', asOf: null, explicit: true,
  });
  assert.deepEqual(detectTemporalIntent('Как предпочтения менялись раньше?'), {
    mode: 'historical', asOf: null, explicit: true,
  });
  assert.deepEqual(detectTemporalIntent('Что было по состоянию на 15.02.2026?'), {
    mode: 'as_of', asOf: '2026-02-15T23:59:59.999Z', explicit: true,
  });
  const intent = detectTemporalIntent('Игорь --as-of 2026-02-15');
  assert.equal(stripTemporalQualifier('Игорь --as-of 2026-02-15', intent), 'Игорь');
  assert.equal(stripTemporalQualifier('Игорь раньше'), 'Игорь');
});

test('telemetry is versioned, correlated, privacy-safe, and records lanes/outcome', () => {
  const previousSalt = process.env.LLMWIKI_TELEMETRY_SALT;
  process.env.LLMWIKI_TELEMETRY_SALT = 'test-only-private-salt';
  const row = buildAskTelemetryRow({
    ts: '2026-07-22T10:00:00Z',
    correlationId: 'corr-1',
    question: 'Секретный вопрос об Alice',
    chunks: [{ id: 'note:secret' }],
    entityFactsContext: {
      entities: [{ name: 'Alice' }],
      laneCounts: { current: 2, historical: 3, selected: 1 },
    },
    resolvedEntities: [{ id: 'entity:alice', name: 'Alice' }],
    temporalIntent: { mode: 'as_of' },
    engine: 'local',
    outcome: 'answered',
  });
  const serialized = JSON.stringify(row);
  assert.equal(row.telemetry_version, ASK_TELEMETRY_VERSION);
  assert.equal(row.correlation_id, 'corr-1');
  assert.equal(row.outcome, 'answered');
  assert.equal(row.temporal_mode, 'as_of');
  assert.deepEqual(row.lane_counts, {
    content: 1, facts_current: 2, facts_historical: 3, facts_selected: 1,
    facts_retracted: 0, facts_conflict: 0,
  });
  assert.match(row.question_hash, /^hmac256:/u);
  assert.doesNotMatch(serialized, /Секретный|Alice|note:secret|entity:alice/u);
  if (previousSalt === undefined) delete process.env.LLMWIKI_TELEMETRY_SALT;
  else process.env.LLMWIKI_TELEMETRY_SALT = previousSalt;
});

test('shared-memory fact bridge is best-effort and preserves the producer event id', async () => {
  let captured = null;
  setMemoryContractAdapterForTests({
    captureEvent(payload) {
      captured = payload;
      return { inserted: true };
    },
  });
  const payload = buildFactMemoryEvent({
    event_id: 'fact_123',
    entity_id: 'entity:alice',
    kind: 'preference',
    value: 'blue',
    evidence: 'Alice explicitly chose the blue option.',
    source_ref: 'note:2',
    said_at: '2026-02-01T10:00:00Z',
    valid_from: '2026-02-01T10:00:00Z',
    status: 'current',
    confidence: 0.9,
  }, ['fact_older']);
  const emitted = await emitFactMemoryEventBestEffort(payload);
  assert.equal(emitted.emitted, true);
  assert.equal(captured.eventId, 'fact_123');
  assert.equal(captured.eventType, 'fact');
  assert.equal(captured.producer, 'llm-wiki');
  assert.equal(captured.metadata.source_id, 'note:2');
  assert.deepEqual(captured.metadata.supersedes, ['fact_older']);

  setMemoryContractAdapterForTests({ captureEvent() { throw new Error('offline'); } });
  assert.deepEqual(await emitFactMemoryEventBestEffort(payload), {
    emitted: false, reason: 'bridge-error', errorType: 'Error',
  });
});

test('durable fact outbox retries bridge failures and never redelivers an exact event', async () => {
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  let captureCalls = 0;
  const captured = [];
  setMemoryContractAdapterForTests({
    captureEvent(payload) {
      captureCalls += 1;
      if (captureCalls === 1) throw new Error('offline');
      captured.push(payload);
      return { inserted: true };
    },
  });

  try {
    const fact = insertFactWithMemoryOutbox(db, {
      entity_id: 'entity:alice',
      kind: 'preference',
      value: 'blue',
      evidence: 'Alice explicitly chose the blue option.',
      source_ref: 'note:outbox',
      said_at: '2026-02-01T10:00:00Z',
      said_by: 'owner',
      confidence: 0.9,
      lineage_key: 'preference.color',
    }, '2026-02-01T11:00:00Z');
    assert.equal(fact.outbox.inserted, true);
    assert.equal(fact.outbox.queued, true);

    assert.deepEqual(enqueueFactMemoryEvent(db, fact.payload), {
      eventId: fact.eventId,
      inserted: false,
      queued: true,
      delivered: false,
    });
    assert.equal(
      db.prepare(`SELECT COUNT(*) AS count FROM ${FACT_MEMORY_OUTBOX_TABLE}`).get().count,
      1,
    );

    const failed = await flushFactMemoryOutbox(db, { limit: 10 });
    assert.equal(failed.attempted, 1);
    assert.equal(failed.delivered, 0);
    assert.equal(failed.failed, 1);
    assert.equal(failed.remaining, 1);
    assert.deepEqual(
      { ...db.prepare(`
        SELECT attempts, delivered_at
        FROM ${FACT_MEMORY_OUTBOX_TABLE}
        WHERE event_id = ?
      `).get(fact.eventId) },
      { attempts: 1, delivered_at: null },
    );

    const retried = await flushFactMemoryOutbox(db, { limit: 10 });
    assert.equal(retried.attempted, 1);
    assert.equal(retried.delivered, 1);
    assert.equal(retried.failed, 0);
    assert.equal(retried.remaining, 0);
    assert.equal(captureCalls, 2);
    assert.deepEqual(captured.map((payload) => payload.eventId), [fact.eventId]);

    assert.deepEqual(enqueueFactMemoryEvent(db, fact.payload), {
      eventId: fact.eventId,
      inserted: false,
      queued: false,
      delivered: true,
    });
    const exactRetry = await flushFactMemoryOutbox(db, { limit: 10 });
    assert.equal(exactRetry.attempted, 0);
    assert.equal(captureCalls, 2);
    assert.throws(
      () => enqueueFactMemoryEvent(db, { ...fact.payload, content: 'changed payload' }),
      /fact memory outbox event id collision/u,
    );
  } finally {
    setMemoryContractAdapterForTests(null);
    db.close();
  }
});

test('bounded reconciliation backfills stable legacy occurrence and conflict events exactly once', async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'llmwiki-fact-reconcile-conflict-'));
  const dbPath = path.join(tempDir, 'memory.sqlite3');
  const memoryContract = require('../scripts/memory_contract.js');
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  setMemoryContractAdapterForTests({
    captureEvent(payload) {
      return memoryContract.captureEvent(payload, { dbPath });
    },
  });

  try {
    const red = insert(db);
    const originalRedPayload = buildFactMemoryEvent(red.row, red.supersededEventIds);
    assert.equal((await emitFactMemoryEventBestEffort(originalRedPayload)).emitted, true);
    const blue = insert(db, {
      value: 'blue',
      source_ref: 'note:2',
      said_at: '2026-02-01T10:00:00Z',
      nowISO: '2026-02-01T11:00:00Z',
    });
    assert.equal(markFactConflict(db, blue.eventId, '2026-03-01T10:00:00Z'), true);

    const first = reconcileFactMemoryOutbox(db, { limit: 1 });
    assert.deepEqual(first, { scanned: 1, enqueued: 1, remaining: 1 });
    const reconciledRed = JSON.parse(db.prepare(`
      SELECT payload_json
      FROM ${FACT_MEMORY_OUTBOX_TABLE}
      WHERE event_id = ?
    `).get(red.eventId).payload_json);
    assert.deepEqual(reconciledRed, originalRedPayload);
    const firstFlush = await flushFactMemoryOutbox(db, { limit: 1 });
    assert.equal(firstFlush.delivered, 1);
    assert.equal(firstFlush.results[0].memory.result.inserted, false);

    const second = reconcileFactMemoryOutbox(db, { limit: 1 });
    assert.deepEqual(second, { scanned: 1, enqueued: 2, remaining: 0 });
    const rows = db.prepare(`
      SELECT event_id, lifecycle_kind, payload_json
      FROM ${FACT_MEMORY_OUTBOX_TABLE}
      ORDER BY id
    `).all();
    assert.equal(rows.length, 3);
    assert.equal(new Set(rows.map((row) => row.event_id)).size, 3);
    const blueOccurrence = JSON.parse(
      rows.find((row) => row.event_id === blue.eventId).payload_json,
    );
    assert.equal(blueOccurrence.status, 'current');
    assert.deepEqual(blueOccurrence.metadata.supersedes, [red.eventId]);
    const conflict = JSON.parse(
      rows.find((row) => row.lifecycle_kind === 'conflict').payload_json,
    );
    assert.equal(conflict.metadata.factId, blue.eventId);
    assert.deepEqual(conflict.metadata.cancels_supersessions, [{
      superseded_event_id: red.eventId,
      superseding_event_id: blue.eventId,
    }]);
    assert.equal((await flushFactMemoryOutbox(db, { limit: 10 })).delivered, 2);
    assert.deepEqual(reconcileFactMemoryOutbox(db, { limit: 10 }), {
      scanned: 0, enqueued: 0, remaining: 0,
    });
    assert.deepEqual(
      memoryContract.listPendingEvents({}, { dbPath }).map((event) => event.id),
      [red.eventId],
    );
    assert.deepEqual(
      memoryContract.listPendingEvents({ includeHistory: true }, { dbPath })
        .map((event) => event.id),
      [red.eventId, blue.eventId, conflict.eventId],
    );
  } finally {
    setMemoryContractAdapterForTests(null);
    db.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('legacy retraction reconciliation preserves the supersession edge and terminal history', async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'llmwiki-fact-reconcile-retraction-'));
  const dbPath = path.join(tempDir, 'memory.sqlite3');
  const memoryContract = require('../scripts/memory_contract.js');
  const db = createLegacyFactsDb();
  ensureFactLineageSchema(db);
  setMemoryContractAdapterForTests({
    captureEvent(payload) {
      return memoryContract.captureEvent(payload, { dbPath });
    },
  });

  try {
    const red = insert(db);
    const blue = insert(db, {
      value: 'blue',
      source_ref: 'note:2',
      said_at: '2026-02-01T10:00:00Z',
      nowISO: '2026-02-01T11:00:00Z',
    });
    assert.equal(retractFact(db, blue.eventId, '2026-03-01T10:00:00Z'), true);
    assert.deepEqual(reconcileFactMemoryOutbox(db, { limit: 10 }), {
      scanned: 2, enqueued: 3, remaining: 0,
    });
    const blueOccurrence = JSON.parse(db.prepare(`
      SELECT payload_json
      FROM ${FACT_MEMORY_OUTBOX_TABLE}
      WHERE event_id = ?
    `).get(blue.eventId).payload_json);
    assert.deepEqual(blueOccurrence.metadata.supersedes, [red.eventId]);
    const retraction = JSON.parse(db.prepare(`
      SELECT payload_json
      FROM ${FACT_MEMORY_OUTBOX_TABLE}
      WHERE lifecycle_kind = 'retracted'
    `).get().payload_json);
    assert.equal(retraction.metadata.factId, blue.eventId);
    assert.equal(retraction.metadata.cancels_supersessions, undefined);
    assert.equal((await flushFactMemoryOutbox(db, { limit: 10 })).delivered, 3);
    assert.deepEqual(memoryContract.listPendingEvents({}, { dbPath }), []);
    assert.deepEqual(
      memoryContract.listPendingEvents({ includeHistory: true }, { dbPath })
        .map((event) => event.id),
      [red.eventId, blue.eventId, retraction.eventId],
    );
  } finally {
    setMemoryContractAdapterForTests(null);
    db.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('retraction and conflict events remain durable across an offline bridge', async (t) => {
  const cases = [
    { status: 'retracted', transition: retractFactWithMemoryBestEffort },
    { status: 'conflict', transition: markFactConflictWithMemoryBestEffort },
  ];
  for (const testCase of cases) {
    await t.test(testCase.status, async () => {
      const db = createLegacyFactsDb();
      ensureFactLineageSchema(db);
      const red = insert(db);
      const target = testCase.status === 'conflict'
        ? insert(db, {
          value: 'blue',
          source_ref: 'note:2',
          said_at: '2026-02-01T10:00:00Z',
          nowISO: '2026-02-01T11:00:00Z',
        })
        : red;
      setMemoryContractAdapterForTests({ captureEvent() { throw new Error('offline'); } });

      try {
        const terminal = await testCase.transition(
          db,
          target.eventId,
          '2026-03-01T10:00:00Z',
          { reason: 'verified terminal state' },
        );
        assert.equal(terminal.memory.emitted, false);
        assert.equal(terminal.memory.reason, 'bridge-error');
        assert.equal(terminal.payload.metadata.fact_status, testCase.status);
        assert.equal(
          db.prepare(`
            SELECT COUNT(*) AS count
            FROM ${FACT_MEMORY_OUTBOX_TABLE}
            WHERE delivered_at IS NULL
          `).get().count,
          1,
        );
        if (testCase.status === 'conflict') {
          assert.deepEqual(terminal.payload.metadata.cancels_supersessions, [{
            superseded_event_id: red.eventId,
            superseding_event_id: target.eventId,
          }]);
        }

        const captured = [];
        setMemoryContractAdapterForTests({
          captureEvent(payload) {
            captured.push(payload);
            return { inserted: true };
          },
        });
        const retried = await flushFactMemoryOutbox(db, { limit: 10 });
        assert.equal(retried.delivered, 1);
        assert.deepEqual(captured, [terminal.payload]);

        const exactRetry = await testCase.transition(
          db,
          target.eventId,
          '2026-03-01T10:00:00Z',
          { reason: 'verified terminal state' },
        );
        assert.deepEqual(exactRetry.payload, terminal.payload);
        assert.equal(exactRetry.memory.emitted, true);
        assert.equal(exactRetry.memory.reason, 'already-delivered');
        assert.equal(captured.length, 1);
      } finally {
        setMemoryContractAdapterForTests(null);
        db.close();
      }
    });
  }
});

test('shared conflict restores the exact local predecessor and keeps lifecycle control in history only', async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'llmwiki-fact-ledger-'));
  const dbPath = path.join(tempDir, 'memory.sqlite3');
  const memoryContract = require('../scripts/memory_contract.js');
  const db = createLegacyFactsDb();
  setMemoryContractAdapterForTests({
    captureEvent(payload) {
      return memoryContract.captureEvent(payload, { dbPath });
    },
  });

  try {
    ensureFactLineageSchema(db);
    const red = insert(db);
    const blue = insert(db, {
      value: 'blue',
      source_ref: 'note:2',
      said_at: '2026-02-01T10:00:00Z',
      nowISO: '2026-02-01T11:00:00Z',
    });
    assert.equal(
      (await emitFactMemoryEventBestEffort(buildFactMemoryEvent(red.row))).emitted,
      true,
    );
    assert.equal(
      (await emitFactMemoryEventBestEffort(
        buildFactMemoryEvent(blue.row, blue.supersededEventIds),
      )).emitted,
      true,
    );

    const conflict = await markFactConflictWithMemoryBestEffort(
      db,
      blue.eventId,
      '2026-03-01T10:00:00Z',
      { reason: 'unverified' },
    );

    assert.equal(conflict.memory.emitted, true);
    assert.equal(conflict.payload.eventType, 'fact_conflict');
    assert.equal(conflict.payload.metadata.factId, blue.eventId);
    assert.deepEqual(conflict.payload.metadata.supersedes, [blue.eventId]);
    assert.equal(conflict.payload.metadata.lifecycle_control, true);
    assert.deepEqual(conflict.cancelsSupersessions, [{
      superseded_event_id: red.eventId,
      superseding_event_id: blue.eventId,
    }]);
    assert.deepEqual(
      conflict.payload.metadata.cancels_supersessions,
      conflict.cancelsSupersessions,
    );
    assert.deepEqual(buildFactStatusMemoryEvent(conflict.row, {
      reason: 'unverified',
      cancelsSupersessions: conflict.cancelsSupersessions,
    }), conflict.payload);
    assert.deepEqual(
      filterFactsByTemporalIntent(loadFactRowsForEntities(db, ['entity:alice']))
        .map((row) => row.event_id),
      [red.eventId],
    );
    assert.deepEqual(
      memoryContract.listPendingEvents({}, { dbPath }).map((event) => event.id),
      [red.eventId],
    );
    assert.deepEqual(memoryContract.lexicalSearchEvents('blue', {}, { dbPath }), []);
    assert.deepEqual(
      memoryContract.listPendingEvents({ includeHistory: true }, { dbPath })
        .map((event) => event.id),
      [red.eventId, blue.eventId, conflict.payload.eventId],
    );

    const retry = await markFactConflictWithMemoryBestEffort(
      db,
      blue.eventId,
      '2026-03-01T10:00:00Z',
      { reason: 'unverified' },
    );
    assert.deepEqual(retry.payload, conflict.payload);
    assert.equal(retry.memory.emitted, true);
    assert.equal(retry.memory.result.inserted, false);

    await assert.rejects(
      markFactConflictWithMemoryBestEffort(
        db,
        blue.eventId,
        '2026-03-01T10:00:00Z',
        { reason: 'different reason' },
      ),
      /fact memory outbox event id collision/u,
    );

    assert.equal(
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM ${FACT_MEMORY_OUTBOX_TABLE}
        WHERE delivered_at IS NOT NULL
      `).get().count,
      1,
    );

    const sharedDb = memoryContract.openMemoryStore({ dbPath });
    try {
      assert.equal(sharedDb.prepare('SELECT COUNT(*) AS count FROM memory_events').get().count, 3);
      assert.equal(
        sharedDb.prepare('SELECT COUNT(*) AS count FROM memory_event_supersession_cancellations').get().count,
        1,
      );
    } finally {
      sharedDb.close();
    }
  } finally {
    setMemoryContractAdapterForTests(null);
    db.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('shared retraction does not restore the superseded predecessor', async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'llmwiki-fact-retraction-'));
  const dbPath = path.join(tempDir, 'memory.sqlite3');
  const memoryContract = require('../scripts/memory_contract.js');
  const db = createLegacyFactsDb();
  setMemoryContractAdapterForTests({
    captureEvent(payload) {
      return memoryContract.captureEvent(payload, { dbPath });
    },
  });

  try {
    ensureFactLineageSchema(db);
    const red = insert(db);
    const blue = insert(db, {
      value: 'blue',
      source_ref: 'note:2',
      said_at: '2026-02-01T10:00:00Z',
      nowISO: '2026-02-01T11:00:00Z',
    });
    await emitFactMemoryEventBestEffort(buildFactMemoryEvent(red.row));
    await emitFactMemoryEventBestEffort(buildFactMemoryEvent(blue.row, blue.supersededEventIds));

    const retraction = await retractFactWithMemoryBestEffort(
      db,
      blue.eventId,
      '2026-03-01T10:00:00Z',
      { reason: 'withdrawn' },
    );
    assert.equal(retraction.memory.emitted, true);
    assert.equal(retraction.payload.eventType, 'fact_retraction');
    assert.equal(retraction.payload.metadata.lifecycle_control, true);
    assert.equal(retraction.payload.metadata.cancels_supersessions, undefined);
    assert.equal(
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM ${FACT_MEMORY_OUTBOX_TABLE}
        WHERE delivered_at IS NOT NULL
      `).get().count,
      1,
    );
    assert.deepEqual(
      filterFactsByTemporalIntent(loadFactRowsForEntities(db, ['entity:alice'])),
      [],
    );
    assert.deepEqual(memoryContract.listPendingEvents({}, { dbPath }), []);
    assert.deepEqual(
      memoryContract.listPendingEvents({ includeHistory: true }, { dbPath })
        .map((event) => event.id),
      [red.eventId, blue.eventId, retraction.payload.eventId],
    );
    const sharedDb = memoryContract.openMemoryStore({ dbPath });
    try {
      assert.equal(
        sharedDb.prepare('SELECT COUNT(*) AS count FROM memory_event_supersession_cancellations').get().count,
        0,
      );
    } finally {
      sharedDb.close();
    }
  } finally {
    setMemoryContractAdapterForTests(null);
    db.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
