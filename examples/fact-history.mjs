import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createRequire } from 'node:module';
import {
  insertFactWithMemoryOutbox, loadFactRowsForEntities,
  filterFactsByTemporalIntent, markFactConflictWithMemoryBestEffort,
  flushFactMemoryOutbox,
} from '../wiki/fact-lineage.mjs';

const require = createRequire(import.meta.url);
const memory = require('../scripts/memory_contract.js');
// Both databases are disposable. The demo never reads your working memory.
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'memory-ledger-demo-'));
const sharedDbPath = path.join(directory, 'events.sqlite3');
process.env.MEMORY_EVENTS_DB_PATH = sharedDbPath;
const wiki = new DatabaseSync(path.join(directory, 'facts.sqlite3'));
wiki.exec(`CREATE TABLE sidecar_entity_facts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_id TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '', source_ref TEXT NOT NULL DEFAULT '',
  said_at TEXT NOT NULL DEFAULT '', said_by TEXT NOT NULL DEFAULT 'owner',
  confidence REAL NOT NULL DEFAULT 1.0, created_at TEXT NOT NULL,
  UNIQUE(entity_id, kind, value)
)`);
function add(value, date, note) {
  return insertFactWithMemoryOutbox(wiki, {
    entity_id: 'entity:demo', kind: 'preference', value,
    evidence: `Synthetic choice: ${value}.`, source_ref: note,
    said_at: `${date}T10:00:00Z`, said_by: 'owner', confidence: 1,
    lineage_key: 'preference.color',
  }, `${date}T11:00:00Z`);
}
const red = add('red', '2026-01-01', 'example:1');
const blue = add('blue', '2026-02-01', 'example:2');
const redAgain = add('red', '2026-03-01', 'example:3');
assert.notEqual(red.eventId, redAgain.eventId);
function values(intent) {
  return filterFactsByTemporalIntent(loadFactRowsForEntities(wiki, ['entity:demo']), intent)
    .map(f => f.value);
}
assert.deepEqual(values(), ['red']);
assert.deepEqual(values({ mode: 'as_of', asOf: '2026-02-15T23:59:59Z' }), ['blue']);
console.log('Current:', values().join(', '));
console.log('On 2026-02-15:', values({ mode: 'as_of', asOf: '2026-02-15T23:59:59Z' }).join(', '));
console.log('History:');
console.table(loadFactRowsForEntities(wiki, ['entity:demo'])
  .sort((a,b) => a.valid_from.localeCompare(b.valid_from))
  .map(({value,status,source_ref,valid_from,valid_to}) => ({value,status,source_ref,valid_from,valid_to})));
await flushFactMemoryOutbox(wiki);
await markFactConflictWithMemoryBestEffort(wiki, redAgain.eventId, '2026-03-02T10:00:00Z');
await flushFactMemoryOutbox(wiki);
assert.deepEqual(values(), ['blue']);
console.log('After rejecting the latest occurrence:', values().join(', '));
console.log('Shared current events:', memory.listPendingEvents({}, { dbPath: sharedDbPath }).length);
console.log('Temporary databases:', directory);
wiki.close();
