import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const require = createRequire(import.meta.url);
const memory = require('../scripts/memory_contract.js');
const cli = fileURLToPath(new URL('../tools/journal.py', import.meta.url));
const python = process.env.PYTHON_COMMAND || (process.platform === 'win32' ? 'python' : 'python3');
const run = (...args) => spawnSync(python, [cli, ...args], { encoding: 'utf8' });

test('online backup restores committed WAL events, identifiers and raw export without touching the source', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-backup-'));
  fs.chmodSync(dir, 0o700);
  const dbPath = path.join(dir, 'source.sqlite3');
  const db = memory.openMemoryStore({ dbPath });
  t.after(() => { db.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  for (const [id, timestamp] of [['early', '2025-01-01T00:00:00.000Z'], ['later', '2025-02-01T00:00:00.000Z']]) {
    memory.captureEvent({ eventId: id, eventType: 'note', producer: 'synthetic-test', source: 'test',
      sessionId: 'test', messageId: id, role: 'user', content: `Synthetic ${id}`, createdAt: timestamp }, { dbPath });
  }
  const original = db.prepare('SELECT * FROM memory_events ORDER BY id').all();
  const backup = path.join(dir, 'backup.sqlite3');
  assert.equal(run('backup', '--db', dbPath, '--to', backup).status, 0);
  const restored = path.join(dir, 'restored.sqlite3');
  assert.equal(run('restore', '--db', backup, '--to', restored).status, 0);
  const restoredDb = memory.openMemoryStore({ dbPath: restored, readOnly: true });
  try { assert.deepEqual(restoredDb.prepare('SELECT * FROM memory_events ORDER BY id').all(), original); }
  finally { restoredDb.close(); }
  const output = path.join(dir, 'events.jsonl');
  assert.equal(run('export', '--db', dbPath, '--to', output).status, 0);
  assert.equal(fs.readFileSync(output, 'utf8').trim().split('\n').length, 2);
  assert.deepEqual(db.prepare('SELECT * FROM memory_events ORDER BY id').all(), original);
  if (process.platform !== 'win32') assert.equal(fs.statSync(backup).mode & 0o777, 0o600);
});

test('backup and export refuse existing paths, relative paths and invalid cutoffs', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-backup-refusal-'));
  fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const source = path.join(dir, 'source.sqlite3');
  memory.openMemoryStore({ dbPath: source }).close();
  const occupied = path.join(dir, 'occupied');
  fs.writeFileSync(occupied, 'preserve');
  assert.notEqual(run('backup', '--db', source, '--to', occupied).status, 0);
  assert.equal(fs.readFileSync(occupied, 'utf8'), 'preserve');
  assert.notEqual(run('backup', '--db', 'relative.sqlite3', '--to', path.join(dir, 'bad')).status, 0);
  assert.notEqual(run('export', '--db', source, '--to', path.join(dir, 'bad'), '--before', '2025-01-01').status, 0);
  assert.equal(fs.existsSync(path.join(dir, 'bad')), false);
});
