import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const memory = require('../scripts/memory_contract.js');

test("Node and Python share the exact event and embedding contract", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mempalace-contract-"));
  const dbPath = path.join(tmp, "memory.sqlite3");
  const eventStorePath = path.join(root, "python/event_store.py");
  const modelDigest = "c".repeat(64);
  const hmacKeyPath = path.join(tmp, "trace-hmac.key");
  const hmacKeyHex = "f".repeat(64);
  const timestamp = "2026-07-22T12:00:00.000Z";
  const nodeContent = "Кобальтовая обсерватория 🔭 uses OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456 and an indexed brass key.";
  const traceQuery = "Где кобальтовая обсерватория? 🔭";
  fs.writeFileSync(hmacKeyPath, `${hmacKeyHex}\n`, { mode: 0o600 });
  const nodeEvent = memory.captureMessage(
    {
      source: "codex",
      producer: "contract-test",
      sessionId: "node-session",
      messageId: "node-message",
      role: "assistant",
      content: nodeContent,
      createdAt: timestamp,
      capturedAt: timestamp,
    },
    { dbPath },
  ).event;
  memory.upsertEventEmbedding(
    nodeEvent.id,
    { model: "cross-runtime", digest: modelDigest, dimensions: 3, vector: [1, 0, 0] },
    { dbPath },
  );
  const previousHmacKey = process.env.MEMORY_TRACE_HMAC_KEY_PATH;
  process.env.MEMORY_TRACE_HMAC_KEY_PATH = hmacKeyPath;
  let nodeTrace;
  try {
    nodeTrace = memory.recordRetrievalTrace({
      traceId: "node-cross-runtime-hmac",
      query: traceQuery,
      consumer: "contract-test",
    }, { dbPath });
  } finally {
    if (previousHmacKey === undefined) delete process.env.MEMORY_TRACE_HMAC_KEY_PATH;
    else process.env.MEMORY_TRACE_HMAC_KEY_PATH = previousHmacKey;
  }

  const python = spawnSync(
    "python3",
    [
      "-c",
      [
        "import importlib.util, json, sys",
        "spec = importlib.util.spec_from_file_location('contract_event_store', sys.argv[1])",
        "module = importlib.util.module_from_spec(spec)",
        "spec.loader.exec_module(module)",
        "store = module.MemoryEventStore(sys.argv[2])",
        "digest = sys.argv[3]",
        "node_id = sys.argv[4]",
        "expected_schema = int(sys.argv[5])",
        "node_content = sys.argv[6]",
        "trace_query = sys.argv[7]",
        "timestamp = sys.argv[8]",
        "assert module.SCHEMA_VERSION == expected_schema",
        "node_hits = store.lexical_events('кобальтовая обсерватория')",
        "assert [item['id'] for item in node_hits] == [node_id]",
        "node_semantic = store.semantic_events([1, 0, 0], model='cross-runtime', digest=digest, dimensions=3)",
        "assert node_semantic[0]['id'] == node_id",
        "assert node_semantic[0]['embedding']['model_digest'] == digest",
        "same = store.capture_event({'source':'codex','producer':'contract-test','session_id':'node-session','message_id':'node-message','role':'assistant','content':node_content,'created_at':timestamp,'captured_at':timestamp})",
        "assert same['inserted'] is False and same['event']['id'] == node_id",
        "assert 'sk-abcdefghijklmnopqrstuvwxyz123456' not in same['event']['content']",
        "created = store.capture_event({'source':'llm-wiki','producer':'contract-test','session_id':'python-session','message_id':'python-message','role':'system','content':'The amber archive uses a numbered slate ledger.','created_at':'2026-07-22T12:01:00.000Z'})",
        "stored = store.upsert_event_embedding(created['event']['id'], model='cross-runtime', model_digest=digest, dimensions=3, vector=[0, 1, 0])",
        "assert stored['model_digest'] == digest and len(stored['vector_sha256']) == 64",
        "python_trace = store.record_retrieval_trace({'trace_id':'python-cross-runtime-hmac','query':trace_query,'consumer':'contract-test'})",
        "with store.connect() as connection:",
        "    columns = [row[1] for row in connection.execute('PRAGMA table_info(memory_event_embeddings)')]",
        "    pk = [row[1] for row in connection.execute('PRAGMA table_info(memory_event_embeddings)') if row[5]]",
        "print(json.dumps({'python_event_id': created['event']['id'], 'node_event_id': same['event']['id'], 'node_content_sha256': same['event']['content_sha256'], 'query_sha256': python_trace['query_sha256'], 'schema': module.SCHEMA_VERSION, 'columns': columns, 'pk': pk, 'stats': store.stats()}))",
      ].join("\n"),
      eventStorePath,
      dbPath,
      modelDigest,
      nodeEvent.id,
      String(memory.SCHEMA_VERSION),
      nodeContent,
      traceQuery,
      timestamp,
    ],
    { cwd: root, encoding: "utf8", env: { ...process.env, MEMORY_TRACE_HMAC_KEY_PATH: hmacKeyPath } },
  );
  assert.equal(python.status, 0, python.stderr);
  const result = JSON.parse(python.stdout.trim());
  assert.equal(result.schema, memory.SCHEMA_VERSION);
  assert.equal(result.node_event_id, nodeEvent.id);
  assert.equal(result.node_content_sha256, nodeEvent.contentSha256);
  assert.equal(result.query_sha256, nodeTrace.querySha256);
  assert.equal(
    result.query_sha256,
    crypto.createHmac("sha256", Buffer.from(hmacKeyHex, "hex")).update(traceQuery).digest("hex"),
  );
  assert.notEqual(result.query_sha256, crypto.createHash("sha256").update(traceQuery).digest("hex"));
  if (process.platform !== "win32") assert.equal(fs.statSync(hmacKeyPath).mode & 0o777, 0o600);
  assert.deepEqual(result.pk, ["event_id", "model", "model_digest"]);
  assert.deepEqual(
    result.columns,
    ["event_id", "model", "model_digest", "dimensions", "vector_sha256", "vector_json", "vector_blob", "projected_at", "metadata_json"],
  );
  assert.equal(result.stats.events, 2);
  assert.equal(result.stats.embeddings, 2);

  const pythonHits = memory.lexicalSearchEvents("amber archive ledger", {}, { dbPath });
  assert.deepEqual(pythonHits.map((event) => event.id), [result.python_event_id]);
  const semantic = memory.semanticSearchEvents(
    [0.1, 0.9, 0],
    { model: "cross-runtime", digest: modelDigest, dimensions: 3 },
    { dbPath },
  );
  assert.deepEqual(semantic.map((event) => event.id), [result.python_event_id, nodeEvent.id]);
  assert.equal(
    memory.captureMessage(
      {
        source: "llm-wiki",
        producer: "contract-test",
        sessionId: "python-session",
        messageId: "python-message",
        role: "system",
        content: "The amber archive uses a numbered slate ledger.",
        createdAt: "2026-07-22T12:01:00.000Z",
      },
      { dbPath },
    ).event.id,
    result.python_event_id,
  );
});


test("Node and Python apply the same supersession history boundary", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mempalace-supersession-"));
  const dbPath = path.join(tmp, "memory.sqlite3");
  const eventStorePath = path.join(root, "python/event_store.py");
  const first = memory.captureEvent({
    id: "cross-fact-a", eventType: "fact", source: "llm-wiki", sessionId: "cross-facts",
    messageId: "a", role: "system", content: "The shared status is amber.",
  }, { dbPath }).event;
  const second = memory.captureEvent({
    id: "cross-fact-b", eventType: "fact", source: "llm-wiki", sessionId: "cross-facts",
    messageId: "b", role: "system", content: "The shared status is blue.",
    metadata: { supersedes: first.id },
  }, { dbPath }).event;
  const python = spawnSync("python3", [
    "-c",
    [
      "import importlib.util, json, sys",
      "spec=importlib.util.spec_from_file_location('event_store', sys.argv[1])",
      "module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)",
      "store=module.MemoryEventStore(sys.argv[2])",
      "assert [e['id'] for e in store.pending_events()] == ['cross-fact-b']",
      "assert [e['id'] for e in store.pending_events(include_superseded=True)] == ['cross-fact-a','cross-fact-b']",
      "created=store.capture_event({'id':'cross-fact-c','event_type':'fact','source':'llm-wiki','session_id':'cross-facts','message_id':'c','role':'system','content':'The shared status is amber.','metadata':{'supersedes':'cross-fact-b'}})",
      "print(json.dumps(created['event']))",
    ].join("\n"),
    eventStorePath,
    dbPath,
  ], { cwd: root, encoding: "utf8" });
  assert.equal(python.status, 0, python.stderr);
  const latest = JSON.parse(python.stdout);
  assert.equal(latest.id, "cross-fact-c");
  assert.deepEqual(memory.listPendingEvents({}, { dbPath }).map((event) => event.id), [latest.id]);
  assert.deepEqual(
    memory.listPendingEvents({ includeSuperseded: true }, { dbPath }).map((event) => event.id),
    [first.id, second.id, latest.id],
  );
});


test("Node and Python share monotonic fact conflict, retraction, and cancellation semantics", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mempalace-cancellation-"));
  const dbPath = path.join(tmp, "memory.sqlite3");
  const eventStorePath = path.join(root, "python/event_store.py");
  const first = memory.captureEvent({
    id: "lineage-fact-a", eventType: "fact", source: "llm-wiki", sessionId: "lineage-facts",
    messageId: "a", role: "system", content: "The lineage color is amber.",
    createdAt: "2026-07-22T12:00:00.000Z", capturedAt: "2026-07-22T12:00:00.000Z",
  }, { dbPath }).event;
  const second = memory.captureEvent({
    id: "lineage-fact-b", eventType: "fact", source: "llm-wiki", sessionId: "lineage-facts",
    messageId: "b", role: "system", content: "The lineage color is blue.",
    createdAt: "2026-07-22T12:01:00.000Z", capturedAt: "2026-07-22T12:01:00.000Z",
    metadata: { supersedes: first.id },
  }, { dbPath }).event;
  const conflictPayload = {
    id: "lineage-conflict-b", event_type: "fact_conflict", source: "llm-wiki",
    session_id: "lineage-facts", message_id: "conflict-b", role: "system",
    content: "The blue lineage fact is conflicted.",
    created_at: "2026-07-22T12:02:00.000Z", captured_at: "2026-07-22T12:02:00.000Z",
    metadata: {
      lifecycle_control: 1,
      supersedes: [second.id],
      cancels_supersessions: [
        { superseded_event_id: first.id, superseding_event_id: second.id },
        { supersedingEventId: second.id, supersededEventId: first.id },
      ],
    },
  };
  const python = spawnSync("python3", [
    "-c",
    [
      "import importlib.util, json, sqlite3, sys",
      "spec=importlib.util.spec_from_file_location('event_store', sys.argv[1])",
      "module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)",
      "store=module.MemoryEventStore(sys.argv[2])",
      "payload=json.loads(sys.argv[3])",
      "created=store.capture_event(payload)",
      "replay=dict(payload); replay['metadata']=dict(payload['metadata']); replay['metadata']['cancels_supersessions']=replay['metadata']['cancels_supersessions'][:1]",
      "replayed=store.capture_event(replay)",
      "with store.connect() as connection:",
      " connection.execute(\"CREATE TRIGGER fail_cancellation_insert BEFORE INSERT ON memory_event_supersession_cancellations WHEN NEW.cancellation_event_id='lineage-conflict-fail' BEGIN SELECT RAISE(ABORT, 'forced cancellation failure'); END\")",
      "failed=False",
      "try:",
      " store.capture_event({'id':'lineage-conflict-fail','event_type':'fact_conflict','source':'llm-wiki','session_id':'lineage-facts','message_id':'conflict-fail','role':'system','content':'forced rollback','metadata':{'lifecycle_control':1,'supersedes':['lineage-fact-b'],'cancels_supersessions':[{'superseded_event_id':'lineage-fact-a','superseding_event_id':'lineage-fact-b'}]}})",
      "except sqlite3.DatabaseError:",
      " failed=True",
      "with store.connect() as connection:",
      " rollback_counts=[connection.execute(\"SELECT COUNT(*) FROM memory_events WHERE id='lineage-conflict-fail'\").fetchone()[0], connection.execute(\"SELECT COUNT(*) FROM memory_event_supersessions WHERE superseding_event_id='lineage-conflict-fail'\").fetchone()[0], connection.execute(\"SELECT COUNT(*) FROM memory_event_supersession_cancellations WHERE cancellation_event_id='lineage-conflict-fail'\").fetchone()[0]]",
      " cancellation_count=connection.execute(\"SELECT COUNT(*) FROM memory_event_supersession_cancellations WHERE superseded_event_id='lineage-fact-a' AND superseding_event_id='lineage-fact-b'\").fetchone()[0]",
      " connection.execute('DROP TRIGGER fail_cancellation_insert')",
      "print(json.dumps({'schema':module.SCHEMA_VERSION,'created':created,'replayed':replayed,'failed':failed,'rollback_counts':rollback_counts,'cancellation_count':cancellation_count,'current':[e['id'] for e in store.pending_events()],'history':[e['id'] for e in store.pending_events(include_superseded=True)]}))",
    ].join("\n"),
    eventStorePath,
    dbPath,
    JSON.stringify(conflictPayload),
  ], { cwd: root, encoding: "utf8" });
  assert.equal(python.status, 0, python.stderr);
  const parity = JSON.parse(python.stdout);
  assert.equal(parity.schema, 5);
  assert.equal(parity.created.inserted, true);
  assert.equal(parity.replayed.inserted, false);
  assert.deepEqual(parity.created.event.metadata.cancels_supersessions, [
    { superseded_event_id: first.id, superseding_event_id: second.id },
  ]);
  assert.equal(parity.cancellation_count, 1);
  assert.equal(parity.failed, true);
  assert.deepEqual(parity.rollback_counts, [0, 0, 0]);
  assert.deepEqual(parity.current, [first.id]);
  assert.deepEqual(parity.history, [first.id, second.id, conflictPayload.id]);
  assert.deepEqual(memory.listPendingEvents({}, { dbPath }).map((event) => event.id), [first.id]);

  const replacement = memory.captureEvent({
    id: "lineage-fact-d", eventType: "fact", source: "llm-wiki", sessionId: "lineage-facts",
    messageId: "d", role: "system", content: "The lineage color is green.",
    createdAt: "2026-07-22T12:03:00.000Z", capturedAt: "2026-07-22T12:03:00.000Z",
    metadata: { supersedes: [first.id] },
  }, { dbPath }).event;
  const afterReplacement = spawnSync("python3", [
    "-c",
    "import importlib.util,json,sys; spec=importlib.util.spec_from_file_location('event_store',sys.argv[1]); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); store=module.MemoryEventStore(sys.argv[2]); print(json.dumps({'current':[e['id'] for e in store.pending_events()],'history':[e['id'] for e in store.pending_events(include_superseded=True)]}))",
    eventStorePath,
    dbPath,
  ], { cwd: root, encoding: "utf8" });
  assert.equal(afterReplacement.status, 0, afterReplacement.stderr);
  assert.deepEqual(JSON.parse(afterReplacement.stdout).current, [replacement.id]);

  const retraction = memory.captureEvent({
    id: "lineage-retraction-d", eventType: "fact_retraction", source: "llm-wiki",
    sessionId: "lineage-facts", messageId: "retract-d", role: "system",
    content: "The green lineage fact is retracted.",
    createdAt: "2026-07-22T12:04:00.000Z", capturedAt: "2026-07-22T12:04:00.000Z",
    metadata: { lifecycle_control: 1, supersedes: [replacement.id] },
  }, { dbPath }).event;
  assert.deepEqual(memory.listPendingEvents({}, { dbPath }).map((event) => event.id), []);
  assert.deepEqual(
    memory.listPendingEvents({ includeSuperseded: true }, { dbPath }).map((event) => event.id),
    [first.id, second.id, conflictPayload.id, replacement.id, retraction.id],
  );
});
