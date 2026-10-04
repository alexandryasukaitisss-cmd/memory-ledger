import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const memory = require(path.join(root, "scripts/memory_contract.js"));

function tempStore() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "memory-contract-"));
  return { dir, dbPath: path.join(dir, "memory.sqlite3") };
}

test("binary embedding cache preserves semantic results and backfills legacy rows", () => {
  const { dbPath } = tempStore();
  const modelDigest = crypto.createHash("sha256").update("binary-cache").digest("hex");
  const first = memory.captureMessage({
    source: "codex", sessionId: "first", messageId: "first", role: "assistant",
    content: "First precise memory.",
  }, { dbPath }).event;
  const second = memory.captureMessage({
    source: "codex", sessionId: "second", messageId: "second", role: "assistant",
    content: "Second precise memory.",
  }, { dbPath }).event;
  for (const [event, vector] of [[first, [1, 0, 0]], [second, [0, 1, 0]]]) {
    memory.upsertEventEmbedding(event.id, { model: "cache", modelDigest, vector }, { dbPath });
  }

  const db = memory.openMemoryStore({ dbPath });
  try {
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM memory_event_embeddings WHERE length(vector_blob) = dimensions * 8").get().count, 2);
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM memory_event_embedding_vectors WHERE length(vector_blob) = dimensions * 8").get().count, 2);
    db.prepare("UPDATE memory_event_embeddings SET vector_blob = NULL").run();
    db.prepare("DELETE FROM memory_event_embedding_vectors").run();
  } finally {
    db.close();
  }
  const legacy = memory.semanticSearchEvents([0.9, 0.1, 0], {
    model: "cache", modelDigest, dimensions: 3,
  }, { dbPath }).map((event) => [event.id, event.semanticSimilarity]);
  assert.deepEqual(memory.backfillEventEmbeddingVectorBlobs({ dbPath, batchSize: 1 }), { updated: 2 });
  const cached = memory.semanticSearchEvents([0.9, 0.1, 0], {
    model: "cache", modelDigest, dimensions: 3,
  }, { dbPath }).map((event) => [event.id, event.semanticSimilarity]);
  assert.deepEqual(cached, legacy);
});

test("memory event capture is sanitized, deterministic, append-only, and WAL-backed", () => {
  const { dbPath } = tempStore();
  const payload = {
    source: "codex",
    producer: "codex-desktop",
    sourceRef: "/tmp/session.jsonl",
    sessionId: "session-a",
    turnId: "turn-7",
    messages: [
      {
        messageId: "message-user",
        role: "user",
        content: "Remember deployment token OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456",
      },
      {
        messageId: "message-assistant",
        role: "assistant",
        content: "The blue-orchid migration is complete.",
      },
    ],
  };

  const first = memory.captureTurn(payload, { dbPath });
  const second = memory.captureTurn(payload, { dbPath });

  assert.equal(first.insertedCount, 2);
  assert.equal(first.existingCount, 0);
  assert.equal(second.insertedCount, 0);
  assert.equal(second.existingCount, 2);
  assert.deepEqual(
    first.events.map((event) => event.id),
    second.events.map((event) => event.id),
  );
  assert.equal(first.events[0].content.includes("sk-abcdefghijklmnopqrstuvwxyz123456"), false);
  assert.match(first.events[0].content, /\[REDACTED:/);

  const db = memory.openMemoryStore({ dbPath });
  try {
    assert.equal(db.prepare("PRAGMA journal_mode").get().journal_mode, "wal");
    assert.equal(db.prepare("PRAGMA busy_timeout").get().timeout, memory.DEFAULT_BUSY_TIMEOUT_MS);
    assert.equal(db.prepare("PRAGMA user_version").get().user_version, memory.SCHEMA_VERSION);
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM memory_events").get().count, 2);
    assert.throws(
      () => db.prepare("UPDATE memory_events SET content = 'mutated' WHERE id = ?").run(first.events[0].id),
      /append-only/,
    );
  } finally {
    db.close();
  }

  const hits = memory.lexicalSearchEvents("blue orchid", {}, { dbPath });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].id, first.events[1].id);
});

test("event identity collisions reject immutable payload changes", () => {
  const { dbPath } = tempStore();
  const payload = {
    eventId: "strict.identity.1",
    eventType: "fact",
    source: "llm-wiki",
    producer: "facts-extract",
    sessionId: "identity-session",
    messageId: "identity-message",
    role: "system",
    content: "The immutable fact keeps the same text.",
    createdAt: "2026-07-22T12:00:00.000Z",
    capturedAt: "2026-07-22T12:00:01.000Z",
    metadata: { lineage: "first" },
  };
  memory.captureEvent(payload, { dbPath });
  assert.equal(memory.captureEvent(payload, { dbPath }).inserted, false);
  assert.throws(
    () => memory.captureEvent({ ...payload, metadata: { lineage: "changed" } }, { dbPath }),
    /metadata_json/,
  );
  assert.throws(
    () => memory.captureEvent({ ...payload, source: "codex" }, { dbPath }),
    /source/,
  );
  assert.equal(memory.getStoreStats({ dbPath }).events, 1);
});

test("projection markers are idempotent and leave the event row unchanged", () => {
  const { dbPath } = tempStore();
  const captured = memory.captureMessage(
    {
      source: "llm-wiki",
      producer: "facts-extract",
      sourceRef: "telegram:chat-44:message-9",
      sessionId: "chat-44",
      messageId: "fact-9",
      eventId: "llmwiki.fact.9",
      eventType: "fact",
      role: "system",
      content: "Aina preferred the green phone.",
      status: "accepted",
      provenance: { chatId: "44", noteId: "9" },
    },
    { dbPath },
  );

  assert.equal(captured.inserted, true);
  assert.equal(captured.event.id, "llmwiki.fact.9");
  assert.equal(captured.event.status, "accepted");
  assert.equal(captured.event.privacyScope, "local");
  assert.deepEqual(captured.event.provenance, { chatId: "44", noteId: "9" });
  assert.equal(captured.event.metadata.status, "accepted");
  assert.deepEqual(captured.event.metadata.provenance, { chatId: "44", noteId: "9" });
  assert.equal(memory.listPendingEvents({ target: "mempalace" }, { dbPath }).length, 1);

  const first = memory.markEventsProjected(
    [captured.event.id],
    { target: "mempalace", projectionRef: "/tmp/transcript.md" },
    { dbPath },
  );
  const second = memory.markEventsProjected(
    [captured.event.id],
    { target: "mempalace", projectionRef: "/tmp/transcript.md" },
    { dbPath },
  );

  assert.equal(first.insertedCount, 1);
  assert.equal(second.insertedCount, 0);
  assert.equal(memory.listPendingEvents({ target: "mempalace" }, { dbPath }).length, 0);
  assert.equal(memory.lexicalSearchEvents("green phone", {}, { dbPath })[0].projected, true);
});

test("MemPalace documents have an independent lexical FTS index", () => {
  const { dbPath } = tempStore();
  const result = memory.upsertMempalaceDocuments(
    [
      {
        id: "drawer-one",
        text: "The zephyr checksum fixed the import.",
        wing: "wing_ops",
        room: "decisions",
        sourceFile: "/tmp/source-one.md",
        metadata: { agent: "codex" },
      },
      {
        id: "drawer-two",
        text: "A different operational note.",
        wing: "wing_ops",
        room: "general",
        sourceFile: "/tmp/source-two.md",
      },
    ],
    { dbPath },
  );

  assert.equal(result.upsertedCount, 2);
  const hits = memory.lexicalSearchDocuments(
    "zephyr checksum",
    { wing: "wing_ops", room: "decisions" },
    { dbPath },
  );
  assert.equal(hits.length, 1);
  assert.equal(hits[0].id, "drawer-one");
  assert.equal(hits[0].sourceFile, "/tmp/source-one.md");
});

test("event embeddings have exact vector identity and can drive next-turn retrieval", () => {
  const { dbPath } = tempStore();
  const modelDigest = "a".repeat(64);
  const staleModelDigest = "b".repeat(64);
  const first = memory.captureMessage(
    {
      source: "llm-wiki",
      sessionId: "historic-a",
      messageId: "embedding-a",
      role: "system",
      content: "The observatory uses a brass alignment key.",
    },
    { dbPath },
  ).event;
  const second = memory.captureMessage(
    {
      source: "llm-wiki",
      sessionId: "historic-b",
      messageId: "embedding-b",
      role: "system",
      content: "The workshop uses a slate inventory board.",
    },
    { dbPath },
  ).event;

  assert.equal(memory.listEmbeddableEvents({ model: "test-vector", modelDigest, dimensions: 3 }, { dbPath }).length, 2);
  const stored = memory.upsertEventEmbedding(
    first.id,
    { model: "test-vector", digest: modelDigest, dimensions: 3, vector: [1, 0, 0] },
    { dbPath },
  );
  memory.upsertEventEmbedding(
    second.id,
    { model: "test-vector", modelDigest, dimensions: 3, vector: [0, 1, 0] },
    { dbPath },
  );
  assert.equal(stored.modelDigest, modelDigest);
  assert.match(stored.vectorSha256, /^[a-f0-9]{64}$/);
  assert.equal(memory.listEmbeddableEvents({ model: "test-vector", modelDigest, dimensions: 3 }, { dbPath }).length, 0);
  assert.equal(memory.listEmbeddableEvents({ model: "test-vector", modelDigest: staleModelDigest, dimensions: 3 }, { dbPath }).length, 2);
  assert.throws(
    () => memory.upsertEventEmbedding(first.id, { model: "test-vector", modelDigest, dimensions: 2, vector: [1, 0, 0] }, { dbPath }),
    /dimensions/,
  );
  assert.throws(
    () => memory.upsertEventEmbedding(first.id, { model: "test-vector", digest: "bad", vector: [1, 0, 0] }, { dbPath }),
    /model digest/,
  );
  assert.throws(
    () => memory.upsertEventEmbedding(first.id, { model: "test-vector", modelDigest, vector: [1, 0, 0], vectorSha256: staleModelDigest }, { dbPath }),
    /vector_sha256/,
  );

  const semantic = memory.semanticSearchEvents(
    [0.9, 0.1, 0],
    { model: "test-vector", modelDigest, dimensions: 3 },
    { dbPath },
  );
  assert.deepEqual(semantic.map((event) => event.id), [first.id, second.id]);
  assert.equal(semantic[0].embedding.modelDigest, modelDigest);
  assert.equal(
    memory.semanticSearchEvents(
      [0.9, 0.1, 0],
      { model: "test-vector", modelDigest: staleModelDigest, dimensions: 3 },
      { dbPath },
    ).length,
    0,
  );
  const pack = memory.buildNextTurnPack(
    {
      query: "token absent from lexical index",
      queryVector: [0.9, 0.1, 0],
      embeddingModel: "test-vector",
      embeddingModelDigest: modelDigest,
      consumer: "codex",
      sessionId: "current-session",
      source: "codex",
      limit: 1,
      markServed: false,
    },
    { dbPath },
  );
  assert.equal(pack.retrievalMode, "event_embedding+fts");
  assert.equal(pack.results[0].id, first.id);
  assert.deepEqual(pack.results[0].retrievalChannels, ["event_embedding"]);

  const bounded = memory.buildNextTurnPack(
    {
      query: "token absent from lexical index",
      queryVector: [0.9, 0.1, 0],
      embeddingModel: "test-vector",
      embeddingModelDigest: modelDigest,
      semanticCandidatePool: "lexical",
      semanticCandidateLimit: 20,
      consumer: "codex",
      sessionId: "current-session",
      source: "codex",
      limit: 1,
      markServed: false,
    },
    { dbPath },
  );
  assert.equal(bounded.retrievalMode, "event_fts");
  assert.deepEqual(bounded.results, []);
});

test("superseded facts are hidden by default and available only through history opt-in", () => {
  const { dbPath } = tempStore();
  const modelDigest = "9".repeat(64);
  const first = memory.captureEvent({
    id: "fact-a", eventType: "fact", source: "llm-wiki", sessionId: "facts",
    messageId: "a", role: "system", content: "Aina prefers the green phone.",
    createdAt: "2026-07-22T12:00:00.000Z",
  }, { dbPath }).event;
  const second = memory.captureEvent({
    id: "fact-b", eventType: "fact", source: "llm-wiki", sessionId: "facts",
    messageId: "b", role: "system", content: "Aina prefers the blue sapphire handset.",
    createdAt: "2026-07-22T12:01:00.000Z", metadata: { supersedes: [first.id] },
  }, { dbPath }).event;
  const latest = memory.captureEvent({
    id: "fact-c", eventType: "fact", source: "llm-wiki", sessionId: "facts",
    messageId: "c", role: "system", content: "Aina prefers the green phone.",
    createdAt: "2026-07-22T12:02:00.000Z", metadata: { supersedes: second.id },
  }, { dbPath }).event;

  assert.deepEqual(memory.listPendingEvents({}, { dbPath }).map((event) => event.id), [latest.id]);
  assert.deepEqual(
    memory.listPendingEvents({ includeSuperseded: true }, { dbPath }).map((event) => event.id),
    [first.id, second.id, latest.id],
  );
  assert.deepEqual(memory.lexicalSearchEvents("sapphire", {}, { dbPath }), []);
  assert.deepEqual(
    memory.lexicalSearchEvents("sapphire", { includeSuperseded: true }, { dbPath }).map((event) => event.id),
    [second.id],
  );
  assert.deepEqual(
    memory.listEmbeddableEvents({ model: "facts", modelDigest, dimensions: 3 }, { dbPath }).map((event) => event.id),
    [latest.id],
  );
  for (const [event, vector] of [[first, [1, 0, 0]], [second, [0, 1, 0]], [latest, [1, 0, 0]]]) {
    memory.upsertEventEmbedding(event.id, { model: "facts", modelDigest, vector }, { dbPath });
  }
  assert.deepEqual(
    memory.semanticSearchEvents([0, 1, 0], { model: "facts", modelDigest, dimensions: 3 }, { dbPath }).map((event) => event.id),
    [latest.id],
  );
  assert.deepEqual(
    memory.semanticSearchEvents(
      [0, 1, 0],
      { model: "facts", modelDigest, dimensions: 3, includeSuperseded: true },
      { dbPath },
    ).map((event) => event.id),
    [second.id, first.id, latest.id],
  );
  const db = memory.openMemoryStore({ dbPath });
  try {
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM memory_event_supersessions").get().count, 2);
    assert.throws(
      () => db.prepare("DELETE FROM memory_event_supersessions WHERE superseded_event_id = ?").run(first.id),
      /append-only/,
    );
  } finally {
    db.close();
  }
});

test("conflict cancellation restores the exact predecessor while retraction remains terminal", () => {
  const { dbPath } = tempStore();
  const modelDigest = "8".repeat(64);
  const first = memory.captureEvent({
    id: "lineage-a", eventType: "fact", source: "llm-wiki", sessionId: "facts",
    messageId: "a", role: "system", content: "Aina prefers the red handset.",
    createdAt: "2026-07-22T13:00:00.000Z",
  }, { dbPath }).event;
  const second = memory.captureEvent({
    id: "lineage-b", eventType: "fact", source: "llm-wiki", sessionId: "facts",
    messageId: "b", role: "system", content: "Aina prefers the blue sapphire handset.",
    createdAt: "2026-07-22T13:01:00.000Z", metadata: { supersedes: [first.id] },
  }, { dbPath }).event;
  const cancellation = {
    superseded_event_id: first.id,
    superseding_event_id: second.id,
  };
  const conflictPayload = {
    id: "lineage-b-conflict", eventType: "fact_conflict", source: "llm-wiki", sessionId: "facts",
    messageId: "b-conflict", role: "system", content: "Conflict: blue sapphire preference is unverified.",
    createdAt: "2026-07-22T13:02:00.000Z",
    metadata: {
      supersedes: [second.id],
      lifecycle_control: true,
      cancels_supersessions: [cancellation, cancellation],
    },
  };
  const conflict = memory.captureEvent(conflictPayload, { dbPath });
  const exactRetry = memory.captureEvent({
    ...conflictPayload,
    metadata: {
      supersedes: [second.id],
      lifecycle_control: true,
      extensions: { cancels_supersessions: [cancellation] },
    },
  }, { dbPath });

  assert.equal(conflict.inserted, true);
  assert.equal(exactRetry.inserted, false);
  assert.deepEqual(conflict.event.metadata.cancels_supersessions, [cancellation]);
  assert.equal(conflict.event.metadata.extensions, undefined);
  assert.deepEqual(memory.listPendingEvents({}, { dbPath }).map((event) => event.id), [first.id]);
  assert.deepEqual(
    memory.listPendingEvents({ includeHistory: true }, { dbPath }).map((event) => event.id),
    [first.id, second.id, conflict.event.id],
  );
  assert.deepEqual(memory.lexicalSearchEvents("red handset", {}, { dbPath }).map((event) => event.id), [first.id]);
  assert.deepEqual(memory.lexicalSearchEvents("blue sapphire", {}, { dbPath }), []);
  assert.deepEqual(
    memory.lexicalSearchEvents("blue sapphire", { includeHistory: true }, { dbPath })
      .map((event) => event.id).sort(),
    [second.id, conflict.event.id].sort(),
  );
  assert.deepEqual(
    memory.listEmbeddableEvents({ model: "facts", modelDigest, dimensions: 3 }, { dbPath })
      .map((event) => event.id),
    [first.id],
  );
  assert.equal(memory.getStoreStats({ dbPath }).pending, 1);
  assert.throws(
    () => memory.captureEvent({
      ...conflictPayload,
      metadata: {
        ...conflictPayload.metadata,
        cancels_supersessions: [
          cancellation,
          { superseded_event_id: first.id, superseding_event_id: conflict.event.id },
        ],
      },
    }, { dbPath }),
    /metadata_json/,
  );

  const db = memory.openMemoryStore({ dbPath });
  try {
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM memory_events").get().count, 3);
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM memory_event_supersessions").get().count, 2);
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM memory_event_supersession_cancellations").get().count, 1);
    assert.throws(
      () => db.prepare("UPDATE memory_event_supersession_cancellations SET recorded_at = recorded_at").run(),
      /append-only/,
    );
    assert.throws(
      () => db.prepare("DELETE FROM memory_event_supersession_cancellations").run(),
      /append-only/,
    );
  } finally {
    db.close();
  }

  const latest = memory.captureEvent({
    id: "lineage-d", eventType: "fact", source: "llm-wiki", sessionId: "facts",
    messageId: "d", role: "system", content: "Aina now prefers the green handset.",
    createdAt: "2026-07-22T13:03:00.000Z", metadata: { supersedes: [first.id] },
  }, { dbPath }).event;
  assert.deepEqual(memory.listPendingEvents({}, { dbPath }).map((event) => event.id), [latest.id]);

  const retractStore = tempStore();
  const retractFirst = memory.captureEvent({
    id: "retract-a", eventType: "fact", source: "llm-wiki", sessionId: "facts",
    messageId: "a", role: "system", content: "Aina prefers red.",
    createdAt: "2026-07-22T14:00:00.000Z",
  }, { dbPath: retractStore.dbPath }).event;
  const retractSecond = memory.captureEvent({
    id: "retract-b", eventType: "fact", source: "llm-wiki", sessionId: "facts",
    messageId: "b", role: "system", content: "Aina prefers blue.",
    createdAt: "2026-07-22T14:01:00.000Z", metadata: { supersedes: [retractFirst.id] },
  }, { dbPath: retractStore.dbPath }).event;
  const retraction = memory.captureEvent({
    id: "retract-b-terminal", eventType: "fact_retraction", source: "llm-wiki", sessionId: "facts",
    messageId: "b-terminal", role: "system", content: "Retraction: blue preference withdrawn.",
    createdAt: "2026-07-22T14:02:00.000Z",
    metadata: { supersedes: [retractSecond.id], lifecycle_control: true },
  }, { dbPath: retractStore.dbPath }).event;
  assert.deepEqual(memory.listPendingEvents({}, { dbPath: retractStore.dbPath }), []);
  assert.deepEqual(
    memory.listPendingEvents({ includeHistory: true }, { dbPath: retractStore.dbPath }).map((event) => event.id),
    [retractFirst.id, retractSecond.id, retraction.id],
  );
});

test("legacy vector checksums migrate without masquerading as the pinned model digest", () => {
  const { dbPath } = tempStore();
  const event = memory.captureMessage(
    {
      source: "migration-test",
      sessionId: "legacy-session",
      messageId: "legacy-message",
      role: "system",
      content: "Legacy embedding row retained for safe re-embedding.",
    },
    { dbPath },
  ).event;
  const legacyVectorSha256 = "d".repeat(64);
  const db = memory.openMemoryStore({ dbPath });
  try {
    db.exec(`
      DROP INDEX memory_event_embeddings_model_idx;
      DROP TABLE memory_event_embeddings;
      CREATE TABLE memory_event_embeddings (
        event_id TEXT NOT NULL REFERENCES memory_events(id),
        model TEXT NOT NULL,
        dimensions INTEGER NOT NULL CHECK(dimensions > 0),
        digest TEXT NOT NULL,
        vector_json TEXT NOT NULL,
        projected_at TEXT NOT NULL,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        PRIMARY KEY(event_id, model)
      );
      CREATE INDEX memory_event_embeddings_model_idx
        ON memory_event_embeddings(model, dimensions, projected_at);
      PRAGMA user_version = 2;
    `);
    db.prepare(`
      INSERT INTO memory_event_embeddings(
        event_id, model, dimensions, digest, vector_json, projected_at, metadata_json
      ) VALUES (?, 'legacy-model', 3, ?, '[1,0,0]', '2026-07-22T12:00:00.000Z', '{}')
    `).run(event.id, legacyVectorSha256);
  } finally {
    db.close();
  }

  const migrated = memory.openMemoryStore({ dbPath });
  try {
    const row = migrated.prepare("SELECT * FROM memory_event_embeddings WHERE event_id = ?").get(event.id);
    assert.equal(row.model_digest, "0".repeat(64));
    assert.equal(row.vector_sha256, legacyVectorSha256);
    assert.equal(migrated.prepare("PRAGMA user_version").get().user_version, memory.SCHEMA_VERSION);
  } finally {
    migrated.close();
  }
  assert.equal(
    memory.listEmbeddableEvents(
      { model: "legacy-model", modelDigest: "e".repeat(64), dimensions: 3 },
      { dbPath },
    ).length,
    1,
  );
});

test("next-turn packs exclude the current source/session and do not re-serve memory", () => {
  const { dbPath } = tempStore();
  const reusable = memory.captureMessage(
    {
      source: "llm-wiki",
      sessionId: "historic-chat",
      messageId: "historic-1",
      role: "system",
      content: "Project lantern uses the cobalt deployment checklist.",
    },
    { dbPath },
  ).event;
  memory.captureMessage(
    {
      source: "codex",
      sessionId: "current-session",
      messageId: "current-1",
      role: "assistant",
      content: "Project lantern currently discusses the cobalt deployment checklist.",
    },
    { dbPath },
  );

  const first = memory.buildNextTurnPack(
    {
      query: "lantern cobalt deployment",
      consumer: "codex",
      sessionId: "current-session",
      source: "codex",
      maxChars: 800,
      limit: 5,
    },
    { dbPath },
  );
  const second = memory.buildNextTurnPack(
    {
      query: "lantern cobalt deployment",
      consumer: "codex",
      sessionId: "current-session",
      source: "codex",
      maxChars: 800,
      limit: 5,
    },
    { dbPath },
  );

  assert.deepEqual(first.results.map((event) => event.id), [reusable.id]);
  assert.equal(first.servedCount, 1);
  assert.equal(second.results.length, 0);
  assert.equal(second.servedCount, 0);
});

test("retrieval traces are append-only and the database path is environment-overridable", () => {
  const { dbPath } = tempStore();
  const old = process.env.MEMORY_EVENTS_DB_PATH;
  process.env.MEMORY_EVENTS_DB_PATH = dbPath;
  try {
    assert.equal(memory.resolveMemoryDbPath(), path.resolve(dbPath));
    const trace = memory.recordRetrievalTrace({
      traceId: "trace-test-1",
      query: "needle",
      consumer: "test-suite",
      sessionId: "session-z",
      resultIds: ["event-a", "drawer-b"],
      filters: { wing: "wing_test" },
    });
    assert.equal(trace.traceId, "trace-test-1");
    const db = memory.openMemoryStore();
    try {
      const row = db.prepare("SELECT * FROM memory_retrieval_traces WHERE trace_id = ?").get("trace-test-1");
      assert.equal(row.consumer, "test-suite");
      assert.equal(row.query, "");
      assert.equal(row.query_preview, "");
      assert.match(row.query_sha256, /^[a-f0-9]{64}$/);
      const keyPath = path.join(path.dirname(dbPath), "memory_trace_hmac.key");
      const key = Buffer.from(fs.readFileSync(keyPath, "utf8").trim(), "hex");
      assert.equal(row.query_sha256, crypto.createHmac("sha256", key).update("needle").digest("hex"));
      assert.notEqual(row.query_sha256, crypto.createHash("sha256").update("needle").digest("hex"));
      if (process.platform !== "win32") assert.equal(fs.statSync(keyPath).mode & 0o777, 0o600);
      assert.equal(JSON.parse(row.metadata_json).queryDigestAlgorithm, "hmac-sha256-v1");
      assert.deepEqual(JSON.parse(row.result_ids_json), ["event-a", "drawer-b"]);
      assert.throws(
        () => db.prepare("UPDATE memory_retrieval_traces SET query = 'changed' WHERE trace_id = ?").run("trace-test-1"),
        /append-only/,
      );
    } finally {
      db.close();
    }
  } finally {
    if (old === undefined) delete process.env.MEMORY_EVENTS_DB_PATH;
    else process.env.MEMORY_EVENTS_DB_PATH = old;
  }
});

test("retrieval query previews require an explicit privacy opt-in", () => {
  const { dbPath } = tempStore();
  const old = process.env.MEMORY_TRACE_STORE_QUERY;
  process.env.MEMORY_TRACE_STORE_QUERY = "1";
  try {
    memory.recordRetrievalTrace({ traceId: "trace-preview", query: "bounded preview", consumer: "test" }, { dbPath });
    const db = memory.openMemoryStore({ dbPath });
    try {
      const row = db.prepare("SELECT query, query_preview FROM memory_retrieval_traces WHERE trace_id = ?").get("trace-preview");
      assert.equal(row.query, "");
      assert.equal(row.query_preview, "bounded preview");
    } finally {
      db.close();
    }
  } finally {
    if (old === undefined) delete process.env.MEMORY_TRACE_STORE_QUERY;
    else process.env.MEMORY_TRACE_STORE_QUERY = old;
  }
});

test("Hermes schema-v5 validation checks required objects, columns, and quick_check", { skip: process.platform === "win32" ? "Hermes requires POSIX file permissions" : false }, () => {
  const { dir, dbPath } = tempStore();
  memory.initializeHermesMemoryStore({ dbPath });
  assert.equal(memory.SCHEMA_VERSION, 5);
  assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
  assert.equal(fs.statSync(dbPath).mode & 0o777, 0o600);
  for (const suffix of ["-wal", "-shm"]) {
    const candidate = `${dbPath}${suffix}`;
    if (fs.existsSync(candidate)) assert.equal(fs.statSync(candidate).mode & 0o777, 0o600);
  }

  const db = memory.openMemoryStore({ dbPath });
  try {
    const prepared = [];
    const checked = {
      prepare(sql) {
        prepared.push(sql.trim());
        return db.prepare(sql);
      },
    };
    memory.validateHermesMemorySchema(checked);
    assert.equal(prepared.includes("PRAGMA quick_check"), true);

    const badIntegrity = {
      prepare(sql) {
        if (sql.trim() === "PRAGMA quick_check") return { get: () => ({ quick_check: "corrupt" }) };
        return db.prepare(sql);
      },
    };
    assert.throws(
      () => memory.validateHermesMemorySchema(badIntegrity),
      (error) => error?.code === "memory_store_invalid",
    );

    db.exec("DROP TRIGGER memory_write_audit_no_delete");
    assert.throws(
      () => memory.validateHermesMemorySchema(db),
      (error) => error?.code === "memory_store_invalid",
    );
  } finally {
    db.close();
  }
});

test("Hermes proposals and audit rows are append-only with one constrained consume transition", () => {
  const { dbPath } = tempStore();
  memory.initializeHermesMemoryStore({ dbPath });
  const context = {
    profile: "main",
    platform: "telegram",
    chatId: "1001",
    chatType: "private",
    userId: "1001",
    topicId: "topic-alpha",
    sessionKey: "session-key-alpha",
    sessionId: "session-alpha",
  };
  const proposal = memory.proposeHermesMemoryWrite(context, {
    eventType: "user_memory",
    content: "Remember the append-only consent invariant.",
  }, { dbPath, nonceFactory: () => "P".repeat(32) });

  const db = memory.openMemoryStore({ dbPath });
  try {
    assert.throws(
      () => db.prepare("UPDATE memory_write_proposals SET payload_json = '{}' WHERE nonce = ?").run(proposal.nonce),
      /consume|append-only|proposal/i,
    );
    assert.throws(
      () => db.prepare("DELETE FROM memory_write_proposals WHERE nonce = ?").run(proposal.nonce),
      /delete|append-only|proposal/i,
    );
    assert.throws(
      () => db.prepare("UPDATE memory_write_proposals SET consumed_at = ?, event_id = ? WHERE nonce = ?")
        .run(new Date().toISOString(), "missing-event", proposal.nonce),
      /event|audit|consume/i,
    );
  } finally {
    db.close();
  }

  memory.confirmHermesMemoryWrite(context, proposal.nonce, proposal.payload_hash, { dbPath });
  const confirmed = memory.openMemoryStore({ dbPath });
  try {
    assert.equal(confirmed.prepare("SELECT COUNT(*) AS count FROM memory_write_audit").get().count, 1);
    assert.throws(
      () => confirmed.prepare("UPDATE memory_write_proposals SET consumed_at = consumed_at WHERE nonce = ?").run(proposal.nonce),
      /consume|append-only|proposal/i,
    );
    assert.throws(
      () => confirmed.prepare("UPDATE memory_write_audit SET action = 'changed'").run(),
      /append-only/i,
    );
    assert.throws(
      () => confirmed.prepare("DELETE FROM memory_write_audit").run(),
      /append-only/i,
    );
  } finally {
    confirmed.close();
  }
});
