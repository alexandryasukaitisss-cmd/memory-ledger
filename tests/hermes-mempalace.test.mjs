import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import test from "node:test";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const memory = require(path.join(root, "scripts/memory_contract.js"));
const bridge = require(path.join(root, "scripts/hermes_mempalace_mcp.js"));
const bridgePath = path.join(root, "scripts/hermes_mempalace_mcp.js");
const pluginPath = path.join(root, "hermes-plugins/local-mempalace/__init__.py");

function trustedContext(overrides = {}) {
  return {
    profile: "main",
    platform: "telegram",
    chatId: "1001",
    chatType: "private",
    userId: "1001",
    topicId: "topic-alpha",
    sessionKey: "agent:main:telegram:private:1001:topic-alpha",
    sessionId: "session-alpha",
    ...overrides,
  };
}

function tempStore() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-mempalace-"));
  const palaceDir = path.join(dir, ".mempalace");
  const dbPath = path.join(palaceDir, "memory_events.sqlite3");
  memory.initializeHermesMemoryStore({ dbPath });
  return { dir, palaceDir, dbPath };
}

function captureScopedEvent(dbPath, context, id, content) {
  return memory.captureEvent({
    eventId: id,
    eventType: "user_memory",
    producer: "hermes-mempalace-test",
    source: "hermes",
    sourceRef: `test:${id}`,
    sessionId: context.sessionId,
    messageId: `message:${id}`,
    role: "user",
    content,
    sourceProfile: context.profile,
    sourcePlatform: context.platform,
    sourceChatId: context.chatId,
    sourceUserId: context.userId,
    sourceTopicId: context.topicId,
    sourceSessionId: context.sessionId,
    scopeKind: "profile_topic",
    authorizationVersion: memory.HERMES_MEMORY_AUTHORIZATION_VERSION,
  }, { dbPath }).event;
}

function bridgeConfig(dbPath, context) {
  return {
    schemaVersion: 1,
    dbPath,
    proposalTtlSeconds: 300,
    routes: [{
      profile: context.profile,
      chatId: context.chatId,
      userId: context.userId,
    }],
  };
}

function writeBridgeConfig(dbPath, context) {
  const configPath = path.join(path.dirname(dbPath), "hermes-mempalace.json");
  fs.writeFileSync(configPath, JSON.stringify({
    ...bridgeConfig(dbPath, context),
    nodeCommand: process.execPath,
    serverPath: bridgePath,
  }));
  fs.chmodSync(configPath, 0o600);
  return configPath;
}

function confirmInChild(configPath, context, proposal) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bridgePath, "confirm"], {
      env: {
        ...process.env,
        HERMES_MEMPALACE_CONFIG: configPath,
        HERMES_MEMPALACE_CONTEXT_B64: Buffer.from(JSON.stringify(context)).toString("base64url"),
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("close", (code) => {
      let payload = null;
      try { payload = JSON.parse(stdout.trim()); } catch {}
      resolve({ code, payload, stdout, stderr });
    });
    child.stdin.end(JSON.stringify({ nonce: proposal.nonce, payloadHash: proposal.payload_hash }));
  });
}

test("authorized search isolates owners, denies legacy rows, honors explicit grants, and stays bounded", () => {
  const { dbPath } = tempStore();
  const owner = trustedContext();
  const otherTopic = trustedContext({ topicId: "topic-beta", sessionKey: "topic-beta-key", sessionId: "topic-beta-session" });
  const otherProfile = trustedContext({
    profile: "family",
    chatId: "2002",
    userId: "2002",
    topicId: "topic-family",
    sessionKey: "family-key",
    sessionId: "family-session",
  });
  const owned = captureScopedEvent(dbPath, owner, "hermes-owned", `orchid ${"bounded ".repeat(300)}`);
  captureScopedEvent(dbPath, otherTopic, "hermes-other-topic", "orchid topic beta only");
  captureScopedEvent(dbPath, otherProfile, "hermes-other-profile", "orchid family only");
  memory.captureEvent({
    eventId: "hermes-legacy",
    eventType: "user_memory",
    producer: "legacy",
    source: "hermes",
    sessionId: "legacy-session",
    messageId: "legacy-message",
    role: "user",
    content: "orchid legacy unlabelled",
  }, { dbPath });

  const ownerResult = memory.searchAuthorizedHermesMemory(owner, "orchid", {
    dbPath,
    limit: 8,
    maxCharsPerItem: 120,
    maxTotalChars: 160,
  });
  assert.deepEqual(ownerResult.items.map((item) => item.event_id), [owned.id]);
  assert.equal(ownerResult.items[0].grant_kind, "owner");
  assert.ok(ownerResult.items[0].text.length <= 120);
  assert.ok(ownerResult.items.reduce((sum, item) => sum + item.text.length, 0) <= 160);
  assert.equal(ownerResult.truncated, true);

  assert.deepEqual(memory.searchAuthorizedHermesMemory(otherTopic, "orchid", { dbPath }).items.map((item) => item.event_id), ["hermes-other-topic"]);
  assert.deepEqual(memory.searchAuthorizedHermesMemory(otherProfile, "orchid", { dbPath }).items.map((item) => item.event_id), ["hermes-other-profile"]);

  const grantee = trustedContext({
    profile: "igor",
    chatId: "3003",
    userId: "3003",
    topicId: "topic-igor",
    sessionKey: "igor-key",
    sessionId: "igor-session",
  });
  assert.deepEqual(memory.searchAuthorizedHermesMemory(grantee, "orchid", { dbPath }).items, []);

  const invalidGrantContext = trustedContext({
    profile: "igor",
    chatId: "4004",
    userId: "4004",
    topicId: "topic-invalid-grant",
    sessionKey: "invalid-grant-key",
    sessionId: "invalid-grant-session",
  });
  const db = memory.openMemoryStore({ dbPath });
  try {
    db.prepare(`
      INSERT INTO memory_shared_grants(
        grant_id, event_id, grantee_profile, grantee_platform, grantee_chat_id,
        grantee_user_id, grantee_topic_id, grant_kind, created_at, expires_at,
        authorization_version
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?)
    `).run(
      "grant-unknown-kind",
      owned.id,
      invalidGrantContext.profile,
      invalidGrantContext.platform,
      invalidGrantContext.chatId,
      invalidGrantContext.userId,
      invalidGrantContext.topicId,
      "unknown",
      new Date().toISOString(),
      memory.HERMES_MEMORY_AUTHORIZATION_VERSION,
    );
  } finally {
    db.close();
  }
  assert.deepEqual(memory.searchAuthorizedHermesMemory(invalidGrantContext, "orchid", { dbPath }).items, []);

  memory.createHermesMemoryGrant(owned.id, grantee, {
    dbPath,
    grantId: "grant-owned-to-igor",
    grantKind: "profile_topic",
  });
  const granted = memory.searchAuthorizedHermesMemory(grantee, "orchid", { dbPath });
  assert.deepEqual(granted.items.map((item) => item.event_id), [owned.id]);
  assert.equal(granted.items[0].grant_kind, "explicit");
  assert.equal(granted.items.some((item) => item.event_id === "hermes-legacy"), false);
});

test("proposal stores only a session-key hash, lasts exactly 300 seconds, and writes no event", () => {
  const { dbPath } = tempStore();
  const context = trustedContext();
  const now = new Date("2026-08-11T12:00:00.000Z");
  const proposal = memory.proposeHermesMemoryWrite(context, {
    eventType: "user_memory",
    content: "Remember the cobalt deployment window.",
    tags: ["deployment", "cobalt"],
  }, {
    dbPath,
    now,
    ttlSeconds: 30,
    nonceFactory: () => "A".repeat(32),
  });

  assert.equal(proposal.expires_at, "2026-08-11T12:05:00.000Z");
  assert.equal(proposal.confirmation_command, `/memory-confirm ${proposal.nonce} ${proposal.payload_hash}`);
  const db = memory.openMemoryStore({ dbPath });
  try {
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM memory_events").get().count, 0);
    const row = db.prepare("SELECT * FROM memory_write_proposals WHERE nonce = ?").get(proposal.nonce);
    assert.equal(row.source_session_key_hash, crypto.createHash("sha256").update(context.sessionKey).digest("hex"));
    assert.equal(row.payload_json.includes(context.sessionKey), false);
    assert.equal(Object.hasOwn(row, "source_session_key"), false);
  } finally {
    db.close();
  }
});

test("confirmation rejects wrong hash, context, session, expiry, and replay without partial writes", () => {
  const { dbPath } = tempStore();
  const context = trustedContext();
  const now = new Date("2026-08-11T13:00:00.000Z");
  const proposal = memory.proposeHermesMemoryWrite(context, {
    eventType: "user_memory",
    content: "Remember the amber release gate.",
  }, { dbPath, now, nonceFactory: () => "B".repeat(32) });

  const denied = [
    () => memory.confirmHermesMemoryWrite(context, proposal.nonce, "0".repeat(64), { dbPath, now }),
    () => memory.confirmHermesMemoryWrite(trustedContext({ topicId: "topic-other" }), proposal.nonce, proposal.payload_hash, { dbPath, now }),
    () => memory.confirmHermesMemoryWrite(trustedContext({ sessionKey: "wrong-session-key" }), proposal.nonce, proposal.payload_hash, { dbPath, now }),
    () => memory.confirmHermesMemoryWrite(trustedContext({ sessionId: "wrong-session-id" }), proposal.nonce, proposal.payload_hash, { dbPath, now }),
    () => memory.confirmHermesMemoryWrite(trustedContext({ profile: "family", chatId: "2002", userId: "2002" }), proposal.nonce, proposal.payload_hash, { dbPath, now }),
  ];
  for (const attempt of denied) assert.throws(attempt, (error) => error?.code === "confirmation_invalid");

  const before = memory.openMemoryStore({ dbPath });
  try {
    assert.equal(before.prepare("SELECT COUNT(*) AS count FROM memory_events").get().count, 0);
    assert.equal(before.prepare("SELECT COUNT(*) AS count FROM memory_write_audit").get().count, 0);
    assert.equal(before.prepare("SELECT consumed_at FROM memory_write_proposals WHERE nonce = ?").get(proposal.nonce).consumed_at, "");
  } finally {
    before.close();
  }

  const expired = memory.proposeHermesMemoryWrite(context, {
    eventType: "user_memory",
    content: "This proposal must expire.",
  }, { dbPath, now, nonceFactory: () => "C".repeat(32) });
  assert.throws(
    () => memory.confirmHermesMemoryWrite(context, expired.nonce, expired.payload_hash, {
      dbPath,
      now: new Date(now.valueOf() + 300_000),
    }),
    (error) => error?.code === "confirmation_invalid",
  );

  const confirmed = memory.confirmHermesMemoryWrite(context, proposal.nonce, proposal.payload_hash, {
    dbPath,
    now: new Date(now.valueOf() + 299_999),
  });
  assert.equal(confirmed.ok, true);
  assert.throws(
    () => memory.confirmHermesMemoryWrite(context, proposal.nonce, proposal.payload_hash, { dbPath }),
    (error) => error?.code === "confirmation_invalid",
  );
  const after = memory.openMemoryStore({ dbPath });
  try {
    assert.equal(after.prepare("SELECT COUNT(*) AS count FROM memory_events").get().count, 1);
    assert.equal(after.prepare("SELECT COUNT(*) AS count FROM memory_write_audit").get().count, 1);
    const event = after.prepare("SELECT * FROM memory_events").get();
    assert.equal(event.source_profile, context.profile);
    assert.equal(event.source_topic_id, context.topicId);
    assert.equal(event.source_session_id, context.sessionId);
  } finally {
    after.close();
  }
});

test("concurrent exact confirmations append exactly one event and one audit row", async () => {
  const { dbPath } = tempStore();
  const context = trustedContext();
  const proposal = memory.proposeHermesMemoryWrite(context, {
    eventType: "user_memory",
    content: "Remember the single-consume race result.",
  }, { dbPath, nonceFactory: () => "D".repeat(32) });
  const configPath = writeBridgeConfig(dbPath, context);

  const results = await Promise.all([
    confirmInChild(configPath, context, proposal),
    confirmInChild(configPath, context, proposal),
  ]);
  assert.deepEqual(results.map((result) => result.code).sort(), [0, 1], JSON.stringify(results));
  assert.equal(results.filter((result) => result.payload?.ok === true).length, 1);

  const db = memory.openMemoryStore({ dbPath });
  try {
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM memory_events").get().count, 1);
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM memory_write_audit").get().count, 1);
    const stored = db.prepare("SELECT consumed_at, event_id FROM memory_write_proposals WHERE nonce = ?").get(proposal.nonce);
    assert.notEqual(stored.consumed_at, "");
    assert.notEqual(stored.event_id, "");
  } finally {
    db.close();
  }
});

test("MCP exposes exactly two tools and rejects model-supplied identity", async () => {
  const context = trustedContext();
  const config = bridgeConfig("/tmp/not-opened.sqlite3", context);
  const listed = await bridge.handleMcpRequest({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  assert.deepEqual(listed.result.tools.map((tool) => tool.name), ["mempalace_context", "mempalace_propose_write"]);
  assert.equal(listed.result.tools.some((tool) => /confirm/i.test(tool.name)), false);

  let observedContext = null;
  const valid = await bridge.handleMcpRequest({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: { name: "mempalace_context", arguments: { query: "orchid", limit: 2 } },
  }, {
    config,
    context,
    search: (trusted) => {
      observedContext = trusted;
      return { version: 1, ok: true, items: [], observed_at: new Date().toISOString(), truncated: false, error: null };
    },
  });
  assert.equal(valid.result.structuredContent.ok, true);
  assert.deepEqual(observedContext, context);

  for (const argumentsValue of [
    { query: "orchid", profile: "family" },
    { query: "orchid", sessionId: "model-session" },
    { query: "orchid", limit: 0 },
    { query: "orchid", limit: 9 },
    { query: "orchid", limit: 1.5 },
    { query: "orchid", limit: "2" },
    { eventType: "user_memory", content: "unsafe identity", topicId: "model-topic" },
  ]) {
    const name = Object.hasOwn(argumentsValue, "eventType") ? "mempalace_propose_write" : "mempalace_context";
    const denied = await bridge.handleMcpRequest({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name, arguments: argumentsValue },
    }, { config, context });
    assert.equal(denied.result.structuredContent.ok, false);
    assert.equal(denied.result.structuredContent.error.code, "invalid_request");
  }
});

test("plugin accepts only the exact private confirmation command and registers no confirmation tool", () => {
  const { dbPath } = tempStore();
  const context = trustedContext();
  const configPath = writeBridgeConfig(dbPath, context);
  const script = String.raw`
import importlib.util, json, sys
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("test_local_mempalace", ${JSON.stringify(pluginPath)})
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

def event(text, chat_type="dm"):
    source = SimpleNamespace(platform="telegram", chat_id="1001", chat_type=chat_type,
                             user_id="1001", profile="main", thread_id="topic-alpha")
    return SimpleNamespace(source=source, text=text, message_id="message-1")

nonce = "N" * 32
digest = "a" * 64
exact = module._pre_gateway_dispatch(event=event(f"/memory-confirm {nonce} {digest}"))
trailing = module._pre_gateway_dispatch(event=event(f"/memory-confirm {nonce} {digest} extra"))
group = module._pre_gateway_dispatch(event=event(f"/memory-confirm {nonce} {digest}", "group"))

class Registry:
    def __init__(self):
        self.tools = []
        self.commands = []
        self.hooks = []
    def register_tool(self, **kwargs): self.tools.append(kwargs["name"])
    def register_command(self, name, *args, **kwargs): self.commands.append(name)
    def register_hook(self, name, *args, **kwargs): self.hooks.append(name)

registry = Registry()
module.register(registry)
print(json.dumps({"exact": exact, "trailing": trailing, "group": group,
                  "tools": registry.tools, "commands": registry.commands,
                  "hooks": registry.hooks}))
`;
  const result = spawnSync("python3", ["-c", script], {
    encoding: "utf8",
    env: { ...process.env, HERMES_MEMPALACE_CONFIG: configPath },
  });
  assert.equal(result.status, 0, result.stderr);
  const payload = JSON.parse(result.stdout);
  assert.equal(payload.exact.action, "rewrite");
  assert.match(payload.exact.text, /^\/memory-confirm-private\s+[A-Za-z0-9_-]+$/u);
  assert.equal(payload.trailing, null);
  assert.deepEqual(payload.group, { action: "skip", reason: "mempalace_route_denied" });
  assert.deepEqual(payload.tools, ["mempalace_context", "mempalace_propose_write"]);
  assert.equal(payload.tools.some((name) => /confirm/i.test(name)), false);
  assert.deepEqual(payload.commands, ["memory-confirm-private"]);
  assert.deepEqual(payload.hooks, ["pre_gateway_dispatch"]);
});

test("gateway confirmation relay preserves session binding and consumes one exact proposal", () => {
  const { dbPath } = tempStore();
  const context = trustedContext();
  const proposal = memory.proposeHermesMemoryWrite(context, {
    eventType: "user_memory",
    content: "Remember the exact gateway relay acceptance.",
    tags: ["gateway", "acceptance"],
  }, { dbPath, nonceFactory: () => "R".repeat(32) });
  const configPath = writeBridgeConfig(dbPath, context);
  const script = String.raw`
import asyncio, importlib.util, json, sys, types
from types import SimpleNamespace

gateway = types.ModuleType("gateway")
session_context = types.ModuleType("gateway.session_context")
values = {
    "HERMES_SESSION_PLATFORM": "telegram",
    "HERMES_SESSION_CHAT_ID": "1001",
    "HERMES_SESSION_CHAT_TYPE": "private",
    "HERMES_SESSION_USER_ID": "1001",
    "HERMES_SESSION_PROFILE": "main",
    "HERMES_SESSION_THREAD_ID": "topic-alpha",
    "HERMES_SESSION_KEY": "agent:main:telegram:private:1001:topic-alpha",
    "HERMES_SESSION_ID": "session-alpha",
    "HERMES_SESSION_MESSAGE_ID": "confirm-message",
}
session_context.get_session_env = lambda key, default="": values.get(key, default)
gateway.session_context = session_context
sys.modules["gateway"] = gateway
sys.modules["gateway.session_context"] = session_context

spec = importlib.util.spec_from_file_location("test_local_mempalace_relay", ${JSON.stringify(pluginPath)})
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

source = SimpleNamespace(platform="telegram", chat_id="1001", chat_type="private",
                         user_id="1001", profile="main", thread_id="topic-alpha")
event = SimpleNamespace(
    source=source,
    text=${JSON.stringify(proposal.confirmation_command)},
    message_id="confirm-message",
)

wrong_relay = module._pre_gateway_dispatch(event=event)
values["HERMES_SESSION_ID"] = "wrong-session"
wrong = asyncio.run(module._confirm_command(wrong_relay["text"].split()[1]))

values["HERMES_SESSION_ID"] = "session-alpha"
exact_relay = module._pre_gateway_dispatch(event=event)
exact_token = exact_relay["text"].split()[1]
exact = asyncio.run(module._confirm_command(exact_token))
replay = asyncio.run(module._confirm_command(exact_token))
print(json.dumps({"wrong": wrong, "exact": exact, "replay": replay}, ensure_ascii=False))
`;
  const result = spawnSync("python3", ["-c", script], {
    encoding: "utf8",
    env: { ...process.env, HERMES_MEMPALACE_CONFIG: configPath },
  });
  assert.equal(result.status, 0, result.stderr);
  const payload = JSON.parse(result.stdout);
  assert.match(payload.wrong, /отклонено/u);
  assert.match(payload.exact, /Память сохранена/u);
  assert.match(payload.replay, /отклонено/u);

  const db = memory.openMemoryStore({ dbPath });
  try {
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM memory_events").get().count, 1);
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM memory_write_audit").get().count, 1);
    const stored = db.prepare("SELECT consumed_at, event_id FROM memory_write_proposals WHERE nonce = ?").get(proposal.nonce);
    assert.notEqual(stored.consumed_at, "");
    assert.notEqual(stored.event_id, "");
  } finally {
    db.close();
  }
});

test("Hermes MemPalace bridge and plugin have no Chroma dependency or import", () => {
  const importPattern = /(?:require\s*\([^)]*chroma|\bfrom\s+\S*chroma\S*\s+import\b|\bimport\s+\S*chroma\S*)/iu;
  for (const relative of [
    "scripts/memory_contract.js",
    "scripts/hermes_mempalace_mcp.js",
    "hermes-plugins/local-mempalace/__init__.py",
  ]) {
    const source = fs.readFileSync(path.join(root, relative), "utf8");
    assert.doesNotMatch(source, importPattern, relative);
  }
});

test('Hermes reads never create stores or silently change their permissions', (t) => {
  const { dir, dbPath, palaceDir } = tempStore();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const missingParent = path.join(dir, 'missing-store');
  assert.throws(() => memory.searchAuthorizedHermesMemory(trustedContext(), 'orchid', {
    dbPath: path.join(missingParent, 'memory.sqlite3'),
  }));
  assert.equal(fs.existsSync(missingParent), false);
  fs.chmodSync(dbPath, 0o644);
  assert.throws(() => memory.searchAuthorizedHermesMemory(trustedContext(), 'orchid', { dbPath }),
    error => error.code === 'memory_store_invalid');
  assert.equal(fs.statSync(dbPath).mode & 0o777, 0o644);
  fs.chmodSync(dbPath, 0o600);
  const before = fs.statSync(dbPath).ctimeMs;
  assert.equal(memory.searchAuthorizedHermesMemory(trustedContext(), 'orchid', { dbPath }).ok, true);
  assert.equal(fs.statSync(dbPath).ctimeMs, before);
  assert.equal(fs.statSync(palaceDir).mode & 0o777, 0o700);
});
