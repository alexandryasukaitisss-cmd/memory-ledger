#!/usr/bin/env node
'use strict';

process.umask(0o077);

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');

const memory = require('./memory_contract');

const CONTEXT_TOOL = Object.freeze({
  name: 'mempalace_context',
  title: 'Authorized MemPalace context',
  description: 'Read bounded memory authorized for the current trusted Hermes profile and Telegram topic.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['query'],
    properties: {
      query: { type: 'string', minLength: 1, maxLength: 2000 },
      limit: { type: 'integer', minimum: 1, maximum: 8 },
    },
  },
});

const PROPOSE_TOOL = Object.freeze({
  name: 'mempalace_propose_write',
  title: 'Propose a MemPalace write',
  description: 'Prepare one bounded memory item for explicit direct Telegram confirmation; this tool never writes a memory event.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['eventType', 'content'],
    properties: {
      eventType: { type: 'string', pattern: '^[a-z][a-z0-9._-]{0,63}$' },
      content: { type: 'string', minLength: 1, maxLength: 4000 },
      tags: {
        type: 'array',
        maxItems: 8,
        items: { type: 'string', minLength: 1, maxLength: 64 },
      },
    },
  },
});

const TOOLS = Object.freeze([CONTEXT_TOOL, PROPOSE_TOOL]);

function response(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function errorResponse(id, code, message) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

function configPath() {
  return path.resolve(
    process.env.HERMES_MEMPALACE_CONFIG
      || path.join(process.env.HERMES_HOME || path.join(os.homedir(), '.hermes'), 'mempalace-hermes.json'),
  );
}

function loadConfig() {
  const target = configPath();
  let payload;
  try {
    if ((fs.statSync(target).mode & 0o777) !== 0o600) throw new Error('unsafe mode');
    payload = JSON.parse(fs.readFileSync(target, 'utf8'));
  } catch (error) {
    throw Object.assign(new Error('MemPalace bridge configuration is unavailable'), {
      code: 'config_unavailable',
      cause: error,
    });
  }
  if (
    payload?.schemaVersion !== 1
    || !path.isAbsolute(String(payload.dbPath || ''))
    || !Number.isInteger(payload.proposalTtlSeconds)
    || payload.proposalTtlSeconds < 30
    || payload.proposalTtlSeconds > 300
  ) {
    throw Object.assign(new Error('MemPalace bridge configuration is invalid'), { code: 'config_invalid' });
  }
  if (!Array.isArray(payload.routes) || payload.routes.length === 0) {
    throw Object.assign(new Error('MemPalace bridge routes are invalid'), { code: 'config_invalid' });
  }
  const routes = payload.routes.map((route) => ({
    profile: String(route?.profile || '').trim(),
    chatId: String(route?.chatId || '').trim(),
    userId: String(route?.userId || '').trim(),
  }));
  if (routes.some((route) => (
    !/^[a-z0-9][a-z0-9_-]{0,63}$/u.test(route.profile)
    || !/^[1-9][0-9]*$/u.test(route.chatId)
    || route.chatId !== route.userId
  ))) {
    throw Object.assign(new Error('MemPalace bridge routes are invalid'), { code: 'config_invalid' });
  }
  const identities = new Set(routes.map((route) => `${route.profile}\0${route.chatId}\0${route.userId}`));
  if (identities.size !== routes.length) {
    throw Object.assign(new Error('MemPalace bridge routes are duplicated'), { code: 'config_invalid' });
  }
  return {
    dbPath: path.resolve(payload.dbPath),
    proposalTtlSeconds: payload.proposalTtlSeconds,
    routes,
  };
}

function trustedContextFromEnv() {
  const encoded = String(process.env.HERMES_MEMPALACE_CONTEXT_B64 || '').trim();
  if (!encoded || encoded.length > 32768) {
    throw Object.assign(new Error('Trusted Hermes context is unavailable'), { code: 'route_denied' });
  }
  try {
    const raw = Buffer.from(encoded, 'base64url').toString('utf8');
    return memory.normalizeHermesMemoryContext(JSON.parse(raw));
  } catch (error) {
    throw Object.assign(new Error('Trusted Hermes context is invalid'), { code: 'route_denied', cause: error });
  }
}

function assertAuthorizedRoute(config, context) {
  const matches = config.routes.filter((route) => (
    route.profile === context.profile
    && route.chatId === context.chatId
    && route.userId === context.userId
  ));
  if (matches.length !== 1) {
    throw Object.assign(new Error('Hermes memory route is not authorized'), { code: 'route_denied' });
  }
}

function requireObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw Object.assign(new Error('Tool arguments must be an object'), { code: 'invalid_request' });
  }
  return value;
}

function publicCode(error, fallback = 'storage_unavailable') {
  const code = String(error?.code || '');
  if (['invalid_request', 'query_invalid', 'proposal_invalid', 'clock_invalid'].includes(code)) {
    return 'invalid_request';
  }
  if (code === 'route_denied') return 'route_denied';
  if (code === 'confirmation_invalid') return 'confirmation_invalid';
  if (code === 'proposal_conflict' || code === 'storage_conflict' || code.startsWith('SQLITE_CONSTRAINT')) {
    return 'storage_conflict';
  }
  if (['config_unavailable', 'config_invalid', 'memory_store_invalid'].includes(code)) {
    return 'configuration_unavailable';
  }
  return fallback;
}

function toolEnvelope(value) {
  return {
    content: [{ type: 'text', text: JSON.stringify(value) }],
    structuredContent: value,
    isError: false,
  };
}

function toolFailure(error, name) {
  const failure = { version: 1, ok: false, error: { code: publicCode(error) } };
  if (name === CONTEXT_TOOL.name) Object.assign(failure, { items: [], truncated: false });
  return toolEnvelope(failure);
}

function invalidRequest(message) {
  throw Object.assign(new Error(message), { code: 'invalid_request' });
}

function validateContextArgs(value) {
  const args = requireObject(value);
  const unknown = Object.keys(args).filter((key) => !['query', 'limit'].includes(key));
  if (unknown.length || typeof args.query !== 'string') invalidRequest('Invalid context request');
  const query = args.query.trim();
  if (!query || query.length > 2000) invalidRequest('Invalid context query');
  if (args.limit !== undefined && (!Number.isInteger(args.limit) || args.limit < 1 || args.limit > 8)) {
    invalidRequest('Invalid context limit');
  }
  return { query, ...(args.limit === undefined ? {} : { limit: args.limit }) };
}

function validateProposalArgs(value) {
  const args = requireObject(value);
  const unknown = Object.keys(args).filter((key) => !['eventType', 'content', 'tags'].includes(key));
  if (
    unknown.length
    || typeof args.eventType !== 'string'
    || !/^[a-z][a-z0-9._-]{0,63}$/u.test(args.eventType)
    || typeof args.content !== 'string'
    || !args.content.trim()
    || args.content.length > 4000
  ) {
    invalidRequest('Invalid proposal request');
  }
  const tags = args.tags === undefined ? [] : args.tags;
  if (
    !Array.isArray(tags)
    || tags.length > 8
    || tags.some((tag) => (
      typeof tag !== 'string'
      || tag.length < 1
      || tag.length > 64
      || !/^[\p{L}\p{N}][\p{L}\p{N}._-]*$/u.test(tag)
    ))
  ) {
    invalidRequest('Invalid proposal tags');
  }
  return { eventType: args.eventType, content: args.content, ...(args.tags === undefined ? {} : { tags }) };
}

async function handleMcpRequest(message = {}, options = {}) {
  if (!message || message.jsonrpc !== '2.0' || typeof message.method !== 'string') {
    return errorResponse(message?.id ?? null, -32600, 'Invalid Request');
  }
  if (message.method.startsWith('notifications/')) return null;
  if (message.method === 'initialize') {
    return response(message.id, {
      protocolVersion: String(message.params?.protocolVersion || '2025-06-18'),
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: 'hermes-mempalace', version: '1.0.0' },
    });
  }
  if (message.method === 'ping') return response(message.id, {});
  if (message.method === 'tools/list') return response(message.id, { tools: TOOLS });
  if (message.method !== 'tools/call') return errorResponse(message.id, -32601, 'Method not found');

  const name = String(message.params?.name || '');
  if (!TOOLS.some((tool) => tool.name === name)) return errorResponse(message.id, -32602, 'Unknown tool');
  try {
    const config = options.config || loadConfig();
    const context = options.context || trustedContextFromEnv();
    assertAuthorizedRoute(config, context);
    if (name === CONTEXT_TOOL.name) {
      const args = validateContextArgs(message.params?.arguments);
      const result = (options.search || memory.searchAuthorizedHermesMemory)(context, args.query, {
        dbPath: config.dbPath,
        limit: args.limit,
      });
      return response(message.id, toolEnvelope(result));
    }
    const args = validateProposalArgs(message.params?.arguments);
    const result = (options.propose || memory.proposeHermesMemoryWrite)(context, args, {
      dbPath: config.dbPath,
      ttlSeconds: config.proposalTtlSeconds,
    });
    return response(message.id, toolEnvelope({ ...result, ok: true, error: null }));
  } catch (error) {
    return response(message.id, toolFailure(error, name));
  }
}

async function readSingleJson() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 64 * 1024) throw Object.assign(new Error('Input is too large'), { code: 'invalid_request' });
    chunks.push(chunk);
  }
  try {
    return requireObject(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  } catch (error) {
    if (error?.code) throw error;
    throw Object.assign(new Error('Input must be one JSON object'), { code: 'invalid_request', cause: error });
  }
}

async function runDirectConfirmation() {
  const input = await readSingleJson();
  const config = loadConfig();
  const context = trustedContextFromEnv();
  assertAuthorizedRoute(config, context);
  return memory.confirmHermesMemoryWrite(context, input.nonce, input.payloadHash, { dbPath: config.dbPath });
}

function runMigration() {
  const config = loadConfig();
  return memory.initializeHermesMemoryStore({ dbPath: config.dbPath });
}

function startStdioServer(options = {}) {
  let toolCallSeen = false;
  const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  input.on('line', async (line) => {
    if (!line.trim()) return;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      process.stdout.write(`${JSON.stringify(errorResponse(null, -32700, 'Parse error'))}\n`);
      return;
    }
    if (message.method === 'tools/call') {
      if (toolCallSeen) {
        process.stdout.write(`${JSON.stringify(errorResponse(message.id, -32000, 'One-shot server already used'))}\n`);
        return;
      }
      toolCallSeen = true;
    }
    const result = await handleMcpRequest(message, options);
    if (result) process.stdout.write(`${JSON.stringify(result)}\n`);
  });
}

async function main() {
  const mode = process.argv[2] || 'mcp';
  if (mode === 'mcp') {
    startStdioServer();
    return;
  }
  try {
    const result = mode === 'confirm' ? await runDirectConfirmation()
      : mode === 'migrate' ? runMigration()
        : (() => { throw Object.assign(new Error('Unknown mode'), { code: 'invalid_request' }); })();
    process.stdout.write(`${JSON.stringify({ ok: true, result, error: null })}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ ok: false, result: null, error: { code: publicCode(error) } })}\n`);
    process.exitCode = 1;
  }
}

if (require.main === module) void main();

module.exports = {
  CONTEXT_TOOL,
  PROPOSE_TOOL,
  TOOLS,
  assertAuthorizedRoute,
  handleMcpRequest,
  loadConfig,
  startStdioServer,
  trustedContextFromEnv,
};
