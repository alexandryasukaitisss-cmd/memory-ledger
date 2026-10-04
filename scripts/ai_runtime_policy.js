const fs = require('node:fs');
const path = require('node:path');
const POLICY_PATH = path.join(__dirname, '../config/memory-policy.json');

function loadRuntimePolicy() {
  return deepFreeze(JSON.parse(fs.readFileSync(POLICY_PATH, 'utf8')));
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function policyError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function boundedRequestedInteger(value, fallback, maximum, label) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw policyError('invalid_experimental_limit', `${label} must be between 1 and ${maximum}`);
  }
  return parsed;
}

function resolveExperimentalMemoryPolicy(request, policy = loadRuntimePolicy()) {
  if (!request) return null;
  const requested = request === true ? { enabled: true } : request;
  if (!requested || typeof requested !== 'object' || requested.enabled !== true) return null;
  const configured = policy.experimentalMemory;
  if (!configured?.enabled) {
    throw policyError('experimental_memory_disabled', 'Experimental memory is disabled by policy');
  }
  const antiRequested = requested.antiHits !== false;
  const structuralRequested = requested.structuralRecall !== false;
  if (antiRequested && !configured.antiHits?.enabled) {
    throw policyError('experimental_memory_disabled', 'Experimental anti-hits are disabled by policy');
  }
  if (structuralRequested && !configured.structuralRecall?.enabled) {
    throw policyError('experimental_memory_disabled', 'Experimental structural recall is disabled by policy');
  }
  if (Number(configured.structuralRecall?.maxHops) !== 1) {
    throw policyError('experimental_memory_disabled', 'Experimental structural recall must remain one hop');
  }
  return deepFreeze({
    enabled: true,
    version: Number(configured.version || 1),
    antiHits: {
      enabled: antiRequested,
      limit: antiRequested
        ? boundedRequestedInteger(
          requested.antiHitLimit,
          configured.antiHits.defaultItems,
          configured.antiHits.maxItems,
          'antiHitLimit',
        )
        : 0,
      maxCandidateScan: boundedRequestedInteger(
        requested.maxCandidateScan,
        configured.antiHits.maxCandidateScan,
        configured.antiHits.maxCandidateScan,
        'maxCandidateScan',
      ),
      maxItemChars: boundedRequestedInteger(
        requested.antiHitMaxItemChars,
        configured.antiHits.maxItemChars,
        configured.antiHits.maxItemChars,
        'antiHitMaxItemChars',
      ),
    },
    structuralRecall: {
      enabled: structuralRequested,
      limit: structuralRequested
        ? boundedRequestedInteger(
          requested.structuralLimit,
          configured.structuralRecall.defaultItems,
          configured.structuralRecall.maxItems,
          'structuralLimit',
        )
        : 0,
      maxHops: 1,
      maxCandidatesPerAnchor: boundedRequestedInteger(
        requested.maxCandidatesPerAnchor,
        configured.structuralRecall.maxCandidatesPerAnchor,
        configured.structuralRecall.maxCandidatesPerAnchor,
        'maxCandidatesPerAnchor',
      ),
      maxItemChars: boundedRequestedInteger(
        requested.structuralMaxItemChars,
        configured.structuralRecall.maxItemChars,
        configured.structuralRecall.maxItemChars,
        'structuralMaxItemChars',
      ),
    },
  });
}

function adapterAllows(adapter, operation, policy = loadRuntimePolicy()) {
  const allowed = policy.adapterOperations[adapter];
  return Array.isArray(allowed) && allowed.includes(operation);
}

function assertAdapterOperation(adapter, operation, policy = loadRuntimePolicy()) {
  if (!adapterAllows(adapter, operation, policy)) {
    throw new Error(`Adapter ${adapter} denies ${operation}`);
  }
  return true;
}

module.exports = { assertAdapterOperation, resolveExperimentalMemoryPolicy };
