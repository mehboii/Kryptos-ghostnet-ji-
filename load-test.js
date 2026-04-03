#!/usr/bin/env node
/**
 * GhostNet Backend — API Load Test (ESM)
 * ───────────────────────────────────────
 * Hits /health, /auth, /messages, /nodes with 100 concurrent requests each.
 * Logs response times (min, max, avg, p50, p95, p99) and failure counts.
 * Saves full results to load-test-results-<timestamp>.txt
 */
'use strict';

import fs from 'fs';

const BACKEND_URL = 'https://ghostnet-ji-production.up.railway.app';
const ENDPOINTS = ['/health', '/auth', '/messages', '/nodes'];
const CONCURRENCY = 100;
const TIMEOUT_MS = 15000;

// ─── Log buffer ──────────────────────────────────────────────────────────────

const logLines = [];
function log(msg = '') {
  console.log(msg);
  logLines.push(msg);
}

// ─── HTTP Request with timing ────────────────────────────────────────────────

async function timedRequest(path) {
  const url = `${BACKEND_URL}${path}`;
  const start = performance.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, { signal: controller.signal });
    const body = await res.text();
    clearTimeout(timer);
    const elapsed = performance.now() - start;
    return {
      status: res.status,
      time_ms: Math.round(elapsed * 100) / 100,
      body_length: body.length,
      error: null,
    };
  } catch (err) {
    clearTimeout(timer);
    const elapsed = performance.now() - start;
    return {
      status: null,
      time_ms: Math.round(elapsed * 100) / 100,
      body_length: 0,
      error: err.name === 'AbortError' ? 'TIMEOUT' : (err.code || err.message),
    };
  }
}

// ─── Percentile helper ───────────────────────────────────────────────────────

function percentile(sorted, p) {
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, idx)];
}

// ─── Run load test for one endpoint ──────────────────────────────────────────

async function testEndpoint(path) {
  const promises = [];
  for (let i = 0; i < CONCURRENCY; i++) {
    promises.push(timedRequest(path));
  }
  const results = await Promise.all(promises);

  // Categorize
  const successes = results.filter((r) => !r.error && r.status >= 200 && r.status < 500);
  const failures = results.filter((r) => r.error);
  const serverErrors = results.filter((r) => !r.error && r.status >= 500);
  const times = results.filter((r) => !r.error).map((r) => r.time_ms).sort((a, b) => a - b);

  // Status distribution
  const statusDist = {};
  for (const r of results) {
    const key = r.error ? `ERR:${r.error}` : `${r.status}`;
    statusDist[key] = (statusDist[key] || 0) + 1;
  }

  // Timing stats
  let timing = null;
  if (times.length > 0) {
    timing = {
      min: times[0],
      max: times[times.length - 1],
      avg: Math.round((times.reduce((a, b) => a + b, 0) / times.length) * 100) / 100,
      p50: percentile(times, 50),
      p95: percentile(times, 95),
      p99: percentile(times, 99),
    };
  }

  return {
    path,
    total: CONCURRENCY,
    successes: successes.length,
    failures: failures.length,
    serverErrors: serverErrors.length,
    statusDist,
    timing,
  };
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const startTime = new Date().toISOString();

  log('╔════════════════════════════════════════════════════════════════╗');
  log('║   GhostNet Backend — API Load Test                            ║');
  log(`║   Target: ${BACKEND_URL.padEnd(49)}║`);
  log(`║   Concurrency: ${String(CONCURRENCY).padEnd(44)}║`);
  log(`║   Started: ${startTime.padEnd(48)}║`);
  log('╚════════════════════════════════════════════════════════════════╝');
  log('');

  const allResults = [];

  for (const endpoint of ENDPOINTS) {
    process.stdout.write(`  ⏳ Hitting ${endpoint} with ${CONCURRENCY} concurrent requests...`);
    const result = await testEndpoint(endpoint);
    allResults.push(result);
    process.stdout.write(' done.\n');
    logLines.push(`  ⏳ Hitting ${endpoint} with ${CONCURRENCY} concurrent requests... done.`);

    // Per-endpoint detail
    log('');
    log(`  ┌─── ${endpoint} ${'─'.repeat(55 - endpoint.length)}┐`);
    log(`  │  Responses: ${result.successes}/${result.total} ok  |  ${result.failures} network errors  |  ${result.serverErrors} server errors`);
    log(`  │  Status distribution: ${JSON.stringify(result.statusDist)}`);
    if (result.timing) {
      const t = result.timing;
      log(`  │  Latency:  min ${t.min}ms  |  avg ${t.avg}ms  |  p50 ${t.p50}ms  |  p95 ${t.p95}ms  |  p99 ${t.p99}ms  |  max ${t.max}ms`);
    } else {
      log(`  │  Latency:  N/A (all requests failed)`);
    }
    log(`  └${'─'.repeat(62)}┘`);
    log('');
  }

  // ─── Summary table ──────────────────────────────────────────────────────

  log('╔═══════════════════════════════════════════════════════════════════════════════════════════╗');
  log('║                              LOAD TEST SUMMARY                                          ║');
  log('╠════════════╦══════╦══════╦═══════╦════════╦════════╦════════╦════════╦════════╦══════════╣');
  log('║ Endpoint   ║  OK  ║ Fail ║ 5xx   ║ Min ms ║ Avg ms ║ p50 ms ║ p95 ms ║ p99 ms ║ Max ms  ║');
  log('╠════════════╬══════╬══════╬═══════╬════════╬════════╬════════╬════════╬════════╬══════════╣');

  for (const r of allResults) {
    const t = r.timing || { min: '-', avg: '-', p50: '-', p95: '-', p99: '-', max: '-' };
    const pad = (v, w) => String(v).padStart(w);
    log(
      `║ ${r.path.padEnd(10)} ║ ${pad(r.successes, 4)} ║ ${pad(r.failures, 4)} ║ ${pad(r.serverErrors, 5)} ║ ${pad(t.min, 6)} ║ ${pad(t.avg, 6)} ║ ${pad(t.p50, 6)} ║ ${pad(t.p95, 6)} ║ ${pad(t.p99, 6)} ║ ${pad(t.max, 7)} ║`
    );
  }

  log('╚════════════╩══════╩══════╩═══════╩════════╩════════╩════════╩════════╩════════╩══════════╝');

  // Verdict
  const totalFails = allResults.reduce((s, r) => s + r.failures, 0);
  const total5xx = allResults.reduce((s, r) => s + r.serverErrors, 0);
  const totalReqs = allResults.reduce((s, r) => s + r.total, 0);
  const allAvg = allResults.filter((r) => r.timing).map((r) => r.timing.avg);
  const overallAvg = allAvg.length > 0 ? Math.round(allAvg.reduce((a, b) => a + b, 0) / allAvg.length) : 0;
  const allP95 = allResults.filter((r) => r.timing).map((r) => r.timing.p95);
  const overallP95 = allP95.length > 0 ? Math.round(Math.max(...allP95)) : 0;

  log('');
  log(`  Total: ${totalReqs} requests  |  ${totalReqs - totalFails} responded  |  ${totalFails} network errors  |  ${total5xx} server errors`);
  log(`  Overall avg latency: ${overallAvg}ms  |  Worst p95: ${overallP95}ms`);

  if (totalFails === 0 && total5xx === 0) {
    log('\n  🟢 ALL ENDPOINTS RESPONDED — No failures under load.\n');
  } else if (totalFails === 0) {
    log(`\n  🟡 NO NETWORK FAILURES but ${total5xx} server errors (5xx) detected.\n`);
  } else {
    log(`\n  🔴 ${totalFails} NETWORK FAILURES + ${total5xx} SERVER ERRORS under ${CONCURRENCY}-concurrent load.\n`);
  }

  // Save to file
  const logFile = `load-test-results-${Date.now()}.txt`;
  fs.writeFileSync(logFile, logLines.join('\n'), 'utf-8');
  log(`  📄 Results saved to ${logFile}`);
}

main().catch((e) => {
  console.error('Load test crashed:', e);
  process.exit(1);
});
