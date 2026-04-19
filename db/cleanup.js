import { deleteExpiredMessages } from './messageStore.js';

const SIX_HOURS_MS = 6 * 60 * 60 * 1000;

let timer = null;

async function runCleanup(olderThanDays = 7) {
  try {
    const count = await deleteExpiredMessages(olderThanDays);
    if (count > 0) {
      console.log(`[DB Cleanup] Deleted ${count} expired messages (older than ${olderThanDays} days).`);
    }
  } catch (err) {
    console.error('[DB Cleanup] Error:', err.message);
  }
}

function startCleanupCron(olderThanDays = 7) {
  runCleanup(olderThanDays);
  timer = setInterval(() => runCleanup(olderThanDays), SIX_HOURS_MS);
  timer.unref();
  console.log('[DB Cleanup] Scheduled every 6 hours.');
}

function stopCleanupCron() {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}

export { startCleanupCron, stopCleanupCron, runCleanup };
