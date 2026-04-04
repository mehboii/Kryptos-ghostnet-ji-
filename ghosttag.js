/**
 * GhostTag — Client-Side Username System
 * ════════════════════════════════════════════════════════════════════════
 *
 * Responsibilities:
 *   • Claim a unique, case-insensitive @username (GhostTag) and link it
 *     to the user's cryptographic identity (nodeId + publicKey).
 *   • Enforce local uniqueness validation before server round-trip.
 *   • Offline-first: if the server is unreachable during registration,
 *     the tag claim is queued in localStorage and automatically synced
 *     when the server comes back online.
 *   • Share identity via tag or invite link.
 *   • Release the tag when the user deletes their identity/account,
 *     making the tag available for other users.
 *
 * Design constraints:
 *   • GhostTag is PERMANENTLY locked to the user until they delete
 *     their identity. No transfers, no renames.
 *   • Two users can NEVER claim the same tag — server is the
 *     authoritative source; client uses optimistic local-first with
 *     server reconciliation.
 *   • Case-insensitive: "GhostUser" and "ghostuser" are the same tag.
 *   • Offline registrations are persisted in localStorage with full
 *     claim data, synced on reconnect via a periodic watcher.
 */

const GhostTag = (() => {
    'use strict';

    // ─── CONSTANTS ──────────────────────────────────────────────────────────
    const TAG_REGEX = /^[a-z0-9_]{3,20}$/;
    const STORAGE_KEY_TAG = 'ghostnet_ghost_tag';
    const STORAGE_KEY_PENDING = 'ghostnet_pending_tag_claim_data';
    const STORAGE_KEY_PENDING_FLAG = 'ghostnet_pending_tag_claim';
    const STORAGE_KEY_SYNC_CONFLICT = 'ghostnet_tag_sync_conflict';

    let _syncInterval = null;
    let _isOnline = navigator.onLine;

    // ─── HELPERS ────────────────────────────────────────────────────────────

    function _getApiUrl() {
        return (window.BACKEND && window.BACKEND.http)
            ? window.BACKEND.http
            : 'https://ghostnet-ji-production.up.railway.app';
    }

    function _getAuthToken() {
        // Try sessionStorage first (index.html stores JSON envelope there)
        const sources = [
            sessionStorage.getItem('ghostnet_token'),
            localStorage.getItem('ghostnet_token'),
            localStorage.getItem('ghostnet_jwt'),
        ];
        for (const raw of sources) {
            if (!raw) continue;
            try {
                const parsed = JSON.parse(raw);
                if (parsed && typeof parsed.token === 'string') {
                    if (parsed.expiresAt && Date.now() > parsed.expiresAt) continue;
                    return parsed.token;
                }
            } catch (_) {}
            if (typeof raw === 'string' && raw.length > 10) return raw;
        }
        return null;
    }

    function _normalizeTag(tag) {
        if (typeof tag !== 'string') return '';
        return tag.trim().toLowerCase().replace(/^@/, '');
    }

    function _validateTag(tag) {
        const normalized = _normalizeTag(tag);
        if (!normalized) return { valid: false, error: 'GhostTag is required.' };
        if (!TAG_REGEX.test(normalized)) {
            return { valid: false, error: 'GhostTag must be 3–20 chars: lowercase letters, numbers, underscores only.' };
        }
        return { valid: true, tag: normalized };
    }

    // ─── LOCAL TAG STORAGE ──────────────────────────────────────────────────

    /**
     * Get the locally stored GhostTag for the current user.
     * Checks both the unified identity object and the legacy separate key.
     */
    function getLocalTag() {
        // 1. Try unified identity
        try {
            const identity = localStorage.getItem('ghostnet_identity');
            if (identity) {
                const parsed = JSON.parse(identity);
                if (parsed && parsed.ghostTag) return _normalizeTag(parsed.ghostTag);
            }
        } catch (_) {}

        // 2. Fallback to separate key
        const separate = localStorage.getItem(STORAGE_KEY_TAG);
        if (separate) return _normalizeTag(separate);

        return null;
    }

    /**
     * Save the GhostTag to both the unified identity object and separate key.
     */
    function _saveLocalTag(tag) {
        const normalized = _normalizeTag(tag);
        localStorage.setItem(STORAGE_KEY_TAG, normalized);

        // Also update unified identity
        try {
            const identity = localStorage.getItem('ghostnet_identity');
            if (identity) {
                const parsed = JSON.parse(identity);
                if (parsed) {
                    parsed.ghostTag = normalized;
                    localStorage.setItem('ghostnet_identity', JSON.stringify(parsed));
                }
            }
        } catch (_) {}
    }

    /**
     * Remove the GhostTag from local storage (on identity deletion).
     */
    function _clearLocalTag() {
        localStorage.removeItem(STORAGE_KEY_TAG);
        localStorage.removeItem(STORAGE_KEY_PENDING);
        localStorage.removeItem(STORAGE_KEY_PENDING_FLAG);
        localStorage.removeItem(STORAGE_KEY_SYNC_CONFLICT);

        try {
            const identity = localStorage.getItem('ghostnet_identity');
            if (identity) {
                const parsed = JSON.parse(identity);
                if (parsed) {
                    parsed.ghostTag = '';
                    localStorage.setItem('ghostnet_identity', JSON.stringify(parsed));
                }
            }
        } catch (_) {}
    }

    // ─── OFFLINE QUEUE ──────────────────────────────────────────────────────

    /**
     * Save a pending tag claim to localStorage for later sync.
     * Stores full claim data so it can be retried independently.
     */
    function _queuePendingClaim(claimData) {
        const payload = {
            tag: claimData.tag,
            nodeId: claimData.nodeId,
            publicKey: claimData.publicKey,
            displayName: claimData.displayName,
            queuedAt: Date.now(),
        };
        localStorage.setItem(STORAGE_KEY_PENDING, JSON.stringify(payload));
        localStorage.setItem(STORAGE_KEY_PENDING_FLAG, 'true');
        console.log(`[GhostTag] Queued pending claim for @${claimData.tag} (offline)`);
    }

    /**
     * Get the pending claim data from localStorage.
     * Returns null if no pending claim exists.
     */
    function getPendingClaim() {
        const flag = localStorage.getItem(STORAGE_KEY_PENDING_FLAG);
        if (flag !== 'true') return null;

        try {
            const raw = localStorage.getItem(STORAGE_KEY_PENDING);
            if (!raw) return null;
            return JSON.parse(raw);
        } catch (_) {
            return null;
        }
    }

    /**
     * Clear the pending claim queue (after successful sync or manual clear).
     */
    function _clearPendingClaim() {
        localStorage.removeItem(STORAGE_KEY_PENDING);
        localStorage.removeItem(STORAGE_KEY_PENDING_FLAG);
    }

    // ─── SERVER OPERATIONS ──────────────────────────────────────────────────

    /**
     * Check if a GhostTag is available on the server.
     * Returns: { available: boolean, tag: string, suggestions?: string[] }
     * On network failure: returns { available: true, offline: true } (optimistic)
     */
    async function checkAvailability(tag) {
        const validation = _validateTag(tag);
        if (!validation.valid) return { available: false, error: validation.error };

        try {
            const res = await fetch(`${_getApiUrl()}/ghosttag/check/${validation.tag}`, {
                method: 'GET',
                signal: AbortSignal.timeout(5000),
            });

            if (res.ok) {
                const data = await res.json();
                return {
                    available: !!data.available,
                    tag: '@' + validation.tag,
                };
            } else if (res.status === 400) {
                return { available: false, error: 'Invalid tag format.' };
            } else {
                // Server error — optimistic fallback
                return { available: true, tag: '@' + validation.tag, offline: true };
            }
        } catch (e) {
            // Network error — optimistic offline mode
            console.warn('[GhostTag] Server unreachable for availability check:', e.message);
            return { available: true, tag: '@' + validation.tag, offline: true };
        }
    }

    /**
     * Claim a GhostTag on the server.
     * If the server is offline, queues the claim for later sync.
     *
     * Returns:
     *   { success: true, tag: '@username' }                    — claimed successfully
     *   { success: true, tag: '@username', pending: true }     — queued offline
     *   { success: false, error: string, suggestions?: [] }    — claim failed
     */
    async function claimTag(tag, identity) {
        const validation = _validateTag(tag);
        if (!validation.valid) return { success: false, error: validation.error };

        const claimData = {
            tag: validation.tag,
            nodeId: identity.nodeId,
            publicKey: identity.publicKey || '',
            displayName: identity.displayName || validation.tag,
        };

        // Save locally immediately (optimistic)
        _saveLocalTag(validation.tag);

        const token = _getAuthToken();
        if (!token) {
            // No auth token — queue for offline sync
            _queuePendingClaim(claimData);
            return { success: true, tag: '@' + validation.tag, pending: true };
        }

        try {
            const res = await fetch(`${_getApiUrl()}/ghosttag/claim`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`,
                },
                body: JSON.stringify(claimData),
                signal: AbortSignal.timeout(8000),
            });

            if (res.ok) {
                const data = await res.json();
                _clearPendingClaim();
                console.log(`[GhostTag] Successfully claimed ${data.tag}`);
                return { success: true, tag: data.tag };
            }

            const errorData = await res.json().catch(() => ({}));

            if (res.status === 409) {
                // Conflict — tag already taken OR user already has a tag
                if (errorData.yourTag) {
                    // User already has a tag — update local to match server
                    _saveLocalTag(errorData.yourTag.replace(/^@/, ''));
                    _clearPendingClaim();
                    return { success: false, error: errorData.error, yourTag: errorData.yourTag };
                }
                // Tag taken by someone else
                _clearLocalTag();
                return {
                    success: false,
                    error: errorData.error || 'GhostTag already taken.',
                    suggestions: errorData.suggestions || [],
                };
            }

            return { success: false, error: errorData.error || 'Server error.' };
        } catch (e) {
            // Network failure — queue for offline sync
            console.warn('[GhostTag] Server unreachable for claim, queuing:', e.message);
            _queuePendingClaim(claimData);
            return { success: true, tag: '@' + validation.tag, pending: true };
        }
    }

    /**
     * Resolve a GhostTag to its owner's identity info.
     * Returns: { tag, nodeId, publicKey, displayName, avatar, online }
     */
    async function resolveTag(tag) {
        const validation = _validateTag(tag);
        if (!validation.valid) return { error: validation.error };

        const token = _getAuthToken();
        if (!token) return { error: 'Authentication required.' };

        try {
            const res = await fetch(`${_getApiUrl()}/ghosttag/resolve/${validation.tag}`, {
                method: 'GET',
                headers: { 'Authorization': `Bearer ${token}` },
                signal: AbortSignal.timeout(5000),
            });

            if (res.ok) return await res.json();
            if (res.status === 404) return { error: 'GhostTag not found.' };
            return { error: 'Server error.' };
        } catch (e) {
            return { error: 'Cannot reach server. Try again later.' };
        }
    }

    /**
     * Release the current user's GhostTag on the server.
     * Called when the user deletes their identity/account.
     * The released tag becomes available for other users.
     */
    async function releaseTag() {
        const token = _getAuthToken();

        // Always clear locally
        const localTag = getLocalTag();
        _clearLocalTag();

        if (!token) {
            console.warn('[GhostTag] No auth token to release tag on server. Local tag cleared.');
            return { success: true, released: localTag ? '@' + localTag : null, localOnly: true };
        }

        try {
            const res = await fetch(`${_getApiUrl()}/ghosttag/release`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                },
                signal: AbortSignal.timeout(5000),
            });

            if (res.ok) {
                const data = await res.json();
                console.log(`[GhostTag] Released ${data.released}`);
                return { success: true, released: data.released };
            }

            return { success: false, error: 'Failed to release tag on server.' };
        } catch (e) {
            console.warn('[GhostTag] Failed to release tag on server:', e.message);
            // Local is already cleared — server will be out of sync
            // but the user's identity is being destroyed so it will be cleaned up
            return { success: true, released: localTag ? '@' + localTag : null, localOnly: true };
        }
    }

    /**
     * Delete the full identity on the server.
     * Releases the GhostTag + removes user and node data.
     * The tag becomes available to all other users.
     */
    async function deleteIdentity() {
        const token = _getAuthToken();
        const localTag = getLocalTag();

        // Always clear locally
        _clearLocalTag();

        if (!token) {
            console.warn('[GhostTag] No auth token to delete identity on server.');
            return { success: true, releasedTag: localTag ? '@' + localTag : null, localOnly: true };
        }

        try {
            const res = await fetch(`${_getApiUrl()}/identity`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                },
                signal: AbortSignal.timeout(8000),
            });

            if (res.ok) {
                const data = await res.json();
                console.log(`[GhostTag] Identity deleted. Released tag: ${data.releasedTag}`);
                return { success: true, releasedTag: data.releasedTag };
            }

            return { success: false, error: 'Failed to delete identity on server.' };
        } catch (e) {
            console.warn('[GhostTag] Failed to delete identity on server:', e.message);
            return { success: true, releasedTag: localTag ? '@' + localTag : null, localOnly: true };
        }
    }

    // ─── SYNC ENGINE ────────────────────────────────────────────────────────
    // Automatically syncs pending offline claims when the server comes online.

    /**
     * Attempt to sync a pending tag claim with the server.
     * Called automatically when the browser comes online or on a periodic timer.
     */
    async function syncPendingClaim() {
        const pending = getPendingClaim();
        if (!pending) return { noOp: true };

        const token = _getAuthToken();
        if (!token) {
            console.log('[GhostTag Sync] No auth token yet — will retry later.');
            return { deferred: true };
        }

        console.log(`[GhostTag Sync] Attempting to sync pending claim: @${pending.tag}`);

        try {
            const res = await fetch(`${_getApiUrl()}/ghosttag/claim`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`,
                },
                body: JSON.stringify({
                    tag: pending.tag,
                    nodeId: pending.nodeId,
                    publicKey: pending.publicKey,
                    displayName: pending.displayName,
                }),
                signal: AbortSignal.timeout(8000),
            });

            if (res.ok) {
                const data = await res.json();
                _clearPendingClaim();
                _saveLocalTag(pending.tag);
                console.log(`[GhostTag Sync] ✓ Successfully synced ${data.tag}`);
                _dispatchSyncEvent('synced', pending.tag);
                return { success: true, tag: data.tag };
            }

            const errorData = await res.json().catch(() => ({}));

            if (res.status === 409) {
                // Conflict during sync
                if (errorData.yourTag) {
                    // User already has a tag on server — use server's version
                    const serverTag = errorData.yourTag.replace(/^@/, '');
                    _saveLocalTag(serverTag);
                    _clearPendingClaim();
                    console.log(`[GhostTag Sync] User already has tag on server: ${errorData.yourTag}`);
                    _dispatchSyncEvent('synced', serverTag);
                    return { success: true, tag: errorData.yourTag, serverOverride: true };
                }
                
                // Tag was taken by someone else while offline
                _clearPendingClaim();
                _clearLocalTag();
                console.error(`[GhostTag Sync] ✗ Tag @${pending.tag} was claimed by another user while offline!`);
                
                // Store conflict info for UI to display
                localStorage.setItem(STORAGE_KEY_SYNC_CONFLICT, JSON.stringify({
                    tag: pending.tag,
                    suggestions: errorData.suggestions || [],
                    detectedAt: Date.now(),
                }));
                
                _dispatchSyncEvent('conflict', pending.tag, errorData.suggestions);
                return { success: false, conflict: true, tag: pending.tag, suggestions: errorData.suggestions };
            }

            // Other server error — keep pending, retry later
            console.warn(`[GhostTag Sync] Server returned ${res.status} — will retry.`);
            return { deferred: true };
        } catch (e) {
            // Still offline — keep pending
            console.log('[GhostTag Sync] Still offline — will retry later.');
            return { deferred: true };
        }
    }

    /**
     * Dispatch a custom event so the UI can react to sync results.
     */
    function _dispatchSyncEvent(status, tag, suggestions) {
        window.dispatchEvent(new CustomEvent('ghosttag:sync', {
            detail: { status, tag, suggestions },
        }));
    }

    /**
     * Start the background sync watcher.
     * Runs every 15 seconds while there's a pending claim.
     * Automatically stops when the claim is resolved.
     */
    function startSyncWatcher() {
        if (_syncInterval) return; // Already running

        // Listen for online/offline events
        window.addEventListener('online', _onOnline);
        window.addEventListener('offline', _onOffline);

        _syncInterval = setInterval(async () => {
            const pending = getPendingClaim();
            if (!pending) {
                // No pending claim — stop the watcher
                stopSyncWatcher();
                return;
            }
            if (!navigator.onLine) return; // Don't attempt if known offline

            await syncPendingClaim();
        }, 15_000);

        // Attempt an immediate sync
        if (navigator.onLine && getPendingClaim()) {
            setTimeout(() => syncPendingClaim(), 1000);
        }

        console.log('[GhostTag] Sync watcher started.');
    }

    /**
     * Stop the background sync watcher.
     */
    function stopSyncWatcher() {
        if (_syncInterval) {
            clearInterval(_syncInterval);
            _syncInterval = null;
        }
        window.removeEventListener('online', _onOnline);
        window.removeEventListener('offline', _onOffline);
        console.log('[GhostTag] Sync watcher stopped.');
    }

    function _onOnline() {
        _isOnline = true;
        console.log('[GhostTag] Network restored — triggering sync...');
        syncPendingClaim();
    }

    function _onOffline() {
        _isOnline = false;
        console.log('[GhostTag] Network lost.');
    }

    // ─── CONFLICT RESOLUTION ────────────────────────────────────────────────

    /**
     * Check if there's an unresolved sync conflict (tag taken while offline).
     * Returns the conflict data or null.
     */
    function getSyncConflict() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY_SYNC_CONFLICT);
            if (!raw) return null;
            return JSON.parse(raw);
        } catch (_) {
            return null;
        }
    }

    /**
     * Clear the sync conflict after the user has been notified or chosen a new tag.
     */
    function clearSyncConflict() {
        localStorage.removeItem(STORAGE_KEY_SYNC_CONFLICT);
    }

    // ─── INVITE LINK HELPERS ────────────────────────────────────────────────

    /**
     * Generate an invite link for the current user's GhostTag.
     */
    function getInviteLink(tag) {
        const normalized = _normalizeTag(tag || getLocalTag());
        if (!normalized) return null;
        return `ghostnet.n11x.dev/invite/@${normalized}`;
    }

    /**
     * Generate a shareable text for the current user's GhostTag.
     */
    function getShareText(tag) {
        const normalized = _normalizeTag(tag || getLocalTag());
        if (!normalized) return null;
        return `Connect with me on GhostNet: @${normalized}\n${getInviteLink(normalized)}`;
    }

    // ─── STATUS ─────────────────────────────────────────────────────────────

    /**
     * Get the current GhostTag status for the UI.
     */
    function getStatus() {
        const localTag = getLocalTag();
        const pending = getPendingClaim();
        const conflict = getSyncConflict();

        if (conflict) {
            return {
                status: 'conflict',
                tag: conflict.tag ? '@' + conflict.tag : null,
                message: `Your tag @${conflict.tag} was claimed by another user while you were offline.`,
                suggestions: conflict.suggestions,
            };
        }

        if (pending) {
            return {
                status: 'pending',
                tag: '@' + pending.tag,
                message: 'Tag claim is pending — will sync when server is reachable.',
            };
        }

        if (localTag) {
            return {
                status: 'active',
                tag: '@' + localTag,
                message: 'Your GhostTag is active and synced.',
            };
        }

        return {
            status: 'none',
            tag: null,
            message: 'No GhostTag claimed.',
        };
    }

    // ─── PUBLIC API ─────────────────────────────────────────────────────────

    return {
        // Core operations
        checkAvailability,
        claimTag,
        resolveTag,
        releaseTag,
        deleteIdentity,

        // Local storage
        getLocalTag,

        // Offline sync
        getPendingClaim,
        syncPendingClaim,
        startSyncWatcher,
        stopSyncWatcher,

        // Conflict resolution
        getSyncConflict,
        clearSyncConflict,

        // UI helpers
        getInviteLink,
        getShareText,
        getStatus,

        // Validation
        validate: _validateTag,
        normalize: _normalizeTag,
    };
})();
