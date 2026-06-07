/**
 * GhostNet Call UI
 * ================
 *
 * Thin UI controller that wires the GhostCall SDK into the running web app:
 *   - constructs a GhostCall from the live app (mesh + secp256k1 identity +
 *     Cloudflare TURN provider + GhostTag resolvers),
 *   - adds a "Call" button to the chat header,
 *   - shows an incoming-call prompt, an in-call bar, and plays remote audio.
 *
 * Calls are addressed by @GhostTag (Option A): the callee's identity key is
 * resolved from their GhostTag so the DTLS fingerprint can be verified. It does
 * NOT change call signaling, the state machine, or fingerprint verification —
 * it only drives the existing GhostCall API + events.
 */

(function () {
    'use strict';
    if (typeof window === 'undefined') return;

    var _call = null;          // GhostCall instance (constructed once, when unlocked)
    var _building = null;      // in-flight construction promise
    var _timer = null;         // in-call elapsed timer
    var _startedAt = 0;

    // ─── identity / construction ────────────────────────

    function _stored() {
        try { return window.GhostIdentity && GhostIdentity.getStoredIdentity ? GhostIdentity.getStoredIdentity() : null; }
        catch (_) { return null; }
    }

    function _ready() {
        return !!(window.GhostCall && window.GhostCallIce && window.app && window.app.mesh);
    }

    // Build the GhostCall once. Requires an UNLOCKED identity (private key) so it
    // can sign DTLS fingerprints. Constructed early so incoming offers are caught.
    async function _ensureCall() {
        if (_call) return _call;
        if (_building) return _building;
        if (!_ready()) throw new Error('Call modules or mesh not ready yet.');
        const stored = _stored();
        if (!stored || !stored.nodeId || !stored.publicKey) throw new Error('No identity — sign in first.');
        const pk = window.GhostIdentity && GhostIdentity.getSessionPrivateKey
            ? await GhostIdentity.getSessionPrivateKey().catch(function () { return null; })
            : null;
        if (!pk) throw new Error('locked');

        _building = (async function () {
            const call = new window.GhostCall({
                mesh: window.app.mesh,
                identity: { id: stored.nodeId, publicKey: stored.publicKey, privateKey: pk },
                getIceServers: window.GhostCallIce.createCloudflareIceProvider({}),
                // Resolve the callee's identity key from their GhostTag (Option A).
                resolveGhostTag: async function (tag) {
                    const r = await window.GhostTag.resolveTag(_normTag(tag));
                    if (!r || r.error || !r.publicKey) throw new Error((r && r.error) || 'GhostTag not found');
                    return { routeId: r.nodeId || r.id || tag, publicKey: r.publicKey };
                },
                // Verify an INCOMING caller's key. Prefer independent GhostTag
                // resolution; fall back to the key in the (mesh-authenticated)
                // signed offer so calls work before the caller has a GhostTag.
                resolveIdentityKey: async function (peerId, msg) {
                    try {
                        const r = await window.GhostTag.resolveTag(_normTag(peerId));
                        if (r && r.publicKey) return r.publicKey;
                    } catch (_) { /* fall through */ }
                    return (msg && msg.fp && msg.fp.pub) ? msg.fp.pub : null;
                },
            });
            _wireEvents(call);
            _call = call;
            _building = null;
            return call;
        })();
        return _building;
    }

    function _normTag(t) {
        t = String(t || '').trim();
        return t.charAt(0) === '@' ? t.slice(1) : t;
    }

    // ─── event wiring → UI ──────────────────────────────

    function _wireEvents(call) {
        call.on('incoming', function (e) { _showIncoming(e); });
        call.on('ringing', function (e) { _showBar('Calling ' + (e.peer || '') + '…', true); });
        call.on('connected', function (e) {
            if (e && e.remoteStream) _attachAudio(e.remoteStream);
            _startedAt = Date.now();
            _showBar('Connected', true);
            _startTimer();
        });
        call.on('ended', function (e) {
            _stopTimer();
            _detachAudio();
            _hideIncoming();
            _toast('Call ended' + (e && e.reason && e.reason !== 'normal' ? ' (' + e.reason + ')' : ''));
            _hideBar();
        });
        call.on('error', function (e) {
            _stopTimer();
            _hideIncoming();
            _hideBar();
            var msg = (e && e.message) ? e.message : 'Call error';
            if (e && e.code === 'mic-permission') msg = 'Microphone blocked. Grant mic access and try again.';
            if (e && e.code === 'ice') msg = 'Could not get a relay (TURN) — call not started.';
            _toast(msg, 5000);
        });
    }

    // ─── public actions ─────────────────────────────────

    async function startCall(tagArg) {
        var tag = tagArg || _currentPeerTag();
        if (!tag) {
            tag = window.prompt('Call which @GhostTag?', _currentPeerTag() || '@');
            if (!tag) return;
        }
        try {
            var call = await _ensureCall();
            _showBar('Calling ' + _normTag(tag) + '…', true);
            await call.startCall(_normTag(tag));
        } catch (err) {
            _hideBar();
            if (err && err.message === 'locked') {
                _toast('Unlock with your PIN first, then call.', 4000);
                if (typeof window.ghostnetEnsureAuth === 'function') window.ghostnetEnsureAuth();
            } else {
                _toast(err && err.message ? err.message : 'Could not start call', 5000);
            }
        }
    }

    async function acceptCall() {
        try { var call = await _ensureCall(); await call.acceptCall(); _hideIncoming(); _showBar('Connecting…', true); }
        catch (err) { _toast(err && err.message ? err.message : 'Could not accept', 4000); }
    }

    function rejectCall() { try { if (_call) _call.rejectCall(); } catch (_) {} _hideIncoming(); }
    function endCall() { try { if (_call) _call.endCall(); } catch (_) {} _hideBar(); }

    // Best-effort: use the open chat's contact name if it looks like a @GhostTag.
    function _currentPeerTag() {
        var name = window.app && window.app.chatContactName;
        if (name && /^@?[a-zA-Z0-9_]{2,}$/.test(String(name))) return String(name);
        return null;
    }

    // ─── chat-header call button ────────────────────────

    function _mountCallButton() {
        var header = document.querySelector('.chat-header-info');
        if (!header || document.getElementById('ghost-call-btn')) return;
        var btn = document.createElement('button');
        btn.id = 'ghost-call-btn';
        btn.type = 'button';
        btn.textContent = 'Call';
        btn.style.cssText = 'margin-left:8px;padding:4px 12px;border:none;border-radius:14px;'
            + 'background:#22c55e;color:#fff;font-size:0.8rem;font-weight:600;cursor:pointer;';
        btn.addEventListener('click', function () { startCall(); });
        header.appendChild(btn);
    }

    // ─── overlays (built dynamically, no markup edits) ──

    function _bar() {
        var bar = document.getElementById('ghost-call-bar');
        if (bar) return bar;
        bar = document.createElement('div');
        bar.id = 'ghost-call-bar';
        bar.style.cssText = 'position:fixed;left:50%;bottom:18px;transform:translateX(-50%);z-index:1000000;'
            + 'display:none;align-items:center;gap:14px;padding:10px 18px;border-radius:28px;'
            + 'background:#0b1020;color:#e6edf6;box-shadow:0 6px 24px rgba(0,0,0,.4);font-size:0.9rem;';
        var label = document.createElement('span');
        label.id = 'ghost-call-bar-label';
        var end = document.createElement('button');
        end.textContent = 'End';
        end.style.cssText = 'padding:6px 14px;border:none;border-radius:16px;background:#ef4444;color:#fff;'
            + 'font-weight:600;cursor:pointer;';
        end.addEventListener('click', endCall);
        bar.appendChild(label);
        bar.appendChild(end);
        document.body.appendChild(bar);
        return bar;
    }
    function _showBar(text, show) {
        var bar = _bar();
        document.getElementById('ghost-call-bar-label').textContent = text;
        bar.style.display = show ? 'flex' : 'none';
    }
    function _hideBar() { var bar = document.getElementById('ghost-call-bar'); if (bar) bar.style.display = 'none'; }

    function _startTimer() {
        _stopTimer();
        _timer = setInterval(function () {
            var s = Math.floor((Date.now() - _startedAt) / 1000);
            var mm = String(Math.floor(s / 60)).padStart(2, '0');
            var ss = String(s % 60).padStart(2, '0');
            var l = document.getElementById('ghost-call-bar-label');
            if (l) l.textContent = 'Connected  ' + mm + ':' + ss;
        }, 1000);
    }
    function _stopTimer() { if (_timer) { clearInterval(_timer); _timer = null; } }

    function _showIncoming(e) {
        _hideIncoming();
        var ov = document.createElement('div');
        ov.id = 'ghost-call-incoming';
        ov.style.cssText = 'position:fixed;inset:0;z-index:1000001;display:flex;align-items:center;'
            + 'justify-content:center;background:rgba(2,4,20,.6);';
        var card = document.createElement('div');
        card.style.cssText = 'background:#0b1020;color:#e6edf6;padding:24px 28px;border-radius:16px;'
            + 'text-align:center;min-width:260px;box-shadow:0 10px 40px rgba(0,0,0,.5);';
        var title = document.createElement('div');
        title.textContent = 'Incoming call';
        title.style.cssText = 'font-size:1.05rem;font-weight:700;margin-bottom:6px;';
        var who = document.createElement('div');
        who.textContent = 'from ' + ((e && e.from) ? String(e.from).slice(0, 16) : 'unknown');
        who.style.cssText = 'opacity:.7;font-size:0.82rem;margin-bottom:18px;word-break:break-all;';
        var row = document.createElement('div');
        row.style.cssText = 'display:flex;gap:12px;justify-content:center;';
        var acc = document.createElement('button');
        acc.textContent = 'Accept';
        acc.style.cssText = 'padding:8px 18px;border:none;border-radius:18px;background:#22c55e;color:#fff;font-weight:600;cursor:pointer;';
        acc.addEventListener('click', acceptCall);
        var rej = document.createElement('button');
        rej.textContent = 'Decline';
        rej.style.cssText = 'padding:8px 18px;border:none;border-radius:18px;background:#ef4444;color:#fff;font-weight:600;cursor:pointer;';
        rej.addEventListener('click', rejectCall);
        row.appendChild(acc); row.appendChild(rej);
        card.appendChild(title); card.appendChild(who); card.appendChild(row);
        ov.appendChild(card);
        document.body.appendChild(ov);
    }
    function _hideIncoming() { var ov = document.getElementById('ghost-call-incoming'); if (ov) ov.remove(); }

    function _attachAudio(stream) {
        var a = document.getElementById('ghost-call-audio');
        if (!a) {
            a = document.createElement('audio');
            a.id = 'ghost-call-audio';
            a.autoplay = true;
            a.style.display = 'none';
            document.body.appendChild(a);
        }
        a.srcObject = stream;
        var p = a.play(); if (p && p.catch) p.catch(function () {});
    }
    function _detachAudio() {
        var a = document.getElementById('ghost-call-audio');
        if (a) { try { a.srcObject = null; } catch (_) {} }
    }

    function _toast(msg, ms) {
        if (typeof window.showToast === 'function') { window.showToast(msg, ms || 3000); return; }
        var t = document.createElement('div');
        t.textContent = msg;
        t.style.cssText = 'position:fixed;left:50%;top:18px;transform:translateX(-50%);z-index:1000002;'
            + 'background:#0b1020;color:#e6edf6;padding:10px 16px;border-radius:12px;font-size:0.85rem;'
            + 'box-shadow:0 6px 24px rgba(0,0,0,.4);max-width:80vw;text-align:center;';
        document.body.appendChild(t);
        setTimeout(function () { t.remove(); }, ms || 3000);
    }

    // ─── bootstrap ──────────────────────────────────────

    function _boot() {
        _mountCallButton();
        // Re-mount the button whenever the chat view re-renders.
        var mo = new MutationObserver(function () { _mountCallButton(); });
        try { mo.observe(document.body, { childList: true, subtree: true }); } catch (_) {}
        // Construct the call engine once the identity is unlocked so incoming
        // offers are caught even before the user places a call.
        function tryBuild() { if (_ready() && _stored()) _ensureCall().catch(function () {}); }
        window.addEventListener('identity:updated', tryBuild);
        window.addEventListener('ghostnet:auth-ready', tryBuild);
        setTimeout(tryBuild, 1500);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _boot);
    } else {
        _boot();
    }

    window.GhostCallUI = { startCall: startCall, acceptCall: acceptCall, rejectCall: rejectCall, endCall: endCall };
})();
