(function () {
  'use strict';

  const OFFLINE_ORIGIN = 'https://kryptos-offline.local';
  const STORE_KEY = 'kryptos_offline_store_v1';
  const PROFILE_CACHE_KEY = 'kryptos_profile_cache';
  const USER_CACHE_KEY = 'kryptos_user';

  window.__KRYPTOS_OFFLINE__ = true;
  window.__KRYPTOS_BACKEND__ = OFFLINE_ORIGIN;
  window.BACKEND = {
    http: OFFLINE_ORIGIN,
    ws: 'wss://kryptos-offline.local/ws',
    url: (path) => `${OFFLINE_ORIGIN}${path}`
  };

  const originalFetch = window.fetch.bind(window);

  function clone(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  function readIdentity() {
    try {
      const raw = localStorage.getItem('kryptos_identity');
      return raw ? JSON.parse(raw) : null;
    } catch (_) {
      return null;
    }
  }

  function randomToken(seed) {
    const safeSeed = String(seed || 'ghost').replace(/[^a-z0-9]/gi, '').slice(0, 24) || 'ghost';
    return `offline.${safeSeed}.${Date.now().toString(36)}`;
  }

  function normalizeTag(tag) {
    return String(tag || '').trim().replace(/^@/, '').toLowerCase();
  }

  function normalizeCode(code) {
    return String(code || '').trim().toUpperCase();
  }

  function shortCodeFor(nodeId, displayName) {
    const seed = String(nodeId || displayName || 'kryptos');
    let hash = 0;
    for (let i = 0; i < seed.length; i += 1) {
      hash = ((hash << 5) - hash + seed.charCodeAt(i)) | 0;
    }
    const code = Math.abs(hash).toString(36).toUpperCase().replace(/[^A-Z0-9]/g, '').padEnd(6, '0');
    return `GN-${code.slice(0, 6)}`;
  }

  function readStore() {
    try {
      const raw = localStorage.getItem(STORE_KEY);
      if (raw) return JSON.parse(raw);
    } catch (_) {}

    return {
      conversations: {},
      messages: {},
      profiles: {},
      ghostTags: {},
      nodes: {},
      shortCodes: {}
    };
  }

  function writeStore(store) {
    localStorage.setItem(STORE_KEY, JSON.stringify(store));
    return store;
  }

  function inferCurrentUser() {
    const identity = readIdentity();
    if (identity && (identity.nodeId || identity.id)) {
      return identity.nodeId || identity.id;
    }
    try {
      const user = JSON.parse(localStorage.getItem(USER_CACHE_KEY) || 'null');
      if (user && (user.nodeId || user.id)) return user.nodeId || user.id;
    } catch (_) {}
    return localStorage.getItem('kryptos_node_id') || localStorage.getItem('kryptos_user_id') || 'local-user';
  }

  function convoKey(a, b) {
    const left = String(a || 'unknown');
    const right = String(b || 'unknown');
    return [left, right].sort().join('::');
  }

  function safeJsonParse(text) {
    if (!text) return {};
    try {
      return JSON.parse(text);
    } catch (_) {
      return {};
    }
  }

  async function parseBody(options) {
    if (!options || !options.body) return {};
    if (typeof options.body === 'string') return safeJsonParse(options.body);
    return {};
  }

  function responseJson(data, status = 200) {
    return new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  function responseText(data, status = 200) {
    return new Response(String(data), {
      status,
      headers: { 'Content-Type': 'text/plain' }
    });
  }

  function ensureProfile(store, identity) {
    const source = identity || readIdentity() || {};
    const userId = source.nodeId || source.id || inferCurrentUser();
    const existing = store.profiles[userId] || {};
    const profile = {
      id: userId,
      nodeId: userId,
      displayName: source.displayName || existing.displayName || 'Ghost User',
      username: source.displayName || existing.username || 'Ghost User',
      address: source.address || existing.address || '',
      publicKey: source.publicKey || existing.publicKey || source.address || '',
      ghostTag: source.ghostTag || existing.ghostTag || '',
      avatar: existing.avatar || ''
    };
    store.profiles[userId] = profile;
    store.nodes[userId] = {
      nodeId: userId,
      displayName: profile.displayName,
      publicKey: profile.publicKey,
      address: profile.address,
      avatar: profile.avatar,
      shortCode: shortCodeFor(userId, profile.displayName)
    };
    store.shortCodes[store.nodes[userId].shortCode] = userId;
    localStorage.setItem(PROFILE_CACHE_KEY, JSON.stringify(profile));
    localStorage.setItem(USER_CACHE_KEY, JSON.stringify(profile));
    return profile;
  }

  async function handleOfflineApi(requestUrl, options) {
    const url = new URL(requestUrl, OFFLINE_ORIGIN);
    const path = url.pathname;
    const method = String(options?.method || 'GET').toUpperCase();
    const store = readStore();
    const currentIdentity = readIdentity();
    const currentProfile = ensureProfile(store, currentIdentity);

    if (path === '/health') {
      writeStore(store);
      return responseJson({ ok: true, offline: true, mode: 'standalone' });
    }

    if (path === '/auth/node' && method === 'POST') {
      const body = await parseBody(options);
      const nodeId = body.nodeId || currentProfile.nodeId || inferCurrentUser();
      ensureProfile(store, {
        ...currentProfile,
        nodeId,
        id: nodeId,
        publicKey: body.publicKey || currentProfile.publicKey
      });
      writeStore(store);
      return responseJson({ token: randomToken(nodeId), offline: true });
    }

    if (path === '/auth/logout') {
      return responseJson({ success: true, offline: true });
    }

    if (path === '/user/profile' && method === 'GET') {
      writeStore(store);
      return responseJson(clone(currentProfile));
    }

    if (path === '/user/profile' && (method === 'PATCH' || method === 'POST' || method === 'PUT')) {
      const body = await parseBody(options);
      const merged = {
        ...currentProfile,
        displayName: body.displayName || currentProfile.displayName,
        username: body.displayName || currentProfile.username,
        avatar: body.avatar || currentProfile.avatar
      };
      store.profiles[currentProfile.nodeId] = merged;
      store.nodes[currentProfile.nodeId] = {
        ...store.nodes[currentProfile.nodeId],
        displayName: merged.displayName,
        avatar: merged.avatar,
        shortCode: shortCodeFor(merged.nodeId, merged.displayName)
      };
      store.shortCodes[store.nodes[currentProfile.nodeId].shortCode] = currentProfile.nodeId;
      writeStore(store);
      localStorage.setItem(PROFILE_CACHE_KEY, JSON.stringify(merged));
      localStorage.setItem(USER_CACHE_KEY, JSON.stringify(merged));
      return responseJson({ user: clone(merged), offline: true });
    }

    if (path === '/user/shortcode' && method === 'GET') {
      const nodeId = url.searchParams.get('nodeId') || currentProfile.nodeId;
      const displayName = url.searchParams.get('displayName') || currentProfile.displayName;
      const shortCode = shortCodeFor(nodeId, displayName);
      store.shortCodes[shortCode] = nodeId;
      writeStore(store);
      return responseJson({ shortCode, nodeId, displayName, offline: true });
    }

    if (path.startsWith('/resolve/') && method === 'GET') {
      const code = normalizeCode(decodeURIComponent(path.slice('/resolve/'.length)));
      const nodeId = store.shortCodes[code];
      if (!nodeId) return responseJson({ error: 'Not found' }, 404);
      const profile = store.profiles[nodeId] || store.nodes[nodeId] || {};
      return responseJson({
        nodeId,
        displayName: profile.displayName || profile.username || 'Ghost User',
        shortCode: code,
        publicKey: profile.publicKey || ''
      });
    }

    if (path.startsWith('/ghosttag/check/') && method === 'GET') {
      const tag = normalizeTag(decodeURIComponent(path.slice('/ghosttag/check/'.length)));
      const owner = store.ghostTags[tag];
      const available = !owner || owner.nodeId === currentProfile.nodeId;
      writeStore(store);
      return responseJson({ available, tag: `@${tag}`, offline: true });
    }

    if ((path === '/ghosttag/claim' || path === '/ghosttag/release') && method === 'POST') {
      const body = await parseBody(options);
      const tag = normalizeTag(body.tag || currentProfile.ghostTag);
      if (!tag) return responseJson({ error: 'Tag required' }, 400);

      if (path === '/ghosttag/release') {
        delete store.ghostTags[tag];
        if (store.profiles[currentProfile.nodeId]) store.profiles[currentProfile.nodeId].ghostTag = '';
        writeStore(store);
        return responseJson({ success: true, released: true, tag: `@${tag}`, offline: true });
      }

      const existing = store.ghostTags[tag];
      if (existing && existing.nodeId !== currentProfile.nodeId) {
        return responseJson({
          error: 'GhostTag already taken.',
          suggestions: [`${tag}_1`, `${tag}_${Math.floor(Math.random() * 90 + 10)}`]
        }, 409);
      }

      store.ghostTags[tag] = {
        nodeId: body.nodeId || currentProfile.nodeId,
        publicKey: body.publicKey || currentProfile.publicKey,
        displayName: body.displayName || currentProfile.displayName
      };
      if (store.profiles[currentProfile.nodeId]) {
        store.profiles[currentProfile.nodeId].ghostTag = tag;
      }
      writeStore(store);
      return responseJson({ success: true, tag: `@${tag}`, offline: true });
    }

    if (path.startsWith('/ghosttag/resolve/') && method === 'GET') {
      const tag = normalizeTag(decodeURIComponent(path.slice('/ghosttag/resolve/'.length)));
      const owner = store.ghostTags[tag];
      if (!owner) return responseJson({ error: 'Not found' }, 404);
      return responseJson({
        tag: `@${tag}`,
        nodeId: owner.nodeId,
        publicKey: owner.publicKey || '',
        displayName: owner.displayName || 'Ghost User',
        offline: true
      });
    }

    if (path === '/identity' && method === 'DELETE') {
      const tag = normalizeTag(currentProfile.ghostTag);
      if (tag) delete store.ghostTags[tag];
      delete store.profiles[currentProfile.nodeId];
      delete store.nodes[currentProfile.nodeId];
      writeStore(store);
      return responseJson({ success: true, offline: true });
    }

    if (path === '/register-node' && method === 'POST') {
      const body = await parseBody(options);
      const nodeId = body.nodeId || currentProfile.nodeId;
      store.nodes[nodeId] = {
        nodeId,
        displayName: body.displayName || currentProfile.displayName,
        publicKey: body.publicKey || currentProfile.publicKey,
        address: body.address || currentProfile.address,
        avatar: body.avatar || currentProfile.avatar,
        shortCode: shortCodeFor(nodeId, body.displayName || currentProfile.displayName)
      };
      store.shortCodes[store.nodes[nodeId].shortCode] = nodeId;
      writeStore(store);
      return responseJson({ success: true, offline: true, node: clone(store.nodes[nodeId]) });
    }

    if (path === '/message' && method === 'POST') {
      const body = await parseBody(options);
      const senderId = body.senderId || currentProfile.nodeId;
      const receiverId = body.receiverId || 'broadcast';
      const convoId = convoKey(senderId, receiverId);
      const timestamp = Date.now();
      const message = {
        id: body.id || `msg_${timestamp.toString(36)}`,
        senderId,
        receiverId,
        content: body.content,
        contactName: body.contactName || '',
        encrypted: !!body.encrypted,
        created: timestamp,
        updated: timestamp
      };
      const messages = store.messages[convoId] || [];
      messages.push(message);
      store.messages[convoId] = messages;
      store.conversations[convoId] = {
        id: convoId,
        participants: [senderId, receiverId],
        updated: timestamp
      };
      writeStore(store);
      return responseJson({
        success: true,
        message: clone(message),
        convo: { id: convoId },
        offline: true
      });
    }

    if (path === '/conversations' && method === 'GET') {
      const userId = url.searchParams.get('userId') || currentProfile.nodeId;
      const convos = Object.values(store.conversations)
        .filter((convo) => Array.isArray(convo.participants) && convo.participants.includes(userId))
        .map((convo) => {
          const otherId = convo.participants.find((id) => id !== userId) || userId;
          const otherProfile = store.profiles[otherId] || store.nodes[otherId] || {};
          const convoMessages = store.messages[convo.id] || [];
          const lastMessage = convoMessages[convoMessages.length - 1];
          return {
            id: convo.id,
            updated: convo.updated || (lastMessage ? lastMessage.updated : Date.now()),
            lastMessage: lastMessage ? lastMessage.content : '',
            otherUser: {
              id: otherId,
              nodeId: otherId,
              username: otherProfile.displayName || otherProfile.username || (otherId === 'broadcast' ? 'Broadcast' : otherId),
              displayName: otherProfile.displayName || otherProfile.username || (otherId === 'broadcast' ? 'Broadcast' : otherId),
              address: otherProfile.address || '',
              avatar: otherProfile.avatar || ''
            }
          };
        })
        .sort((a, b) => (b.updated || 0) - (a.updated || 0));
      writeStore(store);
      return responseJson(convos);
    }

    if (path === '/history' && method === 'GET') {
      const convoId = url.searchParams.get('convoId') || '';
      return responseJson(clone(store.messages[convoId] || []));
    }

    if (path === '/analytics/event') {
      return responseJson({ queued: true, offline: true }, 202);
    }

    if (path === '/wallet/send' && method === 'POST') {
      return responseJson({ success: true, txid: `offline_${Date.now().toString(36)}`, offline: true });
    }

    return null;
  }

  window.fetch = async function offlineFetch(input, options) {
    const requestUrl = typeof input === 'string' ? input : input?.url;
    if (!requestUrl) return originalFetch(input, options);

    const shouldIntercept =
      requestUrl.includes('kryptos-ji-production.up.railway.app') ||
      requestUrl.includes('kryptos-offline.local') ||
      requestUrl.startsWith('/message') ||
      requestUrl.startsWith('/conversations') ||
      requestUrl.startsWith('/history') ||
      requestUrl.startsWith('/resolve/') ||
      requestUrl.includes('/ghosttag/') ||
      requestUrl.includes('/user/profile') ||
      requestUrl.includes('/user/shortcode') ||
      requestUrl.includes('/auth/node') ||
      requestUrl.includes('/auth/logout') ||
      requestUrl.includes('/register-node') ||
      requestUrl.includes('/analytics/event') ||
      requestUrl.includes('/identity') ||
      requestUrl.endsWith('/health') ||
      requestUrl.includes('rpc.ankr.com/eth') ||
      requestUrl.includes('api.mainnet-beta.solana.com') ||
      requestUrl.includes('api.coingecko.com') ||
      requestUrl.includes('api.qrserver.com') ||
      requestUrl.includes('localhost:3001/wallet/send');

    if (requestUrl.includes('rpc.ankr.com/eth')) {
      return responseJson({ jsonrpc: '2.0', id: 1, result: '0x0' });
    }

    if (requestUrl.includes('api.mainnet-beta.solana.com')) {
      return responseJson({ jsonrpc: '2.0', id: 1, result: { value: 0 } });
    }

    if (requestUrl.includes('api.coingecko.com')) {
      return responseJson({
        ethereum: { usd: 0 },
        bitcoin: { usd: 0 },
        solana: { usd: 0 },
        tether: { usd: 1 }
      });
    }

    if (requestUrl.includes('api.qrserver.com')) {
      return responseText('');
    }

    if (!shouldIntercept) {
      return originalFetch(input, options);
    }

    const offlineResponse = await handleOfflineApi(requestUrl, options);
    if (offlineResponse) return offlineResponse;
    return responseJson({ error: 'Offline endpoint not implemented', url: requestUrl }, 404);
  };
})();
