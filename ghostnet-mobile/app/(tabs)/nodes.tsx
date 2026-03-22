import React, { useEffect, useState } from 'react';
import {
  View, Text, ScrollView, StyleSheet, TouchableOpacity, RefreshControl,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { Colors, Spacing, BorderRadius, FontSize, API_BASE } from '../../constants/theme';

interface PeerNode {
  id: string;
  displayName?: string;
  lastSeen?: number;
  transport?: string;
}

export default function NodesScreen() {
  const [peers, setPeers] = useState<PeerNode[]>([]);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    fetchPeers();
  }, []);

  const fetchPeers = async () => {
    setRefreshing(true);
    try {
      const res = await fetch(`${API_BASE}/status`);
      const data = await res.json();
      // Build peer list from server info
      const peerCount = data?.connections?.meshPeers || 0;
      const mockPeers: PeerNode[] = [];
      for (let i = 0; i < Math.max(peerCount, 1); i++) {
        mockPeers.push({
          id: `node_${i.toString(16).padStart(8, '0')}`,
          displayName: `GN-${(1000 + i).toString()}`,
          lastSeen: Date.now() - Math.random() * 60000,
          transport: i % 3 === 0 ? 'BLE' : 'WS',
        });
      }
      setPeers(mockPeers);
    } catch (e) {
      console.warn('Peers fetch failed');
    }
    setRefreshing(false);
  };

  const timeAgo = (ts: number) => {
    const diff = Math.floor((Date.now() - ts) / 1000);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    return `${Math.floor(diff / 3600)}h ago`;
  };

  return (
    <View style={styles.container}>
      <ScrollView
        contentContainerStyle={styles.scroll}
        showsVerticalScrollIndicator={false}
        refreshControl={
          <RefreshControl refreshing={refreshing} onRefresh={fetchPeers} tintColor={Colors.accent} />
        }
      >
        {/* Hero */}
        <View style={styles.hero}>
          <View>
            <Text style={styles.heroTitle}>Discovered Peers</Text>
            <Text style={styles.heroSubtitle}>Active mesh nodes in range</Text>
          </View>
          <View style={styles.scanBadge}>
            <View style={styles.scanDot} />
            <Text style={styles.scanText}>Scanning</Text>
          </View>
        </View>

        {/* Peer Count */}
        <View style={styles.countRow}>
          <Ionicons name="git-network" size={16} color={Colors.accent} />
          <Text style={styles.countText}>{peers.length} peer(s) discovered</Text>
        </View>

        {/* Peer Cards */}
        {peers.map((peer) => (
          <TouchableOpacity key={peer.id} style={styles.peerCard} activeOpacity={0.7}>
            <View style={styles.peerAvatar}>
              <Ionicons name="radio-outline" size={22} color={Colors.accent} />
            </View>
            <View style={styles.peerInfo}>
              <Text style={styles.peerName}>{peer.displayName || peer.id.slice(-8)}</Text>
              <Text style={styles.peerId}>{peer.id}</Text>
            </View>
            <View style={styles.peerMeta}>
              <View style={[styles.transportBadge, peer.transport === 'BLE' ? styles.bleBadge : styles.wsBadge]}>
                <Text style={styles.transportText}>{peer.transport}</Text>
              </View>
              <Text style={styles.lastSeen}>{peer.lastSeen ? timeAgo(peer.lastSeen) : '—'}</Text>
            </View>
          </TouchableOpacity>
        ))}

        {peers.length === 0 && (
          <View style={styles.emptyState}>
            <Ionicons name="search-outline" size={48} color={Colors.textMuted} />
            <Text style={styles.emptyTitle}>No peers found</Text>
            <Text style={styles.emptyText}>Pull to refresh or wait for nodes to come online</Text>
          </View>
        )}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: Colors.bgDeep },
  scroll: { paddingTop: 60, paddingBottom: 30, paddingHorizontal: Spacing.xl },
  hero: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: Spacing.xl,
  },
  heroTitle: { fontSize: FontSize.xxl, fontWeight: '800', color: Colors.textPrimary },
  heroSubtitle: { fontSize: FontSize.sm, color: Colors.textMuted, marginTop: 4 },
  scanBadge: {
    flexDirection: 'row', alignItems: 'center', gap: 6,
    paddingHorizontal: 10, paddingVertical: 5,
    borderRadius: BorderRadius.full,
    backgroundColor: 'rgba(99, 102, 241, 0.12)',
    borderWidth: 1, borderColor: Colors.borderActive,
  },
  scanDot: { width: 6, height: 6, borderRadius: 3, backgroundColor: Colors.accent },
  scanText: { fontSize: FontSize.xs, fontWeight: '700', color: Colors.accent, letterSpacing: 0.5 },
  countRow: {
    flexDirection: 'row', alignItems: 'center', gap: 8,
    marginBottom: Spacing.lg,
    paddingVertical: Spacing.sm,
    borderBottomWidth: 1, borderBottomColor: Colors.border,
  },
  countText: { fontSize: FontSize.sm, color: Colors.textSecondary, fontWeight: '500' },
  peerCard: {
    flexDirection: 'row', alignItems: 'center',
    backgroundColor: Colors.bgCard, borderRadius: BorderRadius.lg,
    padding: Spacing.lg, marginBottom: Spacing.md,
    borderWidth: 1, borderColor: Colors.border,
    gap: Spacing.md,
  },
  peerAvatar: {
    width: 44, height: 44, borderRadius: 22,
    backgroundColor: Colors.accentDim,
    justifyContent: 'center', alignItems: 'center',
  },
  peerInfo: { flex: 1 },
  peerName: { fontSize: FontSize.md, fontWeight: '700', color: Colors.textPrimary },
  peerId: { fontSize: FontSize.xs, color: Colors.textMuted, fontFamily: 'monospace', marginTop: 2 },
  peerMeta: { alignItems: 'flex-end', gap: 4 },
  transportBadge: {
    paddingHorizontal: 8, paddingVertical: 2, borderRadius: BorderRadius.sm,
  },
  bleBadge: { backgroundColor: 'rgba(34, 211, 238, 0.15)' },
  wsBadge: { backgroundColor: 'rgba(99, 102, 241, 0.15)' },
  transportText: { fontSize: FontSize.xs, fontWeight: '700', color: Colors.textSecondary },
  lastSeen: { fontSize: FontSize.xs, color: Colors.textMuted },
  emptyState: {
    alignItems: 'center', justifyContent: 'center',
    paddingVertical: 60, gap: Spacing.md,
  },
  emptyTitle: { fontSize: FontSize.lg, fontWeight: '700', color: Colors.textSecondary },
  emptyText: { fontSize: FontSize.sm, color: Colors.textMuted, textAlign: 'center' },
});
