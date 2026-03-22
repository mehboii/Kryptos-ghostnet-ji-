import React, { useEffect, useRef, useState } from 'react';
import {
  View, Text, ScrollView, StyleSheet, Animated, Dimensions,
} from 'react-native';
import { LinearGradient } from 'expo-linear-gradient';
import { Ionicons } from '@expo/vector-icons';
import { Colors, Spacing, BorderRadius, FontSize, API_BASE } from '../../constants/theme';

const { width } = Dimensions.get('window');

function PulsingDot() {
  const anim = useRef(new Animated.Value(0.4)).current;
  useEffect(() => {
    Animated.loop(
      Animated.sequence([
        Animated.timing(anim, { toValue: 1, duration: 1000, useNativeDriver: true }),
        Animated.timing(anim, { toValue: 0.4, duration: 1000, useNativeDriver: true }),
      ])
    ).start();
  }, []);
  return <Animated.View style={[styles.pulseDot, { opacity: anim }]} />;
}

interface StatCardProps {
  icon: React.ComponentProps<typeof Ionicons>['name'];
  label: string;
  value: string;
  color: string;
  trend?: 'up' | 'down';
}

function StatCard({ icon, label, value, color, trend }: StatCardProps) {
  return (
    <View style={styles.statCard}>
      <View style={[styles.statIconWrap, { backgroundColor: color + '20' }]}>
        <Ionicons name={icon} size={20} color={color} />
      </View>
      <View style={styles.statInfo}>
        <Text style={styles.statLabel}>{label}</Text>
        <Text style={styles.statValue}>{value}</Text>
      </View>
      {trend && (
        <Ionicons
          name={trend === 'up' ? 'trending-up' : 'trending-down'}
          size={16}
          color={trend === 'up' ? Colors.success : Colors.danger}
        />
      )}
    </View>
  );
}

export default function HomeScreen() {
  const [serverStatus, setServerStatus] = useState<any>(null);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  const fetchStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/status`);
      const data = await res.json();
      setServerStatus(data);
    } catch (e) {
      console.warn('Status fetch failed');
    }
  };

  return (
    <View style={styles.container}>
      <ScrollView contentContainerStyle={styles.scroll} showsVerticalScrollIndicator={false}>
        {/* Hero Header */}
        <View style={styles.hero}>
          <View>
            <Text style={styles.heroTitle}>Mesh Overview</Text>
            <Text style={styles.heroSubtitle}>Live Decentralized Topology</Text>
          </View>
          <View style={styles.badgeRow}>
            <View style={styles.badgeLive}>
              <PulsingDot />
              <Text style={styles.badgeLiveText}>LIVE</Text>
            </View>
            <View style={styles.badge}>
              <Ionicons name="shield-checkmark" size={12} color={Colors.textSecondary} />
              <Text style={styles.badgeText}>E2E</Text>
            </View>
          </View>
        </View>

        {/* Stats Row */}
        <View style={styles.statsRow}>
          <StatCard
            icon="git-network"
            label="Active Nodes"
            value={serverStatus?.connections?.meshPeers?.toString() || '1'}
            color={Colors.electric}
            trend="up"
          />
          <StatCard
            icon="pulse"
            label="Latency"
            value="24ms"
            color={Colors.success}
            trend="down"
          />
          <StatCard
            icon="time"
            label="Uptime"
            value={serverStatus?.uptimeHuman || '99.9%'}
            color={Colors.neonPurple}
            trend="up"
          />
        </View>

        {/* Mesh Visualization Placeholder */}
        <View style={styles.meshWrap}>
          <LinearGradient
            colors={[Colors.bgCard, Colors.bgPanel, Colors.bgDeep]}
            style={styles.meshCanvas}
          >
            {/* Animated mesh nodes */}
            {Array.from({ length: 8 }).map((_, i) => (
              <MeshNode key={i} index={i} />
            ))}
            <View style={styles.meshOverlay}>
              <Text style={styles.meshOverlayTitle}>
                <Ionicons name="globe-outline" size={14} color={Colors.textSecondary} /> Network
              </Text>
              <View style={styles.meshStatRow}>
                <View>
                  <Text style={styles.meshStatLabel}>PEERS</Text>
                  <Text style={styles.meshStatValue}>
                    {serverStatus?.connections?.wsClients || 1}
                  </Text>
                </View>
                <View>
                  <Text style={styles.meshStatLabel}>LATENCY</Text>
                  <Text style={styles.meshStatValue}>24ms</Text>
                </View>
                <View>
                  <Text style={styles.meshStatLabel}>STATUS</Text>
                  <Text style={[styles.meshStatValue, { color: Colors.success }]}>● Online</Text>
                </View>
              </View>
            </View>
          </LinearGradient>
        </View>

        {/* Server Info */}
        {serverStatus && (
          <View style={styles.serverInfoCard}>
            <Text style={styles.sectionTitle}>Server Info</Text>
            <View style={styles.infoRow}>
              <Text style={styles.infoLabel}>Mode</Text>
              <Text style={styles.infoValue}>{serverStatus.mode || 'production'}</Text>
            </View>
            <View style={styles.infoRow}>
              <Text style={styles.infoLabel}>Memory</Text>
              <Text style={styles.infoValue}>{serverStatus.memory?.heap || 0} MB heap</Text>
            </View>
            <View style={styles.infoRow}>
              <Text style={styles.infoLabel}>WS Clients</Text>
              <Text style={styles.infoValue}>{serverStatus.connections?.wsClients || 0}</Text>
            </View>
            <View style={styles.infoRow}>
              <Text style={styles.infoLabel}>Node</Text>
              <Text style={styles.infoValue}>{serverStatus.node || 'N/A'}</Text>
            </View>
          </View>
        )}
      </ScrollView>
    </View>
  );
}

function MeshNode({ index }: { index: number }) {
  const anim = useRef(new Animated.Value(0)).current;
  const angle = (index / 8) * Math.PI * 2;
  const radius = 80;
  const cx = width / 2 - 40;
  const cy = 100;

  useEffect(() => {
    Animated.loop(
      Animated.sequence([
        Animated.timing(anim, { toValue: 1, duration: 2000 + index * 300, useNativeDriver: true }),
        Animated.timing(anim, { toValue: 0, duration: 2000 + index * 300, useNativeDriver: true }),
      ])
    ).start();
  }, []);

  const x = cx + Math.cos(angle) * radius;
  const y = cy + Math.sin(angle) * radius;

  return (
    <Animated.View
      style={[
        styles.meshNode,
        {
          left: x,
          top: y,
          opacity: anim.interpolate({ inputRange: [0, 1], outputRange: [0.3, 1] }),
          transform: [{ scale: anim.interpolate({ inputRange: [0, 1], outputRange: [0.8, 1.2] }) }],
        },
      ]}
    />
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: Colors.bgDeep,
  },
  scroll: {
    paddingTop: 60,
    paddingBottom: 30,
  },
  hero: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    paddingHorizontal: Spacing.xl,
    marginBottom: Spacing.xl,
  },
  heroTitle: {
    fontSize: FontSize.xxl,
    fontWeight: '800',
    color: Colors.textPrimary,
    letterSpacing: -0.5,
  },
  heroSubtitle: {
    fontSize: FontSize.sm,
    color: Colors.textMuted,
    marginTop: 4,
    letterSpacing: 0.3,
  },
  badgeRow: {
    flexDirection: 'row',
    gap: 8,
    alignItems: 'center',
  },
  badgeLive: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    paddingHorizontal: 10,
    paddingVertical: 5,
    borderRadius: BorderRadius.full,
    backgroundColor: 'rgba(16, 185, 129, 0.15)',
    borderWidth: 1,
    borderColor: 'rgba(16, 185, 129, 0.3)',
  },
  pulseDot: {
    width: 6,
    height: 6,
    borderRadius: 3,
    backgroundColor: Colors.success,
  },
  badgeLiveText: {
    fontSize: FontSize.xs,
    fontWeight: '700',
    color: Colors.success,
    letterSpacing: 1,
  },
  badge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    paddingHorizontal: 10,
    paddingVertical: 5,
    borderRadius: BorderRadius.full,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  badgeText: {
    fontSize: FontSize.xs,
    fontWeight: '600',
    color: Colors.textSecondary,
    letterSpacing: 0.5,
  },
  statsRow: {
    paddingHorizontal: Spacing.xl,
    gap: Spacing.md,
    marginBottom: Spacing.xl,
  },
  statCard: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: Colors.bgCard,
    borderRadius: BorderRadius.lg,
    padding: Spacing.lg,
    borderWidth: 1,
    borderColor: Colors.border,
    gap: Spacing.md,
  },
  statIconWrap: {
    width: 40,
    height: 40,
    borderRadius: BorderRadius.md,
    justifyContent: 'center',
    alignItems: 'center',
  },
  statInfo: {
    flex: 1,
  },
  statLabel: {
    fontSize: FontSize.xs,
    color: Colors.textMuted,
    fontWeight: '600',
    letterSpacing: 0.5,
    textTransform: 'uppercase',
  },
  statValue: {
    fontSize: FontSize.xl,
    fontWeight: '800',
    color: Colors.textPrimary,
    marginTop: 2,
  },
  meshWrap: {
    paddingHorizontal: Spacing.xl,
    marginBottom: Spacing.xl,
  },
  meshCanvas: {
    height: 260,
    borderRadius: BorderRadius.xl,
    overflow: 'hidden',
    borderWidth: 1,
    borderColor: Colors.border,
    position: 'relative',
  },
  meshNode: {
    position: 'absolute',
    width: 10,
    height: 10,
    borderRadius: 5,
    backgroundColor: Colors.accent,
    shadowColor: Colors.accent,
    shadowOffset: { width: 0, height: 0 },
    shadowOpacity: 0.8,
    shadowRadius: 6,
    elevation: 5,
  },
  meshOverlay: {
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    backgroundColor: 'rgba(2, 4, 40, 0.85)',
    padding: Spacing.lg,
    backdropFilter: 'blur(10)',
  },
  meshOverlayTitle: {
    fontSize: FontSize.sm,
    color: Colors.textSecondary,
    fontWeight: '600',
    marginBottom: Spacing.sm,
    letterSpacing: 0.5,
  },
  meshStatRow: {
    flexDirection: 'row',
    justifyContent: 'space-around',
  },
  meshStatLabel: {
    fontSize: FontSize.xs,
    color: Colors.textMuted,
    fontWeight: '600',
    letterSpacing: 1,
  },
  meshStatValue: {
    fontSize: FontSize.md,
    color: Colors.textPrimary,
    fontWeight: '700',
    marginTop: 2,
  },
  serverInfoCard: {
    marginHorizontal: Spacing.xl,
    backgroundColor: Colors.bgCard,
    borderRadius: BorderRadius.lg,
    padding: Spacing.lg,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  sectionTitle: {
    fontSize: FontSize.lg,
    fontWeight: '700',
    color: Colors.textPrimary,
    marginBottom: Spacing.md,
  },
  infoRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: Spacing.sm,
    borderBottomWidth: 1,
    borderBottomColor: Colors.border,
  },
  infoLabel: {
    fontSize: FontSize.sm,
    color: Colors.textMuted,
    fontWeight: '500',
  },
  infoValue: {
    fontSize: FontSize.sm,
    color: Colors.textPrimary,
    fontWeight: '600',
  },
});
