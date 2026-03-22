import React from 'react';
import { View, Text, ScrollView, StyleSheet, TouchableOpacity } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { LinearGradient } from 'expo-linear-gradient';
import { Colors, Spacing, BorderRadius, FontSize } from '../../constants/theme';

const TOKENS = [
  { symbol: 'ETH', name: 'Ethereum', balance: '0.0000', chain: 'Ethereum', color: '#627eea', icon: 'logo-ethereum' as const },
  { symbol: 'BTC', name: 'Bitcoin', balance: '0.0000', chain: 'Bitcoin', color: '#f7931a', icon: 'logo-bitcoin' as const },
  { symbol: 'SOL', name: 'Solana', balance: '0.0000', chain: 'Solana', color: '#9945ff', icon: 'diamond-outline' as const },
  { symbol: 'USDT', name: 'Tether USD', balance: '0.00', chain: 'Ethereum', color: '#26a17b', icon: 'cash-outline' as const },
];

export default function WalletScreen() {
  return (
    <View style={styles.container}>
      <ScrollView contentContainerStyle={styles.scroll} showsVerticalScrollIndicator={false}>
        {/* Hero */}
        <View style={styles.hero}>
          <View>
            <Text style={styles.heroTitle}>Crypto Wallet</Text>
            <Text style={styles.heroSubtitle}>Multi-chain portfolio overview</Text>
          </View>
          <View style={styles.badge}>
            <Ionicons name="card-outline" size={12} color={Colors.textSecondary} />
            <Text style={styles.badgeText}>Multi-Chain</Text>
          </View>
        </View>

        {/* Total Balance Card */}
        <LinearGradient
          colors={Colors.gradientPrimary as [string, string]}
          start={{ x: 0, y: 0 }}
          end={{ x: 1, y: 1 }}
          style={styles.balanceCard}
        >
          <Text style={styles.balanceLabel}>Total Portfolio Value</Text>
          <Text style={styles.balanceValue}>$0.00</Text>
          <View style={styles.balanceActions}>
            <TouchableOpacity style={styles.actionBtn}>
              <Ionicons name="arrow-up" size={18} color="#fff" />
              <Text style={styles.actionText}>Send</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.actionBtn}>
              <Ionicons name="arrow-down" size={18} color="#fff" />
              <Text style={styles.actionText}>Receive</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.actionBtn}>
              <Ionicons name="swap-horizontal" size={18} color="#fff" />
              <Text style={styles.actionText}>Swap</Text>
            </TouchableOpacity>
          </View>
        </LinearGradient>

        {/* Token List */}
        <Text style={styles.sectionTitle}>Assets</Text>
        {TOKENS.map((token) => (
          <TouchableOpacity key={token.symbol} style={styles.tokenCard} activeOpacity={0.7}>
            <View style={[styles.tokenIcon, { backgroundColor: token.color + '20' }]}>
              <Ionicons name={token.icon} size={22} color={token.color} />
            </View>
            <View style={styles.tokenInfo}>
              <Text style={styles.tokenName}>{token.name}</Text>
              <Text style={styles.tokenChain}>{token.chain}</Text>
            </View>
            <View style={styles.tokenBalance}>
              <Text style={styles.tokenAmount}>{token.balance}</Text>
              <Text style={styles.tokenSymbol}>{token.symbol}</Text>
            </View>
          </TouchableOpacity>
        ))}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: Colors.bgDeep },
  scroll: { paddingTop: 60, paddingBottom: 30 },
  hero: {
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start',
    paddingHorizontal: Spacing.xl, marginBottom: Spacing.xl,
  },
  heroTitle: { fontSize: FontSize.xxl, fontWeight: '800', color: Colors.textPrimary },
  heroSubtitle: { fontSize: FontSize.sm, color: Colors.textMuted, marginTop: 4 },
  badge: {
    flexDirection: 'row', alignItems: 'center', gap: 4,
    paddingHorizontal: 10, paddingVertical: 5,
    borderRadius: BorderRadius.full,
    borderWidth: 1, borderColor: Colors.border,
  },
  badgeText: { fontSize: FontSize.xs, fontWeight: '600', color: Colors.textSecondary },
  balanceCard: {
    marginHorizontal: Spacing.xl, borderRadius: BorderRadius.xl,
    padding: Spacing.xxl, marginBottom: Spacing.xl,
    shadowColor: Colors.accent, shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.3, shadowRadius: 16, elevation: 10,
  },
  balanceLabel: { fontSize: FontSize.sm, color: 'rgba(255,255,255,0.7)', fontWeight: '500' },
  balanceValue: {
    fontSize: 40, fontWeight: '900', color: '#ffffff', marginTop: 4, letterSpacing: -1,
  },
  balanceActions: {
    flexDirection: 'row', gap: Spacing.lg, marginTop: Spacing.xl,
  },
  actionBtn: {
    alignItems: 'center', gap: 4,
    backgroundColor: 'rgba(255,255,255,0.15)',
    paddingHorizontal: Spacing.lg, paddingVertical: Spacing.sm,
    borderRadius: BorderRadius.lg,
  },
  actionText: { fontSize: FontSize.xs, color: '#fff', fontWeight: '600' },
  sectionTitle: {
    fontSize: FontSize.lg, fontWeight: '700', color: Colors.textPrimary,
    paddingHorizontal: Spacing.xl, marginBottom: Spacing.md,
  },
  tokenCard: {
    flexDirection: 'row', alignItems: 'center',
    backgroundColor: Colors.bgCard, borderRadius: BorderRadius.lg,
    padding: Spacing.lg, marginHorizontal: Spacing.xl,
    marginBottom: Spacing.md, borderWidth: 1, borderColor: Colors.border,
    gap: Spacing.md,
  },
  tokenIcon: {
    width: 44, height: 44, borderRadius: 22,
    justifyContent: 'center', alignItems: 'center',
  },
  tokenInfo: { flex: 1 },
  tokenName: { fontSize: FontSize.md, fontWeight: '700', color: Colors.textPrimary },
  tokenChain: { fontSize: FontSize.xs, color: Colors.textMuted, marginTop: 2 },
  tokenBalance: { alignItems: 'flex-end' },
  tokenAmount: { fontSize: FontSize.md, fontWeight: '700', color: Colors.textPrimary },
  tokenSymbol: { fontSize: FontSize.xs, color: Colors.textMuted, marginTop: 2 },
});
