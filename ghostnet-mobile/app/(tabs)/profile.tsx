import React, { useState } from 'react';
import {
  View, Text, ScrollView, StyleSheet, TouchableOpacity, TextInput, Alert,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { LinearGradient } from 'expo-linear-gradient';
import { Colors, Spacing, BorderRadius, FontSize, API_BASE } from '../../constants/theme';

export default function ProfileScreen() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [displayName, setDisplayName] = useState('');
  const [pin, setPin] = useState('');
  const [nodeId, setNodeId] = useState('');

  const handleCreate = () => {
    if (!displayName.trim()) return Alert.alert('Enter a display name');
    if (pin.length < 4) return Alert.alert('PIN must be at least 4 digits');
    // Generate a mock node ID
    const id = '0x' + Array.from({ length: 40 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
    setNodeId(id);
    setIsLoggedIn(true);
  };

  if (!isLoggedIn) {
    return (
      <View style={styles.container}>
        <ScrollView contentContainerStyle={styles.scroll} showsVerticalScrollIndicator={false}>
          {/* Hero */}
          <View style={styles.hero}>
            <Text style={styles.heroTitle}>Node Identity</Text>
            <Text style={styles.heroSubtitle}>Cryptographic self-sovereign identity</Text>
          </View>

          {/* Welcome Card */}
          <View style={styles.welcomeCard}>
            <View style={styles.logoRing}>
              <View style={styles.logoInner}>
                <Ionicons name="shield" size={36} color={Colors.accent} />
              </View>
            </View>
            <Text style={styles.welcomeTitle}>GhostNet</Text>
            <Text style={styles.welcomeSubtitle}>
              Your decentralized identity lives on your device. No servers, no passwords, no tracking.
            </Text>

            <View style={styles.inputGroup}>
              <Text style={styles.inputLabel}>DISPLAY NAME</Text>
              <TextInput
                style={styles.authInput}
                value={displayName}
                onChangeText={setDisplayName}
                placeholder="Enter your name"
                placeholderTextColor={Colors.textMuted}
              />
            </View>

            <View style={styles.inputGroup}>
              <Text style={styles.inputLabel}>SET PIN (4+ digits)</Text>
              <TextInput
                style={styles.authInput}
                value={pin}
                onChangeText={setPin}
                placeholder="●●●●"
                placeholderTextColor={Colors.textMuted}
                keyboardType="number-pad"
                secureTextEntry
                maxLength={8}
              />
            </View>

            <TouchableOpacity style={styles.primaryBtn} onPress={handleCreate}>
              <Ionicons name="add" size={18} color="#fff" />
              <Text style={styles.primaryBtnText}>Create New Identity</Text>
            </TouchableOpacity>

            <TouchableOpacity style={styles.secondaryBtn}>
              <Ionicons name="refresh" size={18} color={Colors.accent} />
              <Text style={styles.secondaryBtnText}>Restore With Seed Phrase</Text>
            </TouchableOpacity>
          </View>
        </ScrollView>
      </View>
    );
  }

  // Logged in view
  return (
    <View style={styles.container}>
      <ScrollView contentContainerStyle={styles.scroll} showsVerticalScrollIndicator={false}>
        {/* Hero */}
        <View style={styles.hero}>
          <View>
            <Text style={styles.heroTitle}>Node Identity</Text>
            <Text style={styles.heroSubtitle}>Cryptographic self-sovereign identity</Text>
          </View>
          <View style={styles.badge}>
            <Ionicons name="shield-checkmark" size={12} color={Colors.textSecondary} />
            <Text style={styles.badgeText}>Zero-Knowledge</Text>
          </View>
        </View>

        {/* Profile Card */}
        <LinearGradient
          colors={Colors.gradientPrimary as [string, string]}
          start={{ x: 0, y: 0 }}
          end={{ x: 1, y: 1 }}
          style={styles.profileCard}
        >
          <View style={styles.profileAvatar}>
            <Text style={styles.profileAvatarText}>{displayName.charAt(0).toUpperCase()}</Text>
          </View>
          <Text style={styles.profileName}>{displayName}</Text>
          <Text style={styles.profileId}>{nodeId.slice(0, 10)}...{nodeId.slice(-6)}</Text>
        </LinearGradient>

        {/* Info Cards */}
        <View style={styles.infoCard}>
          <Text style={styles.sectionTitle}>Identity Details</Text>
          <InfoRow label="Display Name" value={displayName} />
          <InfoRow label="Node ID" value={nodeId.slice(0, 18) + '...'} mono />
          <InfoRow label="Created" value={new Date().toLocaleDateString()} />
          <InfoRow label="Auth Method" value="PIN + Seed Phrase" />
          <InfoRow label="Encryption" value="secp256k1 / AES-256" />
        </View>

        {/* Actions */}
        <View style={styles.actionsCard}>
          <TouchableOpacity style={styles.actionRow}>
            <Ionicons name="key-outline" size={20} color={Colors.accent} />
            <Text style={styles.actionText}>Export Seed Phrase</Text>
            <Ionicons name="chevron-forward" size={16} color={Colors.textMuted} />
          </TouchableOpacity>
          <TouchableOpacity style={styles.actionRow}>
            <Ionicons name="qr-code-outline" size={20} color={Colors.accent} />
            <Text style={styles.actionText}>Show QR Code</Text>
            <Ionicons name="chevron-forward" size={16} color={Colors.textMuted} />
          </TouchableOpacity>
          <TouchableOpacity style={styles.actionRow}>
            <Ionicons name="sync-outline" size={20} color={Colors.accent} />
            <Text style={styles.actionText}>Sync to Another Device</Text>
            <Ionicons name="chevron-forward" size={16} color={Colors.textMuted} />
          </TouchableOpacity>
          <TouchableOpacity
            style={[styles.actionRow, { borderBottomWidth: 0 }]}
            onPress={() => { setIsLoggedIn(false); setPin(''); }}
          >
            <Ionicons name="log-out-outline" size={20} color={Colors.danger} />
            <Text style={[styles.actionText, { color: Colors.danger }]}>Logout</Text>
            <Ionicons name="chevron-forward" size={16} color={Colors.textMuted} />
          </TouchableOpacity>
        </View>
      </ScrollView>
    </View>
  );
}

function InfoRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <View style={styles.infoRow}>
      <Text style={styles.infoLabel}>{label}</Text>
      <Text style={[styles.infoValue, mono && { fontFamily: 'monospace', fontSize: FontSize.xs }]}>
        {value}
      </Text>
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
    borderRadius: BorderRadius.full, borderWidth: 1, borderColor: Colors.border,
  },
  badgeText: { fontSize: FontSize.xs, fontWeight: '600', color: Colors.textSecondary },
  // Welcome / Create
  welcomeCard: {
    marginHorizontal: Spacing.xl, backgroundColor: Colors.bgCard,
    borderRadius: BorderRadius.xl, padding: Spacing.xxl,
    borderWidth: 1, borderColor: Colors.border, alignItems: 'center',
  },
  logoRing: {
    width: 80, height: 80, borderRadius: 40,
    borderWidth: 2, borderColor: Colors.accent,
    justifyContent: 'center', alignItems: 'center',
    marginBottom: Spacing.lg,
  },
  logoInner: {
    width: 60, height: 60, borderRadius: 30,
    backgroundColor: Colors.accentDim,
    justifyContent: 'center', alignItems: 'center',
  },
  welcomeTitle: { fontSize: FontSize.xxl, fontWeight: '900', color: Colors.textPrimary },
  welcomeSubtitle: {
    fontSize: FontSize.sm, color: Colors.textMuted, textAlign: 'center',
    marginTop: Spacing.sm, lineHeight: 20, marginBottom: Spacing.xl,
  },
  inputGroup: { width: '100%', marginBottom: Spacing.lg },
  inputLabel: {
    fontSize: FontSize.xs, fontWeight: '700', color: Colors.textMuted,
    letterSpacing: 0.5, marginBottom: Spacing.sm,
  },
  authInput: {
    backgroundColor: Colors.bgInput, borderRadius: BorderRadius.md,
    paddingHorizontal: Spacing.lg, paddingVertical: 12,
    color: Colors.textPrimary, fontSize: FontSize.md,
    borderWidth: 1, borderColor: Colors.border,
  },
  primaryBtn: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 8,
    backgroundColor: Colors.accent, borderRadius: BorderRadius.lg,
    paddingVertical: 14, width: '100%', marginBottom: Spacing.md,
  },
  primaryBtnText: { fontSize: FontSize.md, fontWeight: '700', color: '#fff' },
  secondaryBtn: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 8,
    borderWidth: 1, borderColor: Colors.borderActive, borderRadius: BorderRadius.lg,
    paddingVertical: 14, width: '100%',
  },
  secondaryBtnText: { fontSize: FontSize.md, fontWeight: '600', color: Colors.accent },
  // Profile Card
  profileCard: {
    marginHorizontal: Spacing.xl, borderRadius: BorderRadius.xl,
    padding: Spacing.xxl, alignItems: 'center', marginBottom: Spacing.xl,
    shadowColor: Colors.accent, shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.3, shadowRadius: 16, elevation: 10,
  },
  profileAvatar: {
    width: 64, height: 64, borderRadius: 32,
    backgroundColor: 'rgba(255,255,255,0.2)',
    justifyContent: 'center', alignItems: 'center', marginBottom: Spacing.md,
  },
  profileAvatarText: { fontSize: 28, fontWeight: '900', color: '#fff' },
  profileName: { fontSize: FontSize.xl, fontWeight: '800', color: '#fff' },
  profileId: { fontSize: FontSize.xs, color: 'rgba(255,255,255,0.6)', fontFamily: 'monospace', marginTop: 4 },
  // Info Card
  infoCard: {
    marginHorizontal: Spacing.xl, backgroundColor: Colors.bgCard,
    borderRadius: BorderRadius.lg, padding: Spacing.lg,
    borderWidth: 1, borderColor: Colors.border, marginBottom: Spacing.lg,
  },
  sectionTitle: {
    fontSize: FontSize.lg, fontWeight: '700', color: Colors.textPrimary, marginBottom: Spacing.md,
  },
  infoRow: {
    flexDirection: 'row', justifyContent: 'space-between',
    paddingVertical: Spacing.sm, borderBottomWidth: 1, borderBottomColor: Colors.border,
  },
  infoLabel: { fontSize: FontSize.sm, color: Colors.textMuted, fontWeight: '500' },
  infoValue: { fontSize: FontSize.sm, color: Colors.textPrimary, fontWeight: '600' },
  // Actions
  actionsCard: {
    marginHorizontal: Spacing.xl, backgroundColor: Colors.bgCard,
    borderRadius: BorderRadius.lg, borderWidth: 1, borderColor: Colors.border,
    overflow: 'hidden',
  },
  actionRow: {
    flexDirection: 'row', alignItems: 'center', gap: Spacing.md,
    paddingHorizontal: Spacing.lg, paddingVertical: Spacing.lg,
    borderBottomWidth: 1, borderBottomColor: Colors.border,
  },
  actionText: { fontSize: FontSize.md, color: Colors.textPrimary, fontWeight: '500', flex: 1 },
});
