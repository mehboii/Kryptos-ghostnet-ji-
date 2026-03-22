import React, { useState } from 'react';
import {
  View, Text, ScrollView, StyleSheet, TouchableOpacity,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { Colors, Spacing, BorderRadius, FontSize } from '../../constants/Theme';

interface VaultFile {
  id: string;
  name: string;
  size: string;
  type: string;
  encrypted: boolean;
  timestamp: number;
}

export default function VaultScreen() {
  const [files, setFiles] = useState<VaultFile[]>([]);

  const getFileIcon = (type: string): React.ComponentProps<typeof Ionicons>['name'] => {
    if (type.includes('image')) return 'image-outline';
    if (type.includes('video')) return 'videocam-outline';
    if (type.includes('audio')) return 'musical-notes-outline';
    if (type.includes('pdf')) return 'document-text-outline';
    return 'document-outline';
  };

  return (
    <View style={styles.container}>
      <ScrollView contentContainerStyle={styles.scroll} showsVerticalScrollIndicator={false}>
        {/* Hero */}
        <View style={styles.hero}>
          <View>
            <Text style={styles.heroTitle}>File Vault</Text>
            <Text style={styles.heroSubtitle}>Encrypted decentralized storage</Text>
          </View>
          <View style={styles.badgeRow}>
            <View style={styles.badge}>
              <Ionicons name="shield-checkmark" size={12} color={Colors.textSecondary} />
              <Text style={styles.badgeText}>AES-256-GCM</Text>
            </View>
          </View>
        </View>

        {/* Upload Zone */}
        <TouchableOpacity style={styles.uploadZone} activeOpacity={0.7}>
          <View style={styles.uploadIcon}>
            <Ionicons name="cloud-upload-outline" size={40} color={Colors.accent} />
          </View>
          <Text style={styles.uploadTitle}>Tap to encrypt & upload</Text>
          <Text style={styles.uploadSubtitle}>
            End-to-end encrypted • Blockchain anchored • Zero-knowledge
          </Text>
          <View style={styles.browseBtn}>
            <Ionicons name="folder-open-outline" size={14} color="#fff" />
            <Text style={styles.browseBtnText}>Browse Files</Text>
          </View>
        </TouchableOpacity>

        {/* Stats Bar */}
        <View style={styles.statsBar}>
          <View style={styles.statItem}>
            <Ionicons name="documents-outline" size={14} color={Colors.accent} />
            <Text style={styles.statText}>{files.length} files</Text>
          </View>
          <View style={styles.statItem}>
            <Ionicons name="server-outline" size={14} color={Colors.accent} />
            <Text style={styles.statText}>0 B</Text>
          </View>
          <View style={styles.statItem}>
            <Ionicons name="link-outline" size={14} color={Colors.success} />
            <Text style={styles.statText}>0 on-chain</Text>
          </View>
        </View>

        {/* File Grid */}
        {files.length > 0 ? (
          <View style={styles.fileGrid}>
            {files.map((file) => (
              <View key={file.id} style={styles.fileCard}>
                <View style={styles.fileIconWrap}>
                  <Ionicons name={getFileIcon(file.type)} size={24} color={Colors.accent} />
                </View>
                <Text style={styles.fileName} numberOfLines={1}>{file.name}</Text>
                <Text style={styles.fileSize}>{file.size}</Text>
                <View style={styles.fileEncBadge}>
                  <Ionicons name="lock-closed" size={10} color={Colors.success} />
                  <Text style={styles.fileEncText}>Encrypted</Text>
                </View>
              </View>
            ))}
          </View>
        ) : (
          <View style={styles.emptyState}>
            <Ionicons name="lock-closed-outline" size={48} color={Colors.textMuted} />
            <Text style={styles.emptyTitle}>Your vault is empty</Text>
            <Text style={styles.emptyText}>
              Tap above to encrypt and store files securely on the decentralized mesh.
            </Text>
          </View>
        )}
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
  badgeRow: { flexDirection: 'row', gap: 8 },
  badge: {
    flexDirection: 'row', alignItems: 'center', gap: 4,
    paddingHorizontal: 10, paddingVertical: 5,
    borderRadius: BorderRadius.full, borderWidth: 1, borderColor: Colors.border,
  },
  badgeText: { fontSize: FontSize.xs, fontWeight: '600', color: Colors.textSecondary },
  uploadZone: {
    marginHorizontal: Spacing.xl, borderRadius: BorderRadius.xl,
    borderWidth: 2, borderColor: Colors.border, borderStyle: 'dashed',
    padding: Spacing.xxl, alignItems: 'center',
    backgroundColor: Colors.bgCard,
    marginBottom: Spacing.xl,
  },
  uploadIcon: {
    width: 70, height: 70, borderRadius: 35,
    backgroundColor: Colors.accentDim,
    justifyContent: 'center', alignItems: 'center',
    marginBottom: Spacing.lg,
  },
  uploadTitle: { fontSize: FontSize.lg, fontWeight: '700', color: Colors.textPrimary },
  uploadSubtitle: {
    fontSize: FontSize.xs, color: Colors.textMuted, textAlign: 'center',
    marginTop: Spacing.sm, lineHeight: 18,
  },
  browseBtn: {
    flexDirection: 'row', alignItems: 'center', gap: 6,
    backgroundColor: Colors.accent, borderRadius: BorderRadius.md,
    paddingHorizontal: Spacing.lg, paddingVertical: Spacing.sm,
    marginTop: Spacing.lg,
  },
  browseBtnText: { fontSize: FontSize.sm, fontWeight: '600', color: '#fff' },
  statsBar: {
    flexDirection: 'row', justifyContent: 'space-around',
    paddingHorizontal: Spacing.xl, paddingVertical: Spacing.md,
    marginHorizontal: Spacing.xl, borderRadius: BorderRadius.lg,
    backgroundColor: Colors.bgCard, borderWidth: 1, borderColor: Colors.border,
    marginBottom: Spacing.xl,
  },
  statItem: { flexDirection: 'row', alignItems: 'center', gap: 6 },
  statText: { fontSize: FontSize.sm, color: Colors.textSecondary, fontWeight: '500' },
  fileGrid: {
    flexDirection: 'row', flexWrap: 'wrap',
    paddingHorizontal: Spacing.xl, gap: Spacing.md,
  },
  fileCard: {
    width: '47%', backgroundColor: Colors.bgCard,
    borderRadius: BorderRadius.lg, padding: Spacing.lg,
    borderWidth: 1, borderColor: Colors.border, alignItems: 'center',
  },
  fileIconWrap: {
    width: 48, height: 48, borderRadius: 24,
    backgroundColor: Colors.accentDim,
    justifyContent: 'center', alignItems: 'center',
    marginBottom: Spacing.sm,
  },
  fileName: { fontSize: FontSize.sm, fontWeight: '600', color: Colors.textPrimary, textAlign: 'center' },
  fileSize: { fontSize: FontSize.xs, color: Colors.textMuted, marginTop: 2 },
  fileEncBadge: {
    flexDirection: 'row', alignItems: 'center', gap: 4,
    marginTop: Spacing.sm, paddingHorizontal: 8, paddingVertical: 2,
    borderRadius: BorderRadius.sm, backgroundColor: 'rgba(16, 185, 129, 0.12)',
  },
  fileEncText: { fontSize: 9, color: Colors.success, fontWeight: '600' },
  emptyState: {
    alignItems: 'center', paddingVertical: 50, paddingHorizontal: Spacing.xxl, gap: Spacing.md,
  },
  emptyTitle: { fontSize: FontSize.lg, fontWeight: '700', color: Colors.textSecondary },
  emptyText: { fontSize: FontSize.sm, color: Colors.textMuted, textAlign: 'center', lineHeight: 20 },
});
