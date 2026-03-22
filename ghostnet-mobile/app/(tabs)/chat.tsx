import React, { useState, useRef, useEffect } from 'react';
import {
  View, Text, ScrollView, StyleSheet, TextInput, TouchableOpacity,
  KeyboardAvoidingView, Platform, FlatList,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { Colors, Spacing, BorderRadius, FontSize, API_BASE } from '../../constants/Theme';

interface Message {
  id: string;
  text: string;
  sender: 'me' | 'them';
  timestamp: number;
  status?: 'sent' | 'delivered' | 'queued';
}

interface Conversation {
  id: string;
  name: string;
  lastMessage: string;
  updated: number;
  unread?: boolean;
}

export default function ChatScreen() {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeConvo, setActiveConvo] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const scrollRef = useRef<FlatList>(null);

  // Simulated data
  useEffect(() => {
    setConversations([
      { id: 'demo1', name: 'Phantom_99', lastMessage: 'Encryption verified.', updated: Date.now() - 300000, unread: true },
      { id: 'demo2', name: 'GN-4201', lastMessage: 'Mesh relay active', updated: Date.now() - 900000 },
    ]);
  }, []);

  const selectConvo = (id: string) => {
    setActiveConvo(id);
    const convo = conversations.find(c => c.id === id);
    setMessages([
      { id: '1', text: 'Hey, are you on the mesh?', sender: 'them', timestamp: Date.now() - 60000 },
      { id: '2', text: 'Yeah, connected via WebSocket relay', sender: 'me', timestamp: Date.now() - 30000, status: 'delivered' },
      { id: '3', text: 'Encryption verified. ✓', sender: 'them', timestamp: Date.now() - 10000 },
    ]);
  };

  const sendMessage = () => {
    if (!input.trim()) return;
    const msg: Message = {
      id: Date.now().toString(),
      text: input.trim(),
      sender: 'me',
      timestamp: Date.now(),
      status: 'sent',
    };
    setMessages(prev => [...prev, msg]);
    setInput('');
    setTimeout(() => scrollRef.current?.scrollToEnd({ animated: true }), 100);
  };

  const formatTime = (ts: number) => {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  // Conversation List
  if (!activeConvo) {
    return (
      <View style={styles.container}>
        <View style={styles.chatHeader}>
          <View>
            <Text style={styles.heroTitle}>Messages</Text>
            <Text style={styles.heroSubtitle}>End-to-end encrypted</Text>
          </View>
          <TouchableOpacity style={styles.newChatBtn}>
            <Ionicons name="add" size={22} color={Colors.textPrimary} />
          </TouchableOpacity>
        </View>
        <ScrollView contentContainerStyle={styles.convoList}>
          {conversations.map((convo) => (
            <TouchableOpacity
              key={convo.id}
              style={styles.convoCard}
              onPress={() => selectConvo(convo.id)}
              activeOpacity={0.7}
            >
              <View style={styles.convoAvatar}>
                <Text style={styles.convoAvatarText}>{convo.name.charAt(0)}</Text>
              </View>
              <View style={styles.convoInfo}>
                <View style={styles.convoTopRow}>
                  <Text style={styles.convoName}>{convo.name}</Text>
                  <Text style={styles.convoTime}>{formatTime(convo.updated)}</Text>
                </View>
                <View style={styles.convoBottomRow}>
                  <Ionicons name="shield-checkmark" size={11} color={Colors.textMuted} />
                  <Text style={styles.convoPreview} numberOfLines={1}>{convo.lastMessage}</Text>
                  {convo.unread && <View style={styles.unreadDot} />}
                </View>
              </View>
            </TouchableOpacity>
          ))}
        </ScrollView>
      </View>
    );
  }

  // Active Chat
  const convoName = conversations.find(c => c.id === activeConvo)?.name || 'Chat';

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
      keyboardVerticalOffset={90}
    >
      {/* Chat Header */}
      <View style={styles.activeChatHeader}>
        <TouchableOpacity onPress={() => setActiveConvo(null)} style={styles.backBtn}>
          <Ionicons name="arrow-back" size={22} color={Colors.textPrimary} />
        </TouchableOpacity>
        <View style={styles.activeChatAvatar}>
          <Text style={styles.convoAvatarText}>{convoName.charAt(0)}</Text>
        </View>
        <View style={{ flex: 1 }}>
          <Text style={styles.activeChatName}>{convoName}</Text>
          <View style={styles.onlineRow}>
            <View style={styles.onlineDot} />
            <Text style={styles.onlineText}>Mesh Active</Text>
          </View>
        </View>
        <View style={styles.e2eBadge}>
          <Ionicons name="shield-checkmark" size={12} color={Colors.accent} />
          <Text style={styles.e2eText}>E2E</Text>
        </View>
      </View>

      {/* Messages */}
      <FlatList
        ref={scrollRef}
        data={messages}
        keyExtractor={item => item.id}
        contentContainerStyle={styles.messageList}
        onContentSizeChange={() => scrollRef.current?.scrollToEnd({ animated: false })}
        renderItem={({ item }) => (
          <View style={[styles.messageBubble, item.sender === 'me' ? styles.myBubble : styles.theirBubble]}>
            <Text style={[styles.messageText, item.sender === 'me' ? styles.myText : styles.theirText]}>
              {item.text}
            </Text>
            <View style={styles.messageFooter}>
              <Text style={styles.messageTime}>{formatTime(item.timestamp)}</Text>
              {item.sender === 'me' && item.status && (
                <Text style={[
                  styles.messageStatus,
                  item.status === 'delivered' && { color: Colors.neonBlue },
                  item.status === 'queued' && { color: Colors.textMuted },
                ]}>
                  {item.status === 'delivered' ? '✓✓' : item.status === 'queued' ? '🕐' : '✓'}
                </Text>
              )}
            </View>
          </View>
        )}
      />

      {/* Input Bar */}
      <View style={styles.inputBar}>
        <TouchableOpacity style={styles.attachBtn}>
          <Ionicons name="attach" size={22} color={Colors.textMuted} />
        </TouchableOpacity>
        <TextInput
          style={styles.textInput}
          value={input}
          onChangeText={setInput}
          placeholder="Type a secure message..."
          placeholderTextColor={Colors.textMuted}
          onSubmitEditing={sendMessage}
          returnKeyType="send"
        />
        <TouchableOpacity style={styles.sendBtn} onPress={sendMessage}>
          <Ionicons name="send" size={18} color="#fff" />
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: Colors.bgDeep },
  chatHeader: {
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start',
    paddingHorizontal: Spacing.xl, paddingTop: 60, paddingBottom: Spacing.lg,
    borderBottomWidth: 1, borderBottomColor: Colors.border,
  },
  heroTitle: { fontSize: FontSize.xxl, fontWeight: '800', color: Colors.textPrimary },
  heroSubtitle: { fontSize: FontSize.xs, color: Colors.textMuted, marginTop: 3, letterSpacing: 0.5 },
  newChatBtn: {
    width: 40, height: 40, borderRadius: 20,
    backgroundColor: Colors.bgCard, borderWidth: 1, borderColor: Colors.border,
    justifyContent: 'center', alignItems: 'center',
  },
  convoList: { paddingTop: Spacing.md },
  convoCard: {
    flexDirection: 'row', alignItems: 'center', gap: Spacing.md,
    paddingHorizontal: Spacing.xl, paddingVertical: Spacing.lg,
    borderBottomWidth: 1, borderBottomColor: Colors.border,
  },
  convoAvatar: {
    width: 48, height: 48, borderRadius: 24,
    backgroundColor: Colors.accent,
    justifyContent: 'center', alignItems: 'center',
  },
  convoAvatarText: { fontSize: FontSize.lg, fontWeight: '800', color: '#fff' },
  convoInfo: { flex: 1 },
  convoTopRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  convoName: { fontSize: FontSize.md, fontWeight: '700', color: Colors.textPrimary },
  convoTime: { fontSize: FontSize.xs, color: Colors.textMuted },
  convoBottomRow: { flexDirection: 'row', alignItems: 'center', gap: 4, marginTop: 4 },
  convoPreview: { fontSize: FontSize.sm, color: Colors.textMuted, flex: 1 },
  unreadDot: {
    width: 8, height: 8, borderRadius: 4, backgroundColor: Colors.accent,
  },
  // Active Chat
  activeChatHeader: {
    flexDirection: 'row', alignItems: 'center', gap: Spacing.md,
    paddingHorizontal: Spacing.lg, paddingTop: 56, paddingBottom: Spacing.md,
    backgroundColor: Colors.bgPanel, borderBottomWidth: 1, borderBottomColor: Colors.border,
  },
  backBtn: { padding: 4 },
  activeChatAvatar: {
    width: 38, height: 38, borderRadius: 19,
    backgroundColor: Colors.accent,
    justifyContent: 'center', alignItems: 'center',
  },
  activeChatName: { fontSize: FontSize.md, fontWeight: '700', color: Colors.textPrimary },
  onlineRow: { flexDirection: 'row', alignItems: 'center', gap: 4 },
  onlineDot: { width: 5, height: 5, borderRadius: 3, backgroundColor: Colors.success },
  onlineText: { fontSize: FontSize.xs, color: Colors.textMuted },
  e2eBadge: {
    flexDirection: 'row', alignItems: 'center', gap: 4,
    paddingHorizontal: 8, paddingVertical: 3,
    borderRadius: BorderRadius.full,
    backgroundColor: Colors.accentDim,
  },
  e2eText: { fontSize: FontSize.xs, fontWeight: '700', color: Colors.accent },
  messageList: { padding: Spacing.lg, paddingBottom: Spacing.xxl },
  messageBubble: {
    maxWidth: '78%', padding: Spacing.md,
    borderRadius: BorderRadius.lg, marginBottom: Spacing.sm,
  },
  myBubble: {
    alignSelf: 'flex-end',
    backgroundColor: Colors.accent,
    borderBottomRightRadius: 4,
  },
  theirBubble: {
    alignSelf: 'flex-start',
    backgroundColor: Colors.bgCard,
    borderBottomLeftRadius: 4,
    borderWidth: 1, borderColor: Colors.border,
  },
  messageText: { fontSize: FontSize.md, lineHeight: 20 },
  myText: { color: '#ffffff' },
  theirText: { color: Colors.textPrimary },
  messageFooter: {
    flexDirection: 'row', justifyContent: 'flex-end', alignItems: 'center',
    gap: 4, marginTop: 4,
  },
  messageTime: { fontSize: 9, color: 'rgba(255,255,255,0.5)' },
  messageStatus: { fontSize: 10, color: 'rgba(255,255,255,0.7)' },
  inputBar: {
    flexDirection: 'row', alignItems: 'center', gap: Spacing.sm,
    paddingHorizontal: Spacing.lg, paddingVertical: Spacing.md,
    backgroundColor: Colors.bgPanel, borderTopWidth: 1, borderTopColor: Colors.border,
  },
  attachBtn: { padding: 6 },
  textInput: {
    flex: 1, backgroundColor: Colors.bgInput,
    borderRadius: BorderRadius.xl, paddingHorizontal: Spacing.lg,
    paddingVertical: 10, color: Colors.textPrimary,
    fontSize: FontSize.md, borderWidth: 1, borderColor: Colors.border,
  },
  sendBtn: {
    width: 40, height: 40, borderRadius: 20,
    backgroundColor: Colors.accent,
    justifyContent: 'center', alignItems: 'center',
  },
});
