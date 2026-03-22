import React from 'react';
import { Tabs } from 'expo-router';
import { View, StyleSheet } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { Colors } from '../../constants/Theme';

type TabIconName = React.ComponentProps<typeof Ionicons>['name'];

const TAB_ITEMS: { name: string; title: string; icon: TabIconName; iconActive: TabIconName }[] = [
  { name: 'index', title: 'Home', icon: 'globe-outline', iconActive: 'globe' },
  { name: 'nodes', title: 'Nodes', icon: 'git-network-outline', iconActive: 'git-network' },
  { name: 'wallet', title: 'Wallet', icon: 'wallet-outline', iconActive: 'wallet' },
  { name: 'chat', title: 'Chat', icon: 'chatbubble-outline', iconActive: 'chatbubble' },
  { name: 'vault', title: 'Vault', icon: 'lock-closed-outline', iconActive: 'lock-closed' },
  { name: 'profile', title: 'Profile', icon: 'person-outline', iconActive: 'person' },
];

export default function TabLayout() {
  return (
    <Tabs
      screenOptions={{
        headerShown: false,
        tabBarStyle: styles.tabBar,
        tabBarActiveTintColor: Colors.accent,
        tabBarInactiveTintColor: Colors.textMuted,
        tabBarLabelStyle: styles.tabLabel,
      }}
    >
      {TAB_ITEMS.map((tab) => (
        <Tabs.Screen
          key={tab.name}
          name={tab.name}
          options={{
            title: tab.title,
            tabBarIcon: ({ focused, color, size }) => (
              <View style={focused ? styles.activeIconWrap : undefined}>
                <Ionicons name={focused ? tab.iconActive : tab.icon} size={22} color={color} />
                {focused && <View style={styles.activeIndicator} />}
              </View>
            ),
          }}
        />
      ))}
    </Tabs>
  );
}

const styles = StyleSheet.create({
  tabBar: {
    backgroundColor: Colors.bgPanel,
    borderTopColor: Colors.border,
    borderTopWidth: 1,
    height: 65,
    paddingBottom: 8,
    paddingTop: 6,
    elevation: 20,
    shadowColor: Colors.glowAccent,
    shadowOffset: { width: 0, height: -4 },
    shadowOpacity: 0.3,
    shadowRadius: 12,
  },
  tabLabel: {
    fontSize: 10,
    fontWeight: '600',
    letterSpacing: 0.4,
  },
  activeIconWrap: {
    alignItems: 'center',
  },
  activeIndicator: {
    width: 4,
    height: 4,
    borderRadius: 2,
    backgroundColor: Colors.accent,
    marginTop: 2,
  },
});
