import React, { useRef, useState, useEffect } from 'react';
import { View, StyleSheet, BackHandler, Platform, Text, StatusBar } from 'react-native';
import { WebView } from 'react-native-webview';
import * as SplashScreen from 'expo-splash-screen';

const GHOSTNET_URL = 'https://ghostnet-ji-production.up.railway.app';

export default function App() {
  const webViewRef = useRef<WebView>(null);
  const [error, setError] = useState(false);

  // Handle Android back button
  useEffect(() => {
    if (Platform.OS !== 'android') return;
    const onBackPress = () => {
      if (webViewRef.current) {
        webViewRef.current.goBack();
        return true;
      }
      return false;
    };
    const subscription = BackHandler.addEventListener('hardwareBackPress', onBackPress);
    return () => subscription.remove();
  }, []);

  // Aggressive fix for DOM elements swallowing touch events on mobile
  const INJECTED_JS = `
    setTimeout(function() {
      // 1. Force mobile layout constraints
      var meta = document.querySelector('meta[name="viewport"]');
      if (!meta) {
        meta = document.createElement('meta');
        meta.name = 'viewport';
        document.head.appendChild(meta);
      }
      meta.content = 'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no';

      // 2. Eradicate pointer event blockers
      var style = document.createElement('style');
      style.innerHTML = "canvas, #particles-js, .particles-bg { pointer-events: none !important; z-index: -1 !important; } a, button, input, select, textarea, .nav-item, .bottom-nav a, [role='button'], .clickable { pointer-events: auto !important; z-index: 99999 !important; position: relative !important; } body, html { height: 100% !important; overflow-y: auto !important; -webkit-overflow-scrolling: touch !important; }";
      document.head.appendChild(style);
    }, 500);
    true;
  `;

  if (error) {
    SplashScreen.hideAsync();
    return (
      <View style={styles.container}>
        <View style={styles.errorContainer}>
          <Text style={styles.errorText}>Unable to connect to GhostNet</Text>
          <Text style={styles.errorSub}>Check your connection or wait for the server to wake up</Text>
          <Text style={styles.retryBtn} onPress={() => setError(false)}>Retry</Text>
        </View>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#0a0e27" />
      <WebView
        ref={webViewRef}
        source={{ uri: GHOSTNET_URL }}
        style={styles.webview}
        javaScriptEnabled={true}
        domStorageEnabled={true}
        injectedJavaScript={INJECTED_JS}
        androidLayerType="hardware"
        onLoadEnd={() => {
          setTimeout(() => SplashScreen.hideAsync(), 500);
        }}
        onError={() => setError(true)}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0e27',
  },
  webview: {
    flex: 1,
    backgroundColor: '#0a0e27',
  },
  errorContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
    backgroundColor: '#0a0e27',
  },
  errorText: {
    fontSize: 18,
    color: '#ffffff',
    fontWeight: 'bold',
    marginBottom: 8,
  },
  errorSub: {
    fontSize: 14,
    color: '#8b8fa3',
    marginBottom: 20,
    textAlign: 'center',
  },
  retryBtn: {
    fontSize: 16,
    color: '#6c5ce7',
    fontWeight: 'bold',
    padding: 12,
    borderWidth: 1,
    borderColor: '#6c5ce7',
    borderRadius: 8,
  },
});
