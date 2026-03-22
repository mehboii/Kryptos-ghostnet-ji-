import React, { useRef, useState, useEffect } from 'react';
import { View, StyleSheet, BackHandler, Platform, SafeAreaView, Text, ActivityIndicator } from 'react-native';
import { WebView } from 'react-native-webview';
import * as SplashScreen from 'expo-splash-screen';

const GHOSTNET_URL = 'https://ghostnet-ji-production.up.railway.app';

export default function App() {
  const webViewRef = useRef<WebView>(null);
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(true); // fall-back spinner

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

  // Force minimum touch targets and responsive scrolling behavior
  const INJECTED_JS = `
    try {
      if (!document.querySelector('meta[name="viewport"]')) {
        var meta = document.createElement('meta');
        meta.name = 'viewport';
        meta.content = 'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, shrink-to-fit=no';
        document.head.appendChild(meta);
      }
      var style = document.createElement('style');
      style.innerHTML = \`
        html, body {
           -webkit-overflow-scrolling: touch; 
           overflow-y: auto !important; 
           overflow-x: hidden; 
           touch-action: pan-y pan-x;
        }
        * {
           -webkit-tap-highlight-color: transparent;
        }
      \`;
      document.head.appendChild(style);
    } catch(e) {}
    true;
  `;

  if (error) {
    SplashScreen.hideAsync();
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.errorContainer}>
          <Text style={styles.errorText}>Unable to connect to GhostNet</Text>
          <Text style={styles.errorSub}>Wait for the web app to spin up or check your connection</Text>
          <Text
            style={styles.retryBtn}
            onPress={() => { setError(false); setLoading(true); }}
          >
            Retry
          </Text>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <WebView
        ref={webViewRef}
        source={{ uri: GHOSTNET_URL }}
        style={styles.webview}
        javaScriptEnabled={true}
        domStorageEnabled={true}
        allowsBackForwardNavigationGestures={true}
        injectedJavaScript={INJECTED_JS}
        androidLayerType="hardware"
        onLoadStart={() => setLoading(true)}
        onLoadEnd={() => {
          setTimeout(() => SplashScreen.hideAsync(), 500);
          setLoading(false);
        }}
        onError={() => setError(true)}
        onHttpError={() => setError(true)}
        setSupportMultipleWindows={false}
        allowsInlineMediaPlayback={true}
        mediaPlaybackRequiresUserAction={Platform.OS !== 'android'}
        mixedContentMode="always"
        cacheEnabled={true}
        allowFileAccess={true}
        allowUniversalAccessFromFileURLs={true}
        originWhitelist={['*']}
        thirdPartyCookiesEnabled={true}
        sharedCookiesEnabled={true}
      />
      {/* If taking a really long time after Splash hides, show spinner */}
      {loading && (
        <View style={styles.loadingOverlay} pointerEvents="none">
          <ActivityIndicator size="large" color="#6c5ce7" />
        </View>
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0e27', // Matching the Splash color
  },
  webview: {
    flex: 1,
    backgroundColor: 'transparent',
  },
  loadingOverlay: {
    ...StyleSheet.absoluteFillObject,
    justifyContent: 'center',
    alignItems: 'center',
    zIndex: 9999,
  },
  errorContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#0a0e27',
    padding: 20,
  },
  errorText: {
    fontSize: 18,
    fontWeight: '700',
    color: '#ffffff',
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
    fontWeight: '700',
    color: '#6c5ce7',
    paddingHorizontal: 24,
    paddingVertical: 12,
    borderWidth: 1,
    borderColor: '#6c5ce7',
    borderRadius: 8,
    overflow: 'hidden',
  },
});
