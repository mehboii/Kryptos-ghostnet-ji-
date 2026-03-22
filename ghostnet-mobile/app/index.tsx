import React, { useRef, useState } from 'react';
import { View, StyleSheet, ActivityIndicator, BackHandler, Platform, SafeAreaView, Text } from 'react-native';
import { WebView } from 'react-native-webview';

const GHOSTNET_URL = 'https://ghostnet-ji-production.up.railway.app';

export default function App() {
  const webViewRef = useRef<WebView>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  // Handle Android back button
  React.useEffect(() => {
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

  // Only inject viewport meta — no CSS overrides that could break functionality
  const INJECTED_JS = `
    (function() {
      var existing = document.querySelector('meta[name="viewport"]');
      if (!existing) {
        var meta = document.createElement('meta');
        meta.name = 'viewport';
        meta.content = 'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no';
        document.head.appendChild(meta);
      }
    })();
    true;
  `;

  if (error) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.errorContainer}>
          <Text style={styles.errorText}>Unable to connect to GhostNet</Text>
          <Text style={styles.errorSub}>Check your internet connection</Text>
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
        startInLoadingState={false}
        allowsBackForwardNavigationGestures={true}
        injectedJavaScript={INJECTED_JS}
        onLoadEnd={() => setLoading(false)}
        onError={() => setError(true)}
        onHttpError={() => setError(true)}
        setSupportMultipleWindows={false}
        allowsInlineMediaPlayback={true}
        mediaPlaybackRequiresUserAction={false}
        mixedContentMode="always"
        cacheEnabled={true}
        javaScriptCanOpenWindowsAutomatically={true}
        allowFileAccess={true}
        allowUniversalAccessFromFileURLs={true}
        originWhitelist={['*']}
        thirdPartyCookiesEnabled={true}
        sharedCookiesEnabled={true}
        webviewDebuggingEnabled={true}
      />
      {loading && (
        <View style={styles.splashOverlay}>
          <Text style={styles.logoText}>GHOST{'\n'}NET</Text>
          <ActivityIndicator size="large" color="#6c5ce7" style={{ marginTop: 20 }} />
        </View>
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#020428',
  },
  webview: {
    flex: 1,
    backgroundColor: '#020428',
  },
  splashOverlay: {
    ...StyleSheet.absoluteFillObject,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#020428',
  },
  logoText: {
    fontSize: 32,
    fontWeight: '900',
    color: '#6c5ce7',
    textAlign: 'center',
    letterSpacing: 4,
  },
  errorContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#020428',
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
