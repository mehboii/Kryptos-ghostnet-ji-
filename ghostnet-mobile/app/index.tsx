import React, { useRef, useState } from 'react';
import { View, StyleSheet, ActivityIndicator, BackHandler, Platform, SafeAreaView } from 'react-native';
import { WebView } from 'react-native-webview';

const GHOSTNET_URL = 'https://ghostnet-ji-production.up.railway.app';

export default function App() {
  const webViewRef = useRef<WebView>(null);
  const [loading, setLoading] = useState(true);

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

  // Inject CSS to make the web app mobile-friendly
  const INJECTED_CSS = `
    (function() {
      var meta = document.createElement('meta');
      meta.name = 'viewport';
      meta.content = 'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no';
      document.head.appendChild(meta);

      var style = document.createElement('style');
      style.textContent = \`
        /* Mobile-friendly overrides */
        body {
          overflow-x: hidden !important;
          -webkit-overflow-scrolling: touch !important;
        }
        
        /* Make sidebar collapse on mobile */
        .sidebar, .nav-sidebar, #sidebar {
          position: fixed !important;
          z-index: 1000 !important;
          width: 200px !important;
          transform: translateX(-100%) !important;
          transition: transform 0.3s ease !important;
        }
        .sidebar.open, .nav-sidebar.open, #sidebar.open {
          transform: translateX(0) !important;
        }
        
        /* Main content full width */
        .main-content, #main-content, .content {
          margin-left: 0 !important;
          width: 100% !important;
          padding: 8px !important;
        }
        
        /* Stat cards responsive */
        .stat-cards, .stats-row, .overview-stats {
          flex-wrap: wrap !important;
          gap: 8px !important;
        }
        .stat-card, .stat-item {
          min-width: 100px !important;
          flex: 1 1 30% !important;
        }
        
        /* Fix any fixed positioning issues */
        * {
          max-width: 100vw !important;
        }
        
        /* Improve touch targets */
        button, a, .clickable, [role="button"] {
          min-height: 44px !important;
          min-width: 44px !important;
        }
        
        /* Bottom nav mobile-friendly */
        .mobile-nav, .bottom-nav {
          padding-bottom: env(safe-area-inset-bottom) !important;
        }
      \`;
      document.head.appendChild(style);
    })();
    true;
  `;

  return (
    <SafeAreaView style={styles.container}>
      <WebView
        ref={webViewRef}
        source={{ uri: GHOSTNET_URL }}
        style={styles.webview}
        javaScriptEnabled={true}
        domStorageEnabled={true}
        startInLoadingState={true}
        allowsBackForwardNavigationGestures={true}
        injectedJavaScript={INJECTED_CSS}
        onLoadEnd={() => setLoading(false)}
        renderLoading={() => (
          <View style={styles.loadingContainer}>
            <ActivityIndicator size="large" color="#6c5ce7" />
          </View>
        )}
        userAgent="Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
        setSupportMultipleWindows={false}
        allowsInlineMediaPlayback={true}
        mediaPlaybackRequiresUserAction={false}
        mixedContentMode="compatibility"
        cacheEnabled={true}
        cacheMode="LOAD_DEFAULT"
      />
      {loading && (
        <View style={styles.splashOverlay}>
          <ActivityIndicator size="large" color="#6c5ce7" />
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
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#020428',
  },
  splashOverlay: {
    ...StyleSheet.absoluteFillObject,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#020428',
  },
});
