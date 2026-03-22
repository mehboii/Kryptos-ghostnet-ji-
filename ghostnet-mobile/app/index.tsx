import React, { useRef, useState, useEffect } from 'react';
import { View, StyleSheet, BackHandler, Platform, Text, StatusBar, Animated } from 'react-native';
import { WebView } from 'react-native-webview';
import * as SplashScreen from 'expo-splash-screen';

const GHOSTNET_URL = 'https://ghostnet-ji-production.up.railway.app';

const SPLASH_HTML = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      background: #020428; display: flex; justify-content: center;
      align-items: center; height: 100vh; overflow: hidden;
    }
    .splash {
      position: relative; width: 260px; height: 260px;
      display: flex; justify-content: center; align-items: center;
    }
    .glow {
      position: absolute; width: 180px; height: 180px;
      background: radial-gradient(circle, rgba(88,217,255,0.28) 0%, rgba(88,217,255,0.08) 45%, transparent 75%);
      border-radius: 50%; filter: blur(18px); opacity: 0;
      animation: glowIn 1.1s ease-out forwards;
    }
    .logo {
      width: 180px; opacity: 0; transform: scale(0.82);
      animation: logoReveal 1.2s ease-out forwards;
      animation-delay: 0.2s; filter: drop-shadow(0 0 18px rgba(88,217,255,0.15));
    }
    .eye-left, .eye-right {
      opacity: 0; animation: eyesReveal 0.35s ease-out forwards; animation-delay: 1s;
    }
    @keyframes glowIn {
      0% { opacity: 0; transform: scale(0.6); }
      100% { opacity: 1; transform: scale(1.15); }
    }
    @keyframes logoReveal {
      0% { opacity: 0; transform: scale(0.82) translateY(8px); }
      70% { opacity: 1; transform: scale(1.04) translateY(0); }
      100% { opacity: 1; transform: scale(1) translateY(0); }
    }
    @keyframes eyesReveal {
      0% { opacity: 0; transform: translateY(4px); }
      100% { opacity: 1; transform: translateY(0); }
    }
  </style>
</head>
<body>
  <div class="splash">
    <div class="glow"></div>
    <svg class="logo" viewBox="0 0 512 512" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M256 70C206 88 162 99 140 112V231C140 328 193 391 256 438C319 391 372 328 372 231V112C350 99 306 88 256 70Z" fill="url(#shieldGradient)"/>
      <path d="M258 127C215 127 192 160 192 215V309C192 309 219 296 241 280C258 328 284 347 284 347C319 311 330 270 330 217C330 161 302 127 258 127Z" fill="#03062E"/>
      <path class="eye-left" d="M228 196C236 189 248 191 255 199C248 206 235 207 228 196Z" fill="white"/>
      <path class="eye-right" d="M284 199C291 191 303 189 311 196C304 207 291 206 284 199Z" fill="white"/>
      <defs>
        <linearGradient id="shieldGradient" x1="140" y1="70" x2="372" y2="438" gradientUnits="userSpaceOnUse">
          <stop stop-color="#F4F4F6"/>
          <stop offset="1" stop-color="#58D9FF"/>
        </linearGradient>
      </defs>
    </svg>
  </div>
</body>
</html>
`;

export default function App() {
  const webViewRef = useRef<WebView>(null);
  const [error, setError] = useState(false);
  const [showSplash, setShowSplash] = useState(true);
  const fadeAnim = useRef(new Animated.Value(1)).current;

  useEffect(() => {
    // Kill the native static splash screen immediately so our HTML animation shows
    setTimeout(() => SplashScreen.hideAsync(), 50);
  }, []);

  // Handle Android back button for WebView navigation
  useEffect(() => {
    if (Platform.OS !== 'android') return;
    const onBackPress = () => {
      if (webViewRef.current) {
        webViewRef.current.goBack();
        return true;
      }
      return false;
    };
    const sub = BackHandler.addEventListener('hardwareBackPress', onBackPress);
    return () => sub.remove();
  }, []);

  const handleWebViewLoad = () => {
    // The GhostNet web app finished loading — fade out the splash overlay
    setTimeout(() => {
      Animated.timing(fadeAnim, {
        toValue: 0,
        duration: 600,
        useNativeDriver: true,
      }).start(() => setShowSplash(false));
    }, 1200);
  };

  if (error) {
    return (
      <View style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#020428" />
        <View style={styles.errorBox}>
          <Text style={styles.errorTitle}>Unable to connect to GhostNet</Text>
          <Text style={styles.errorSub}>Check your connection or wait for the server to wake up</Text>
          <Text style={styles.retryBtn} onPress={() => { setError(false); setShowSplash(true); fadeAnim.setValue(1); }}>Retry</Text>
        </View>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#020428" />

      {/* Main WebView — loads GhostNet web app with identical UI */}
      <WebView
        ref={webViewRef}
        source={{ uri: GHOSTNET_URL }}
        style={styles.webview}
        javaScriptEnabled={true}
        domStorageEnabled={true}
        androidLayerType="hardware"
        onLoadEnd={handleWebViewLoad}
        onError={() => setError(true)}
        setSupportMultipleWindows={false}
        mixedContentMode="always"
        allowFileAccess={true}
        originWhitelist={['*']}
        thirdPartyCookiesEnabled={true}
        sharedCookiesEnabled={true}
        cacheEnabled={true}
      />

      {/* Dynamic animated splash overlay — sits on top until web app is ready */}
      {showSplash && (
        <Animated.View style={[styles.splashOverlay, { opacity: fadeAnim }]} pointerEvents="none">
          <WebView
            source={{ html: SPLASH_HTML }}
            style={{ flex: 1, backgroundColor: '#020428' }}
            scrollEnabled={false}
            showsVerticalScrollIndicator={false}
            showsHorizontalScrollIndicator={false}
          />
        </Animated.View>
      )}
    </View>
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
    backgroundColor: '#020428',
    zIndex: 9999,
    elevation: 9999,
  },
  errorBox: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  },
  errorTitle: {
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
