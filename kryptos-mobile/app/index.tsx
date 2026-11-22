import 'react-native-gesture-handler';
import React, { useRef, useState, useEffect } from 'react';
import { View, Image, StyleSheet, BackHandler, Platform, Text, StatusBar, Animated, TouchableOpacity, AccessibilityInfo } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { WebView } from 'react-native-webview';
import * as SplashScreen from 'expo-splash-screen';
import { useKeepAwake } from 'expo-keep-awake';

const KRYPTOS_URL = 'https://kryptos-ji-production.up.railway.app';

export default function App() {
  useKeepAwake();

  const webViewRef = useRef<WebView>(null);
  const [error, setError] = useState(false);
  const [showSplash, setShowSplash] = useState(true);
  const reduceMotion = useRef(false);
  useEffect(() => {
    AccessibilityInfo.isReduceMotionEnabled().then(value => { reduceMotion.current = value; });
    const listener = AccessibilityInfo.addEventListener('reduceMotionChanged', value => { reduceMotion.current = value; });
    return () => listener.remove();
  }, []);
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
    // The Kryptos web app finished loading — fade out the splash overlay
    setTimeout(() => {
      Animated.timing(fadeAnim, {
        toValue: 0,
        duration: reduceMotion.current ? 0 : 180,
        useNativeDriver: true,
      }).start(() => setShowSplash(false));
    }, 1200);
  };

  if (error) {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#020428" />
        <View style={styles.errorBox}>
          <Text style={styles.errorTitle}>Unable to connect to Kryptos</Text>
          <Text style={styles.errorSub}>Check your connection or wait for the server to wake up</Text>
          <TouchableOpacity onPress={() => { setError(false); setShowSplash(true); fadeAnim.setValue(1); }} activeOpacity={0.7}>
            <Text style={styles.retryBtn}>Retry</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#020428" />

      {/* Main WebView — loads Kryptos web app with identical UI */}
      <WebView
        ref={webViewRef}
        source={{ uri: KRYPTOS_URL }}
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
          <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center' }}>
            <Image source={require('../assets/images/kryptos-logo.png')} accessibilityLabel="Kryptos" resizeMode="contain" style={{ width: 180, height: 180 }} />
          </View>
        </Animated.View>
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
    color: '#e2e8f0',
    fontWeight: 'bold',
    marginBottom: 8,
  },
  errorSub: {
    fontSize: 14,
    color: '#64748b',
    marginBottom: 20,
    textAlign: 'center',
  },
  retryBtn: {
    fontSize: 16,
    color: '#ffffff',
    backgroundColor: '#252329',
    fontWeight: 'bold',
    padding: 12,
    borderWidth: 1,
    borderColor: '#252329',
    borderRadius: 8,
  },
});
