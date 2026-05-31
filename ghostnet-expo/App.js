import React, { useRef, useState, useEffect, useCallback } from 'react';
import { StyleSheet, View, BackHandler, StatusBar, Image, Text, Platform, KeyboardAvoidingView, PermissionsAndroid } from 'react-native';
import { WebView } from 'react-native-webview';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import * as SplashScreen from 'expo-splash-screen';

SplashScreen.preventAutoHideAsync();

const OFFLINE_SOURCE = Platform.OS === 'android'
  ? { uri: 'file:///android_asset/offline-web/index.html' }
  : require('./offline-web/index.html');

export default function App() {
  const webViewRef = useRef(null);
  const [canGoBack, setCanGoBack] = useState(false);
  const [webViewReady, setWebViewReady] = useState(false);

  // Request camera permission up-front so the in-WebView QR scanner (getUserMedia)
  // can access the camera. Without the native grant Android silently denies it.
  useEffect(() => {
    if (Platform.OS === 'android' && PermissionsAndroid?.PERMISSIONS?.CAMERA) {
      PermissionsAndroid.request(PermissionsAndroid.PERMISSIONS.CAMERA, {
        title: 'Camera access',
        message: 'GhostNet needs the camera to scan QR codes to connect.',
        buttonPositive: 'Allow',
        buttonNegative: 'Deny',
      }).catch(() => {});
    }
  }, []);

  useEffect(() => {
    const handleBackPress = () => {
      if (canGoBack && webViewRef.current) {
        webViewRef.current.goBack();
        return true;
      }
      return false;
    };

    BackHandler.addEventListener('hardwareBackPress', handleBackPress);
    return () => {
      BackHandler.removeEventListener('hardwareBackPress', handleBackPress);
    };
  }, [canGoBack]);

  const onWebViewLoad = useCallback(() => {
    setWebViewReady(true);
    SplashScreen.hideAsync();
  }, []);

  return (
    <SafeAreaProvider>
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#0b0e14" />
        <KeyboardAvoidingView
          style={styles.keyboardView}
          behavior={Platform.OS === 'ios' ? 'padding' : undefined}
          keyboardVerticalOffset={0}
        >
          <WebView
            ref={webViewRef}
            source={OFFLINE_SOURCE}
            style={[styles.webview, !webViewReady && styles.hidden]}
            onNavigationStateChange={(navState) => {
              setCanGoBack(navState.canGoBack);
            }}
            onLoadEnd={onWebViewLoad}
            startInLoadingState={false}
            allowsInlineMediaPlayback={true}
            mediaPlaybackRequiresUserAction={false}
            javaScriptEnabled={true}
            domStorageEnabled={true}
            cacheEnabled={true}
            cacheMode="LOAD_DEFAULT"
            originWhitelist={['file://', 'about:blank']}
            allowFileAccess={true}
            allowFileAccessFromFileURLs={true}
            allowUniversalAccessFromFileURLs={true}
            onShouldStartLoadWithRequest={(request) => {
              return request.url.startsWith('file://') || request.url === 'about:blank';
            }}
            bounces={false}
            overScrollMode="never"
            setSupportMultipleWindows={false}
            androidLayerType="hardware"
          />
          {!webViewReady && (
            <View style={styles.loadingContainer}>
              <Image
                source={require('./assets/ghostnet-logo.png')}
                style={styles.loadingLogo}
                resizeMode="contain"
              />
              <Text style={styles.loadingText}>GhostNet</Text>
              <Text style={styles.loadingSubtext}>Encrypted Mesh Network</Text>
            </View>
          )}
        </KeyboardAvoidingView>
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0b0e14',
  },
  keyboardView: {
    flex: 1,
  },
  webview: {
    flex: 1,
    backgroundColor: '#0b0e14',
  },
  hidden: {
    opacity: 0,
  },
  loadingContainer: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: '#0b0e14',
    justifyContent: 'center',
    alignItems: 'center',
  },
  loadingLogo: {
    width: 120,
    height: 120,
    marginBottom: 20,
  },
  loadingText: {
    color: '#ffffff',
    fontSize: 24,
    fontWeight: '700',
    letterSpacing: 1,
  },
  loadingSubtext: {
    color: '#64748b',
    fontSize: 14,
    marginTop: 8,
    letterSpacing: 0.5,
  },
});
