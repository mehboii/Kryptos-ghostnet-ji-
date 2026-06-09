import React, { useRef, useState, useEffect, useCallback } from 'react';
import { StyleSheet, View, BackHandler, StatusBar, Image, Text, Platform, KeyboardAvoidingView, PermissionsAndroid } from 'react-native';
import { WebView } from 'react-native-webview';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import * as SplashScreen from 'expo-splash-screen';
import ProximityBLE from './src/ble/ProximityBLE';
import { BLE_BRIDGE_SHIM } from './src/ble/bridgeShim';

SplashScreen.preventAutoHideAsync();

const OFFLINE_SOURCE = Platform.OS === 'android'
  ? { uri: 'file:///android_asset/offline-web/index.html' }
  : require('./offline-web/index.html');

export default function App() {
  const webViewRef = useRef(null);
  const bleRef = useRef(null);
  const [canGoBack, setCanGoBack] = useState(false);
  const [webViewReady, setWebViewReady] = useState(false);

  // ── Native BLE transport bridge ──────────────────────────────────────────
  // proximity-connect.js (in the WebView) calls window.GhostNetBLE.* which RPCs
  // here; this routes to the native ProximityBLE radio and pushes events back.
  const injectToWeb = useCallback((js) => {
    if (webViewRef.current) webViewRef.current.injectJavaScript(js + '\ntrue;');
  }, []);

  const emitToWeb = useCallback((event, data) => {
    injectToWeb(
      `window.GhostNetBLE && window.GhostNetBLE._event(${JSON.stringify(event)}, ${JSON.stringify(data || {})});`
    );
  }, [injectToWeb]);

  const ackToWeb = useCallback((id, ok, payload) => {
    injectToWeb(
      `window.GhostNetBLE && window.GhostNetBLE._ack(${JSON.stringify(id)}, ${ok ? 'true' : 'false'}, ${JSON.stringify(payload ?? null)});`
    );
  }, [injectToWeb]);

  // Lazily construct the radio + forward all transport events to the web layer.
  const getBle = useCallback(async () => {
    if (!bleRef.current) {
      const ble = new ProximityBLE();
      await ble.init();
      const forward = [
        'deviceFound', 'deviceUpdated', 'centralWrite', 'centralConnected',
        'centralDisconnected', 'notification', 'disconnected', 'peripheralState', 'error',
      ];
      forward.forEach((evt) => ble.on(evt, (data) => emitToWeb(evt, data)));
      bleRef.current = ble;
    }
    return bleRef.current;
  }, [emitToWeb]);

  const handleBleCommand = useCallback(async (id, cmd, args) => {
    try {
      const ble = await getBle();
      let result = null;
      switch (cmd) {
        case 'isSupported': {
          const state = await ble.adapterState();
          result = { adapterState: state, peripheral: await ble.isPeripheralSupported() };
          break;
        }
        case 'isPeripheralSupported': result = await ble.isPeripheralSupported(); break;
        case 'requestPermissions': result = await ble.requestPermissions(); break;
        case 'adapterState': result = await ble.adapterState(); break;
        case 'startAdvertising': result = await ble.startAdvertising(args); break;
        case 'updatePseudonym': await ble.updatePseudonym(args.pseudonymHex); result = true; break;
        case 'stopAdvertising': await ble.stopAdvertising(); result = true; break;
        case 'startScan': ble.startScan(); result = true; break;
        case 'stopScan': ble.stopScan(); result = true; break;
        case 'connect': result = await ble.connect(args.deviceId); break;
        case 'disconnect': await ble.disconnect(args.deviceId); result = true; break;
        case 'read': result = await ble.read(args.deviceId, args.charUuid); break;
        case 'write': result = await ble.write(args.deviceId, args.charUuid, args.base64); break;
        case 'startNotifications': ble.startNotifications(args.deviceId, args.charUuid); result = true; break;
        case 'notifyData': await ble.notifyData(args.base64); result = true; break;
        default: throw new Error('Unknown BLE command: ' + cmd);
      }
      ackToWeb(id, true, result);
    } catch (e) {
      ackToWeb(id, false, { message: e.message || String(e) });
    }
  }, [getBle, ackToWeb]);

  const onWebViewMessage = useCallback((event) => {
    let msg;
    try { msg = JSON.parse(event.nativeEvent.data); } catch (_) { return; }
    if (!msg || msg.ns !== 'ble') return; // ignore non-BLE messages
    handleBleCommand(msg.id, msg.cmd, msg.args || {});
  }, [handleBleCommand]);

  useEffect(() => () => { if (bleRef.current) bleRef.current.destroy(); }, []);

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
            injectedJavaScriptBeforeContentLoaded={BLE_BRIDGE_SHIM}
            onMessage={onWebViewMessage}
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
