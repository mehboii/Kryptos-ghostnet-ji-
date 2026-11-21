const { app, BrowserWindow, Menu, shell } = require('electron');
const path = require('path');

// ── Config ──────────────────────────────────────────────────────────────────
const KRYPTOS_URL = 'https://kryptos-ji.vercel.app';
const APP_NAME = 'Kryptos';

let mainWindow;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1280,
        height: 800,
        minWidth: 400,
        minHeight: 600,
        title: APP_NAME,
        icon: path.join(__dirname, 'icon.png'),
        backgroundColor: '#0a0e17',
        autoHideMenuBar: true,
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            sandbox: true,
        },
        // Frameless dark theme
        titleBarStyle: 'hidden',
        titleBarOverlay: {
            color: '#0a0e17',
            symbolColor: '#00f0ff',
            height: 36
        },
    });

    // Load the Kryptos web app
    mainWindow.loadURL(KRYPTOS_URL);

    // Open external links in the system browser
    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        if (!url.startsWith(KRYPTOS_URL)) {
            shell.openExternal(url);
            return { action: 'deny' };
        }
        return { action: 'allow' };
    });

    // Inject native platform detection so the app knows it's on desktop
    // TODO: Move this executeJavaScript call to a preload script for better security isolation
    mainWindow.webContents.on('did-finish-load', () => {
        mainWindow.webContents.executeJavaScript(`
            window.__KRYPTOS_DESKTOP__ = true;
            window.__KRYPTOS_PLATFORM__ = 'desktop-electron';
            console.log('[Kryptos Desktop] Running as native Electron app');
        `);
    });

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

// Remove the default menu
Menu.setApplicationMenu(null);

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    app.quit();
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});

// Security: prevent navigation to unknown origins
app.on('web-contents-created', (event, contents) => {
    contents.on('will-navigate', (event, url) => {
        const allowed = ['kryptos-ji.vercel.app', 'kryptos-ji-production.up.railway.app', 'localhost'];
        const parsed = new URL(url);
        if (!allowed.includes(parsed.hostname)) {
            event.preventDefault();
        }
    });
});
