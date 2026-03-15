# Walkthrough - Scribe Local Grammar Assistant

I have built a premium, local-first grammar and spelling checker called **Scribe**.

## Key Features

- **Privacy-First**: Uses `harper.js` (WebAssembly) to perform all analysis locally on your machine.
- **Premium Design**: A glassmorphism-inspired dark mode interface using `Outfit` and `Inter` typography.
- **Real-Time Analysis**: Debounced grammar and spelling checks as you type.
- **Interactive Suggestions**: A sidebar that displays detailed corrections with clickable suggestion buttons.

## Progress Overview

- [x] **Project Setup**: Vite + React initialized in `local-grammarly`.
- [x] **Design System**: Implemented in `index.css` with CSS variables and glassmorphism.
- [x] **Core Logic**: `useGrammar` hook developed for `harper.js` integration.
- [x] **UI Layout**: Sidebar, Editor, and Suggestions panel implemented.

## Verification Result

The application is ready to be launched. You can run it locally and test it with deliberate typos like "The quick brown fox jump over the lazy dog."
