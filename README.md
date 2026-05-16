# URLGuard

URLGuard is a Chrome extension that scans URLs for potential threats using VirusTotal and Google Safe Browsing. It can badge links on pages and scan URLs on demand from the extension popup or context menu.

## Setup

1. Open Chrome and go to `chrome://extensions`.
2. Enable Developer mode.
3. Choose **Load unpacked** and select this folder.
4. Open the extension options page and add your VirusTotal and/or Google Safe Browsing API key.

## Files

- `manifest.json` defines the Chrome extension configuration.
- `background.js` handles scanning, API calls, badges, and context menu actions.
- `content.js` and `content.css` annotate links on pages.
- `popup.html` and `popup.js` power the extension popup.
- `options.html` and `options.js` manage API keys and scan settings.
