# Link Vault

A local-first Chrome extension for organizing bookmarks into folders, with optional encrypted credentials per link — synced through your own cloud drive (OneDrive, Google Drive, etc.), no external server involved.

## Features

- **Folders & links** — organize bookmarks into custom folders, tag and search across all of them
- **Cloud sync without a backend** — data lives in a single `.json` file inside your OneDrive/Google Drive folder; the extension reads/writes it directly via the File System Access API, and your existing cloud client handles the sync
- **Encrypted credentials (optional)** — attach a username/password to any link, protected with AES-256-GCM, key derived from a master password via PBKDF2 (250,000 iterations). The master password is never stored; only a verifier is kept to check it on unlock
- **Import / Export** — load or download the data file as portable JSON at any time
- **Persistent file link** — the picked file handle is remembered (IndexedDB) across sessions; reconnect with a single click after a browser restart
- **Favicon lookup, autosave, dark UI**

## Installation

1. Download or clone this repo
2. Open `chrome://extensions`
3. Enable **Developer mode** (top right)
4. Click **Load unpacked** and select the project folder
5. Pin the extension icon to your toolbar

Clicking the icon opens a dedicated window (not the limited Chrome popup) so there's room to work with folders and links comfortably.

## Usage

- **Open…** — link an existing `.json` file (e.g. on your OneDrive) for live read/write sync
- **Import…** — load a `.json` file into memory (replaces current data; written to the linked file on next save if one is open)
- **Export** — download the current data as `Rep.json`
- **+ Lien** — add a link, optionally with a username/password (creates a master password on first use)
- **🔑 Identifiants** — decrypt and reveal a link's saved credentials on demand
- **🔒 Verrouiller** — clear the decryption key from memory

## Data format

A single JSON file with `folders`, `links`, and an optional `security` block (PBKDF2 salt + encrypted verifier) used only when at least one credential has been saved. Credentials are stored as `{iv, data}` AES-GCM ciphertext — unreadable without the master password.

## Security notes

- All encryption/decryption happens client-side via the Web Crypto API; nothing is transmitted anywhere
- The master password is never written to disk or synced — losing it means losing access to saved credentials (links themselves stay readable)
- No analytics, no remote requests other than favicon lookups (`google.com/s2/favicons`)

## Browser support

Requires the File System Access API (Chrome/Edge and other Chromium-based browsers). Not available in Firefox or Safari.

## License

MIT
