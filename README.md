# Lockbox

A small, polished file-encryption app. Choose a file, protect it with a password, and download an encrypted `.lockbox` copy. Select that copy later to decrypt it with the same password.

## Run it

This is a static web app with no build step or dependencies. Open `index.html` in a modern browser, or serve this folder locally (for example, `python -m http.server 8000`) and visit `http://localhost:8000`.

Web Crypto requires a secure context: use HTTPS or `localhost` for the encryption and decryption features. The browser never uploads your files. Keep a safe copy of your password—there is no password recovery.

## Security design

- AES-256-GCM provides encryption and authentication.
- A fresh random 16-byte salt and 12-byte IV are generated for every encryption.
- The AES key is derived from the password with PBKDF2-HMAC-SHA-256 (310,000 iterations).
- The binary file format contains an 8-byte magic/version header, salt, IV, and authenticated ciphertext.
- A wrong password or modified encrypted file fails authentication and does not produce a plaintext download.

This is a learning/demo app, not a substitute for an audited encryption product. Very large files are read into memory, so keep demo files modest in size. Anyone who obtains a `.lockbox` file can attempt offline password guesses; use a long, unique password.

## Demo checklist

1. Encrypt a small test file with a memorable demo password.
2. Decrypt the `.lockbox` download with that same password and compare the files.
3. Try a wrong password and confirm that decryption is refused.
4. Try drag-and-drop, the show-password control, and switching between encrypt/decrypt tabs.

## Split the work

- **Encryption:** `app.js` — password-based key derivation, AES-GCM, and file format.
- **Interface:** `index.html` and `styles.css` — responsive product UI and drag-and-drop.
- **Testing/presentation:** use the demo checklist above; present the workflow, local-only processing, and security choices.
