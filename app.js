const ITERATIONS = 310_000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const MAGIC = new Uint8Array([76, 66, 79, 88, 1, 13, 10, 0]); // LBOX, format version 1

const form = document.querySelector("#file-form");
const fileInput = document.querySelector("#file-input");
const dropZone = document.querySelector("#drop-zone");
const fileName = document.querySelector("#file-name");
const fileChip = document.querySelector("#file-chip");
const dropTitle = document.querySelector("#drop-title");
const dropHint = document.querySelector("#drop-hint");
const fileLabel = document.querySelector("#file-label");
const passwordLabel = document.querySelector("#password-label");
const passwordInput = document.querySelector("#password-input");
const confirmInput = document.querySelector("#confirm-input");
const confirmWrap = document.querySelector("#confirm-wrap");
const submitButton = document.querySelector("#submit-button");
const submitLabel = document.querySelector("#submit-label");
const statusMessage = document.querySelector("#status-message");
const fileError = document.querySelector("#file-error");
const passwordError = document.querySelector("#password-error");
const confirmError = document.querySelector("#confirm-error");

let mode = "encrypt";
let selectedFile = null;
let busy = false;

function setMode(nextMode) {
  if (busy || (nextMode !== "encrypt" && nextMode !== "decrypt")) return;
  mode = nextMode;
  document.querySelectorAll(".mode-tab").forEach((tab) => {
    const active = tab.dataset.mode === mode;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
    tab.tabIndex = active ? 0 : -1;
  });
  fileLabel.textContent = mode === "encrypt" ? "File to encrypt" : "Encrypted file to decrypt";
  passwordLabel.textContent = mode === "encrypt" ? "Create a password" : "Enter your password";
  passwordInput.autocomplete = mode === "encrypt" ? "new-password" : "current-password";
  confirmWrap.hidden = mode === "decrypt";
  confirmInput.required = mode === "encrypt";
  submitLabel.textContent = mode === "encrypt" ? "Encrypt file" : "Decrypt file";
  dropTitle.textContent = selectedFile ? selectedFile.name : "Drop a file here";
  dropHint.innerHTML = mode === "decrypt"
    ? 'or <span class="browse-link">browse your device</span> <span class="hint-suffix">· .lockbox file</span>'
    : 'or <span class="browse-link">browse your device</span>';
  clearErrors();
  statusMessage.hidden = true;
}

function clearErrors() {
  fileError.textContent = "";
  passwordError.textContent = "";
  confirmError.textContent = "";
  passwordInput.removeAttribute("aria-invalid");
  confirmInput.removeAttribute("aria-invalid");
}

function chooseFile(file) {
  if (!file || busy) return;
  selectedFile = file;
  fileInput.value = "";
  fileChip.hidden = false;
  fileName.textContent = file.name;
  dropTitle.textContent = "File ready";
  dropHint.textContent = "Select another file to replace it";
  clearErrors();
  statusMessage.hidden = true;
}

function removeFile(event) {
  event?.stopPropagation();
  selectedFile = null;
  fileChip.hidden = true;
  fileName.textContent = "";
  dropTitle.textContent = "Drop a file here";
  dropHint.innerHTML = mode === "decrypt"
    ? 'or <span class="browse-link">browse your device</span> <span class="hint-suffix">· .lockbox file</span>'
    : 'or <span class="browse-link">browse your device</span>';
  clearErrors();
  statusMessage.hidden = true;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function deriveKey(password, salt) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptFile(file, password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const key = await deriveKey(password, salt);
  const plaintext = await file.arrayBuffer();
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  const output = new Uint8Array(MAGIC.length + SALT_LENGTH + IV_LENGTH + ciphertext.byteLength);
  output.set(MAGIC, 0);
  output.set(salt, MAGIC.length);
  output.set(iv, MAGIC.length + SALT_LENGTH);
  output.set(new Uint8Array(ciphertext), MAGIC.length + SALT_LENGTH + IV_LENGTH);
  return new Blob([output], { type: "application/octet-stream" });
}

async function decryptFile(file, password) {
  const data = new Uint8Array(await file.arrayBuffer());
  const headerLength = MAGIC.length + SALT_LENGTH + IV_LENGTH;
  if (data.length < headerLength + 16 || !MAGIC.every((byte, index) => data[index] === byte)) {
    throw new Error("This file isn't a valid Lockbox encrypted file.");
  }
  const saltStart = MAGIC.length;
  const ivStart = saltStart + SALT_LENGTH;
  const key = await deriveKey(password, data.subarray(saltStart, ivStart));
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: data.subarray(ivStart, ivStart + IV_LENGTH) },
      key,
      data.subarray(headerLength),
    );
    return new Blob([plaintext], { type: "application/octet-stream" });
  } catch {
    throw new Error("Couldn't unlock this file. Check your password and try again.");
  }
}

function outputFilename(inputName) {
  if (mode === "encrypt") return `${inputName}.lockbox`;
  const suffix = ".lockbox";
  if (inputName.toLowerCase().endsWith(suffix)) {
    const original = inputName.slice(0, -suffix.length);
    return original || "decrypted-file";
  }
  return `${inputName}.decrypted`;
}

function download(blob, name) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.style.display = "none";
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

function setBusy(value) {
  busy = value;
  submitButton.disabled = value;
  document.querySelectorAll(".mode-tab").forEach((tab) => { tab.disabled = value; });
  dropZone.classList.toggle("is-busy", value);
  submitLabel.textContent = value ? (mode === "encrypt" ? "Encrypting…" : "Decrypting…") : (mode === "encrypt" ? "Encrypt file" : "Decrypt file");
}

function showStatus(message, kind) {
  statusMessage.textContent = message;
  statusMessage.className = `status-message ${kind}`;
  statusMessage.hidden = false;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy) return;
  clearErrors();
  statusMessage.hidden = true;
  let valid = true;
  if (!selectedFile) {
    fileError.textContent = "Choose a file to continue.";
    valid = false;
  }
  if (!passwordInput.value) {
    passwordError.textContent = "Enter your password to continue.";
    passwordInput.setAttribute("aria-invalid", "true");
    valid = false;
  }
  if (mode === "encrypt" && passwordInput.value && passwordInput.value !== confirmInput.value) {
    confirmError.textContent = "Those passwords don't match.";
    confirmInput.setAttribute("aria-invalid", "true");
    valid = false;
  }
  if (!valid) return;
  if (!window.crypto?.subtle) {
    showStatus("Secure encryption requires a modern browser and a secure connection (HTTPS or localhost).", "error");
    return;
  }

  setBusy(true);
  try {
    const output = mode === "encrypt"
      ? await encryptFile(selectedFile, passwordInput.value)
      : await decryptFile(selectedFile, passwordInput.value);
    const name = outputFilename(selectedFile.name);
    download(output, name);
    showStatus(`${mode === "encrypt" ? "Encrypted" : "Decrypted"} successfully. Your download is ready: ${name}`, "success");
  } catch (error) {
    showStatus(error instanceof Error ? error.message : "Something went wrong. Please try again.", "error");
  } finally {
    setBusy(false);
  }
});

document.querySelectorAll(".mode-tab").forEach((tab) => {
  tab.addEventListener("click", () => setMode(tab.dataset.mode));
  tab.addEventListener("keydown", (event) => {
    if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
      event.preventDefault();
      const next = tab.dataset.mode === "encrypt" ? "decrypt" : "encrypt";
      setMode(next);
      document.querySelector(`[data-mode="${next}"]`).focus();
    }
  });
});

dropZone.addEventListener("click", (event) => {
  if (event.target.closest("#remove-file") || busy) return;
  fileInput.click();
});
dropZone.addEventListener("keydown", (event) => {
  if ((event.key === "Enter" || event.key === " ") && !busy) {
    event.preventDefault();
    fileInput.click();
  }
});
fileInput.addEventListener("change", () => chooseFile(fileInput.files?.[0]));
document.querySelector("#remove-file").addEventListener("click", removeFile);

for (const eventName of ["dragenter", "dragover"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    if (!busy) dropZone.classList.add("is-dragging");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("is-dragging");
  });
}
dropZone.addEventListener("drop", (event) => chooseFile(event.dataTransfer?.files?.[0]));

document.querySelector("#toggle-password").addEventListener("click", (event) => {
  const button = event.currentTarget;
  const visible = passwordInput.type === "text";
  passwordInput.type = visible ? "password" : "text";
  button.textContent = visible ? "Show" : "Hide";
  button.setAttribute("aria-label", `${visible ? "Show" : "Hide"} password`);
});
document.querySelector("#toggle-confirm").addEventListener("click", (event) => {
  const button = event.currentTarget;
  const visible = confirmInput.type === "text";
  confirmInput.type = visible ? "password" : "text";
  button.textContent = visible ? "Show" : "Hide";
  button.setAttribute("aria-label", `${visible ? "Show" : "Hide"} password confirmation`);
});
