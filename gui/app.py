"""Tkinter GUI for RSA-OAEP-256 file encryption and decryption."""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext
import tkinter as tk
from tkinter import ttk

from crypto_utils.cipher_format import validate_ciphertext_format
from crypto_utils.decryptor import decrypt_file
from crypto_utils.encryptor import encrypt_file
from crypto_utils.hash_utils import sha256_file
from crypto_utils.key_utils import (
    load_private_key_from_hex_file,
    load_public_key_from_hex_file,
    save_key_to_hex_file,
)
from crypto_utils.rsa_core import generate_keypair, get_key_size_bytes


DEFAULT_KEYS_DIR = Path("keys")
DEFAULT_OUTPUTS_DIR = Path("outputs")


def derive_decryption_output_path(
    plaintext_path: str | Path,
    output_dir: str | Path = DEFAULT_OUTPUTS_DIR,
) -> Path:
    """Return the default decrypted output path for a selected plaintext file."""
    source = Path(plaintext_path)
    if not source.name:
        return Path(output_dir) / "decrypted_output.bin"
    return Path(output_dir) / f"decrypted_{source.name}"


class RSAOAEPApp:
    """Small demo GUI that integrates the repository's crypto pipeline."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("RSA-OAEP-256 File Encryption and Decryption")
        self.root.geometry("900x760")
        self.root.minsize(820, 680)

        self.key_dir_var = tk.StringVar(value=str(DEFAULT_KEYS_DIR))
        self.plaintext_var = tk.StringVar()
        self.public_key_var = tk.StringVar(value=str(DEFAULT_KEYS_DIR / "public_key.hex"))
        self.cipher_output_var = tk.StringVar(value=str(DEFAULT_OUTPUTS_DIR / "ciphertext.bin"))
        self.cipher_input_var = tk.StringVar(value=str(DEFAULT_OUTPUTS_DIR / "ciphertext.bin"))
        self.private_key_var = tk.StringVar(value=str(DEFAULT_KEYS_DIR / "private_key.hex"))
        self.plain_output_var = tk.StringVar(value=str(DEFAULT_OUTPUTS_DIR / "decrypted_output.bin"))
        self.original_hash_file_var = tk.StringVar()
        self.decrypted_hash_file_var = tk.StringVar(value=str(DEFAULT_OUTPUTS_DIR / "decrypted_output.bin"))
        self.original_hash_var = tk.StringVar()
        self.decrypted_hash_var = tk.StringVar()
        self.hash_match_var = tk.StringVar(value="No comparison yet")

        self.action_buttons: list[ttk.Button] = []
        self.plaintext_var.trace_add("write", self._on_plaintext_changed)

        self._configure_style()
        self._build_layout()
        self._log("Ready. Generate keys, then encrypt, decrypt, and compare hashes.")

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        style.configure("Section.TLabelframe", padding=10)
        style.configure("Section.TLabelframe.Label", font=("Segoe UI", 10, "bold"))
        style.configure("Status.TLabel", font=("Segoe UI", 10, "bold"))

    def _build_layout(self) -> None:
        container = ttk.Frame(self.root, padding=12)
        container.pack(fill=tk.BOTH, expand=True)
        container.columnconfigure(0, weight=1)

        title = ttk.Label(
            container,
            text="RSA-OAEP-256 File Encryption and Decryption",
            font=("Segoe UI", 16, "bold"),
        )
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        key_section = ttk.LabelFrame(
            container, text="Key Generation", style="Section.TLabelframe"
        )
        key_section.grid(row=1, column=0, sticky="ew", pady=5)
        self._build_key_section(key_section)

        encrypt_section = ttk.LabelFrame(
            container, text="Encryption", style="Section.TLabelframe"
        )
        encrypt_section.grid(row=2, column=0, sticky="ew", pady=5)
        self._build_encrypt_section(encrypt_section)

        decrypt_section = ttk.LabelFrame(
            container, text="Decryption", style="Section.TLabelframe"
        )
        decrypt_section.grid(row=3, column=0, sticky="ew", pady=5)
        self._build_decrypt_section(decrypt_section)

        hash_section = ttk.LabelFrame(
            container, text="SHA-256 Validation", style="Section.TLabelframe"
        )
        hash_section.grid(row=4, column=0, sticky="ew", pady=5)
        self._build_hash_section(hash_section)

        log_section = ttk.LabelFrame(container, text="Status Log", style="Section.TLabelframe")
        log_section.grid(row=5, column=0, sticky="nsew", pady=(5, 0))
        container.rowconfigure(5, weight=1)
        self._build_log_section(log_section)

    def _build_key_section(self, parent: ttk.LabelFrame) -> None:
        parent.columnconfigure(1, weight=1)
        self._path_row(parent, 0, "Output directory", self.key_dir_var, "directory")

        generate_button = ttk.Button(
            parent,
            text="Generate 2048-bit RSA Key Pair",
            command=self._generate_keys,
        )
        generate_button.grid(row=1, column=1, sticky="w", pady=(8, 0))
        self.action_buttons.append(generate_button)

    def _build_encrypt_section(self, parent: ttk.LabelFrame) -> None:
        parent.columnconfigure(1, weight=1)
        self._path_row(parent, 0, "Plaintext file", self.plaintext_var, "open")
        self._path_row(parent, 1, "Public key", self.public_key_var, "open")
        self._path_row(parent, 2, "Ciphertext output", self.cipher_output_var, "save")

        encrypt_button = ttk.Button(parent, text="Encrypt", command=self._encrypt)
        encrypt_button.grid(row=3, column=1, sticky="w", pady=(8, 0))
        self.action_buttons.append(encrypt_button)

    def _build_decrypt_section(self, parent: ttk.LabelFrame) -> None:
        parent.columnconfigure(1, weight=1)
        self._path_row(parent, 0, "Ciphertext file", self.cipher_input_var, "open")
        self._path_row(parent, 1, "Private key", self.private_key_var, "open")
        self._auto_output_row(parent, 2, "Plaintext output", self.plain_output_var)

        decrypt_button = ttk.Button(parent, text="Decrypt", command=self._decrypt)
        decrypt_button.grid(row=3, column=1, sticky="w", pady=(8, 0))
        self.action_buttons.append(decrypt_button)

    def _build_hash_section(self, parent: ttk.LabelFrame) -> None:
        parent.columnconfigure(1, weight=1)
        self._path_row(parent, 0, "Original file", self.original_hash_file_var, "open")
        self._path_row(parent, 1, "Decrypted file", self.decrypted_hash_file_var, "open")

        compare_button = ttk.Button(parent, text="Compare SHA-256", command=self._compare_hashes)
        compare_button.grid(row=2, column=1, sticky="w", pady=(8, 4))
        self.action_buttons.append(compare_button)

        ttk.Label(parent, text="Original SHA-256").grid(row=3, column=0, sticky="w", pady=2)
        self._readonly_entry(parent, self.original_hash_var).grid(
            row=3, column=1, columnspan=2, sticky="ew", pady=2
        )

        ttk.Label(parent, text="Decrypted SHA-256").grid(row=4, column=0, sticky="w", pady=2)
        self._readonly_entry(parent, self.decrypted_hash_var).grid(
            row=4, column=1, columnspan=2, sticky="ew", pady=2
        )

        ttk.Label(parent, textvariable=self.hash_match_var, style="Status.TLabel").grid(
            row=5, column=1, sticky="w", pady=(4, 0)
        )

    def _build_log_section(self, parent: ttk.LabelFrame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        self.log_text = scrolledtext.ScrolledText(parent, height=8, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.grid(row=0, column=0, sticky="nsew")

    def _path_row(
        self,
        parent: ttk.LabelFrame,
        row: int,
        label: str,
        variable: tk.StringVar,
        mode: str,
    ) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3)
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky="ew", padx=(8, 8), pady=3)
        ttk.Button(
            parent,
            text="Browse",
            command=lambda: self._browse(variable, mode),
        ).grid(row=row, column=2, sticky="e", pady=3)

    def _auto_output_row(
        self,
        parent: ttk.LabelFrame,
        row: int,
        label: str,
        variable: tk.StringVar,
    ) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3)
        ttk.Entry(parent, textvariable=variable, state="readonly").grid(
            row=row, column=1, sticky="ew", padx=(8, 8), pady=3
        )
        ttk.Label(parent, text="Auto").grid(row=row, column=2, sticky="e", pady=3)

    def _readonly_entry(self, parent: ttk.LabelFrame, variable: tk.StringVar) -> ttk.Entry:
        return ttk.Entry(parent, textvariable=variable, state="readonly")

    def _browse(self, variable: tk.StringVar, mode: str) -> None:
        current = variable.get().strip()
        initial_dir = str(Path(current).parent if current else Path.cwd())

        if mode == "directory":
            selected = filedialog.askdirectory(initialdir=initial_dir, title="Choose output directory")
        elif mode == "save":
            selected = filedialog.asksaveasfilename(
                initialdir=initial_dir,
                title="Choose output file",
                defaultextension=".bin",
                filetypes=(("Binary files", "*.bin"), ("All files", "*.*")),
            )
        else:
            selected = filedialog.askopenfilename(
                initialdir=initial_dir,
                title="Choose file",
                filetypes=(("All files", "*.*"),),
            )

        if selected:
            variable.set(selected)

    def _on_plaintext_changed(self, *_args) -> None:
        plaintext_path = self.plaintext_var.get().strip()
        if not plaintext_path:
            return

        decrypted_output_path = derive_decryption_output_path(plaintext_path)
        self.plain_output_var.set(str(decrypted_output_path))
        self.original_hash_file_var.set(plaintext_path)
        self.decrypted_hash_file_var.set(str(decrypted_output_path))

    def _generate_keys(self) -> None:
        output_dir = Path(self.key_dir_var.get().strip() or DEFAULT_KEYS_DIR)
        public_path = output_dir / "public_key.hex"
        private_path = output_dir / "private_key.hex"

        if public_path.exists() or private_path.exists():
            overwrite = messagebox.askyesno(
                "Overwrite keys?",
                "Key files already exist in this directory. Overwrite them?",
            )
            if not overwrite:
                self._log("Key generation cancelled because key files already exist.")
                return

        def job() -> dict[str, str | int]:
            output_dir.mkdir(parents=True, exist_ok=True)
            public_key, private_key = generate_keypair(bits=2048)
            save_key_to_hex_file(public_key, str(public_path))
            save_key_to_hex_file(private_key, str(private_path))
            return {
                "public_path": str(public_path),
                "private_path": str(private_path),
                "key_bits": public_key[0].bit_length(),
            }

        def success(result: dict[str, str | int]) -> None:
            self.public_key_var.set(str(result["public_path"]))
            self.private_key_var.set(str(result["private_path"]))
            message = (
                "RSA key pair generated successfully.\n"
                f"Key size: {result['key_bits']} bits\n"
                f"Public key: {result['public_path']}\n"
                f"Private key: {result['private_path']}"
            )
            messagebox.showinfo("Keys Generated", message)
            self._log(message.replace("\n", " | "))

        self._run_background("Generating 2048-bit RSA key pair", job, success)

    def _encrypt(self) -> None:
        try:
            plaintext_path = self._require_existing_file(self.plaintext_var.get(), "Plaintext file")
            public_key_path = self._require_existing_file(self.public_key_var.get(), "Public key file")
            output_path = self._prepare_output_path(self.cipher_output_var.get(), "Ciphertext output")
        except (FileNotFoundError, ValueError, PermissionError) as exc:
            self._show_error("Encryption", exc)
            return

        def job() -> dict:
            public_key = load_public_key_from_hex_file(str(public_key_path))
            return encrypt_file(str(plaintext_path), public_key, str(output_path))

        def success(result: dict) -> None:
            self.cipher_input_var.set(result["output_path"])
            message = (
                "Encryption completed.\n"
                f"Blocks: {result['blocks']}\n"
                f"Input bytes: {result['input_bytes']}\n"
                f"Output: {result['output_path']}"
            )
            messagebox.showinfo("Encryption Successful", message)
            self._log(message.replace("\n", " | "))

        self._run_background("Encrypting file", job, success)

    def _decrypt(self) -> None:
        try:
            ciphertext_path = self._require_existing_file(self.cipher_input_var.get(), "Ciphertext file")
            private_key_path = self._require_existing_file(self.private_key_var.get(), "Private key file")
            output_path = self._prepare_output_path(self.plain_output_var.get(), "Plaintext output")
        except (FileNotFoundError, ValueError, PermissionError) as exc:
            self._show_error("Decryption", exc)
            return

        def job() -> dict:
            private_key = load_private_key_from_hex_file(str(private_key_path))
            block_size = get_key_size_bytes(private_key)
            validate_ciphertext_format(str(ciphertext_path), block_size=block_size)
            return decrypt_file(str(ciphertext_path), private_key, str(output_path))

        def success(result: dict) -> None:
            self.decrypted_hash_file_var.set(result["output_path"])
            message = (
                "Decryption completed.\n"
                f"Blocks: {result['blocks']}\n"
                f"Output bytes: {result['output_bytes']}\n"
                f"Output: {result['output_path']}"
            )
            messagebox.showinfo("Decryption Successful", message)
            self._log(message.replace("\n", " | "))

        self._run_background("Decrypting file", job, success)

    def _compare_hashes(self) -> None:
        try:
            original_path = self._require_existing_file(self.original_hash_file_var.get(), "Original file")
            decrypted_path = self._require_existing_file(
                self.decrypted_hash_file_var.get(), "Decrypted file"
            )
        except (FileNotFoundError, ValueError, PermissionError) as exc:
            self._show_error("SHA-256 validation", exc)
            return

        def job() -> dict[str, str | bool]:
            original_hash = sha256_file(str(original_path))
            decrypted_hash = sha256_file(str(decrypted_path))
            return {
                "original_hash": original_hash,
                "decrypted_hash": decrypted_hash,
                "matches": original_hash == decrypted_hash,
            }

        def success(result: dict[str, str | bool]) -> None:
            self.original_hash_var.set(str(result["original_hash"]))
            self.decrypted_hash_var.set(str(result["decrypted_hash"]))
            status = "MATCH" if result["matches"] else "NOT MATCH"
            self.hash_match_var.set(status)
            message = (
                f"SHA-256 comparison: {status}\n"
                f"Original: {result['original_hash']}\n"
                f"Decrypted: {result['decrypted_hash']}"
            )
            messagebox.showinfo("SHA-256 Validation", message)
            self._log(message.replace("\n", " | "))

        self._run_background("Comparing SHA-256 hashes", job, success)

    def _require_existing_file(self, value: str, label: str) -> Path:
        if not value.strip():
            raise ValueError(f"{label} is required.")

        path = Path(value.strip())
        if not path.is_file():
            raise FileNotFoundError(f"{label} does not exist: {path}")
        return path

    def _prepare_output_path(self, value: str, label: str) -> Path:
        if not value.strip():
            raise ValueError(f"{label} is required.")

        path = Path(value.strip())
        if path.exists() and path.is_dir():
            raise ValueError(f"{label} must be a file path, not a directory: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def _run_background(self, description: str, job, success) -> None:
        self._set_busy(True)
        self._log(f"{description} started.")

        def worker() -> None:
            try:
                result = job()
            except Exception as exc:  # pragma: no cover - exercised through GUI use
                logging.exception("%s failed", description)
                self.root.after(0, lambda: self._finish_with_error(description, exc))
            else:
                self.root.after(0, lambda: self._finish_with_success(description, result, success))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_with_success(self, description: str, result, success) -> None:
        self._set_busy(False)
        self._log(f"{description} finished.")
        success(result)

    def _finish_with_error(self, description: str, exc: Exception) -> None:
        self._set_busy(False)
        self._log(f"{description} failed: {self._friendly_error(exc)}")
        self._show_error(description, exc)

    def _set_busy(self, busy: bool) -> None:
        state = tk.DISABLED if busy else tk.NORMAL
        for button in self.action_buttons:
            button.configure(state=state)

    def _show_error(self, title: str, exc: Exception) -> None:
        messagebox.showerror(f"{title} Error", self._friendly_error(exc))

    def _friendly_error(self, exc: Exception) -> str:
        message = str(exc) or exc.__class__.__name__
        lower_message = message.lower()

        if isinstance(exc, FileNotFoundError):
            return f"Input file does not exist. {message}"
        if isinstance(exc, PermissionError):
            return f"Output path is not writable or access is denied. {message}"
        if isinstance(exc, ValueError):
            if "oaep decoding error" in lower_message:
                return f"Wrong private key or corrupted ciphertext. {message}"
            if "ciphertext" in lower_message or "blok" in lower_message or "block" in lower_message:
                return f"Ciphertext is corrupted or truncated. {message}"
            if "key" in lower_message or "kunci" in lower_message:
                return f"Key file is invalid or the key size is not supported. {message}"
            return f"Invalid input. {message}"

        return f"Unexpected error. {message}"

    def _log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)


def run_app() -> None:
    logging.basicConfig(level=logging.INFO)
    root = tk.Tk()
    RSAOAEPApp(root)
    root.mainloop()
