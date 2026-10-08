import base64
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# Constants used for key derivation and encryption settings.
SALT_SIZE_BYTES = 16 # Salt size in bytes and longer the size the higher the security. :)
PBKDF2_ITERATIONS = 480_000 # Number of iterations for PBKDF2 key derivation. Adjust this value based on your security requirements and performance considerations.
ENCRYPTED_FILE_EXTENSION = ".enc" # Extension for encrypted files
HIDDEN_PASSWORD_CHAR = "•" #You can Change however you want to do like ('*'/'x'/'#')

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    key_derivation_function = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    raw_key = key_derivation_function.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)


def encrypt_bytes(plain_bytes: bytes, password: str) -> bytes:
    # The salt is prepended to the encrypted data so that it can be used during decryption.
    salt = os.urandom(SALT_SIZE_BYTES)
    fernet = Fernet(derive_key_from_password(password, salt))
    return salt + fernet.encrypt(plain_bytes)


def decrypt_bytes(salt_and_token: bytes, password: str) -> bytes:
    # The salt is extracted from the beginning of the encrypted data and used to derive the key for decryption.
    if len(salt_and_token) <= SALT_SIZE_BYTES:
        raise InvalidToken

    salt = salt_and_token[:SALT_SIZE_BYTES]
    token = salt_and_token[SALT_SIZE_BYTES:]
    fernet = Fernet(derive_key_from_password(password, salt))
    return fernet.decrypt(token)


def encrypt_text(plain_text: str, password: str) -> str:
    encrypted_bytes = encrypt_bytes(plain_text.encode("utf-8"), password)
    return base64.urlsafe_b64encode(encrypted_bytes).decode("ascii")


def decrypt_text(encrypted_text: str, password: str) -> str:
    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_text.strip().encode("ascii"))
    except Exception:
        raise InvalidToken
    return decrypt_bytes(encrypted_bytes, password).decode("utf-8")


# GUI is written here using Tkinter.
class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Encryption / Decryption Tool")
        self.geometry("640x560")
        self.minsize(560, 480)

        tabs = ttk.Notebook(self)
        tabs.pack(fill="both", expand=True, padx=10, pady=10)

        self.text_tab = ttk.Frame(tabs, padding=10)
        self.file_tab = ttk.Frame(tabs, padding=10)
        tabs.add(self.text_tab, text="Text")
        tabs.add(self.file_tab, text="File")

        self._build_text_tab()
        self._build_file_tab()

        self.status_message = tk.StringVar(value="Ready")
        status_bar = ttk.Label(
            self, textvariable=self.status_message, relief="sunken", anchor="w"
        )
        status_bar.pack(fill="x", side="bottom")

    def _toggle_password_visibility(self, password_entry, show_password_var):
        password_entry.config(
            show="" if show_password_var.get() else HIDDEN_PASSWORD_CHAR
        )
# This area is for the text tab, which allows users to encrypt and decrypt text using a password.
    def _build_text_tab(self):
        tab = self.text_tab
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        tab.rowconfigure(5, weight=1)

        ttk.Label(tab, text="Input text:").grid(row=0, column=0, sticky="w")
        self.input_text_box = tk.Text(tab, height=8, wrap="word")
        self.input_text_box.grid(row=1, column=0, columnspan=4, sticky="nsew", pady=(2, 8))

        ttk.Label(tab, text="Password:").grid(row=2, column=0, sticky="w")
        self.text_password_var = tk.StringVar()
        self.text_password_entry = ttk.Entry(
            tab, textvariable=self.text_password_var, show=HIDDEN_PASSWORD_CHAR
        )
        self.text_password_entry.grid(row=3, column=0, sticky="ew", pady=(2, 8))

        self.show_text_password_var = tk.BooleanVar()
        ttk.Checkbutton(
            tab,
            text="Show",
            variable=self.show_text_password_var,
            command=lambda: self._toggle_password_visibility(
                self.text_password_entry, self.show_text_password_var
            ),
        ).grid(row=3, column=1, padx=6)

        button_row = ttk.Frame(tab)
        button_row.grid(row=4, column=0, columnspan=4, sticky="w", pady=(0, 8))
        ttk.Button(button_row, text="Encrypt", command=self.on_encrypt_text).pack(side="left")
        ttk.Button(button_row, text="Decrypt", command=self.on_decrypt_text).pack(side="left", padx=6)
        ttk.Button(button_row, text="Clear", command=self.on_clear_text).pack(side="left")

        ttk.Label(tab, text="Output:").grid(row=4, column=2, sticky="e")
        self.output_text_box = tk.Text(tab, height=8, wrap="word")
        self.output_text_box.grid(row=5, column=0, columnspan=4, sticky="nsew", pady=(2, 8))

        ttk.Button(tab, text="Copy output", command=self.on_copy_output).grid(
            row=6, column=0, sticky="w"
        )

    def _read_text_and_password(self):
        
        text = self.input_text_box.get("1.0", "end-1c")
        password = self.text_password_var.get()

        if not text.strip():
            messagebox.showwarning("Missing input", "Please enter some text.")
            return None
        if not password:
            messagebox.showwarning("Missing password", "Please enter a password.")
            return None
        return text, password

    def _show_output_text(self, text: str):
        self.output_text_box.delete("1.0", "end")
        self.output_text_box.insert("1.0", text)

    def on_encrypt_text(self):
        inputs = self._read_text_and_password()
        if inputs is None:
            return
        text, password = inputs

        try:
            self._show_output_text(encrypt_text(text, password))
            self.status_message.set("Text encrypted.")
        except Exception as error:
            messagebox.showerror("Error", f"Encryption failed:\n{error}")

    def on_decrypt_text(self):
        inputs = self._read_text_and_password()
        if inputs is None:
            return
        encrypted_text, password = inputs

        try:
            self._show_output_text(decrypt_text(encrypted_text, password))
            self.status_message.set("Text decrypted.")
        except InvalidToken:
            messagebox.showerror(
                "Decryption failed", "Wrong password or the text is corrupted."
            )
        except Exception as error:
            messagebox.showerror("Error", f"Decryption failed:\n{error}")

    def on_copy_output(self):
        output_text = self.output_text_box.get("1.0", "end-1c")
        if output_text:
            self.clipboard_clear()
            self.clipboard_append(output_text)
            self.status_message.set("Output copied to clipboard.")

    def on_clear_text(self):
        self.input_text_box.delete("1.0", "end")
        self.output_text_box.delete("1.0", "end")
        self.text_password_var.set("")
        self.status_message.set("Cleared.")
# File tab into the GUI where user can select a file to encrypt or decrypt using a password.
    def _build_file_tab(self):
        tab = self.file_tab
        tab.columnconfigure(0, weight=1)

        ttk.Label(tab, text="Select file:").grid(row=0, column=0, sticky="w")
        self.selected_file_path_var = tk.StringVar()
        ttk.Entry(tab, textvariable=self.selected_file_path_var).grid(
            row=1, column=0, sticky="ew", pady=(2, 8)
        )
        ttk.Button(tab, text="Browse…", command=self.on_browse_file).grid(
            row=1, column=1, padx=6
        )

        ttk.Label(tab, text="Password:").grid(row=2, column=0, sticky="w")
        self.file_password_var = tk.StringVar()
        self.file_password_entry = ttk.Entry(
            tab, textvariable=self.file_password_var, show=HIDDEN_PASSWORD_CHAR
        )
        self.file_password_entry.grid(row=3, column=0, sticky="ew", pady=(2, 8))

        self.show_file_password_var = tk.BooleanVar()
        ttk.Checkbutton(
            tab,
            text="Show",
            variable=self.show_file_password_var,
            command=lambda: self._toggle_password_visibility(
                self.file_password_entry, self.show_file_password_var
            ),
        ).grid(row=3, column=1, padx=6)

        button_row = ttk.Frame(tab)
        button_row.grid(row=4, column=0, sticky="w", pady=8)
        ttk.Button(button_row, text="Encrypt file", command=self.on_encrypt_file).pack(side="left")
        ttk.Button(button_row, text="Decrypt file", command=self.on_decrypt_file).pack(side="left", padx=6)

        help_text = (
            "Encrypted files are saved with a .enc extension next to the original.\n"
            "The original file is never modified or deleted.\n"
            "Keep your password safe: without it the data cannot be recovered."
        )
        ttk.Label(tab, text=help_text, foreground="gray", justify="left").grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(12, 0)
        )

    def on_browse_file(self):
        chosen_path = filedialog.askopenfilename(title="Choose a file")
        if chosen_path:
            self.selected_file_path_var.set(chosen_path)

    def _read_file_path_and_password(self):
        file_path = self.selected_file_path_var.get().strip()
        password = self.file_password_var.get()

        if not file_path or not os.path.isfile(file_path):
            messagebox.showwarning("Missing file", "Please select a valid file.")
            return None
        if not password:
            messagebox.showwarning("Missing password", "Please enter a password.")
            return None
        return file_path, password

    def _confirm_overwrite_if_exists(self, output_path: str) -> bool:
        if not os.path.exists(output_path):
            return True
        return messagebox.askyesno(
            "File exists",
            f"{os.path.basename(output_path)} already exists.\nOverwrite it?",
        )

    def on_encrypt_file(self):
        inputs = self._read_file_path_and_password()
        if inputs is None:
            return
        input_path, password = inputs

        output_path = input_path + ENCRYPTED_FILE_EXTENSION
        if not self._confirm_overwrite_if_exists(output_path):
            return

        try:
            with open(input_path, "rb") as input_file:
                plain_bytes = input_file.read()
            with open(output_path, "wb") as output_file:
                output_file.write(encrypt_bytes(plain_bytes, password))

            self.status_message.set(f"Encrypted → {output_path}")
            messagebox.showinfo("Success", f"File encrypted:\n{output_path}")
        except Exception as error:
            messagebox.showerror("Error", f"Encryption failed:\n{error}")

    def on_decrypt_file(self):
        inputs = self._read_file_path_and_password()
        if inputs is None:
            return
        input_path, password = inputs

        if input_path.lower().endswith(ENCRYPTED_FILE_EXTENSION):
            output_path = input_path[: -len(ENCRYPTED_FILE_EXTENSION)]
        else:
            output_path = input_path + ".dec"
        if not self._confirm_overwrite_if_exists(output_path):
            return

        try:
            with open(input_path, "rb") as input_file:
                encrypted_bytes = input_file.read()
            decrypted_bytes = decrypt_bytes(encrypted_bytes, password)
            with open(output_path, "wb") as output_file:
                output_file.write(decrypted_bytes)

            self.status_message.set(f"Decrypted → {output_path}")
            messagebox.showinfo("Success", f"File decrypted:\n{output_path}")
        except InvalidToken:
            messagebox.showerror(
                "Decryption failed",
                "Wrong password or the file is not a valid encrypted file.",
            )
        except Exception as error:
            messagebox.showerror("Error", f"Decryption failed:\n{error}")

if __name__ == "__main__":
    CryptoApp().mainloop()