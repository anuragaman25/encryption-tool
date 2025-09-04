from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ---------- Helpers ----------

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

def input_nonempty(prompt: str) -> str:
    s = input(prompt).strip()
    if not s:
        raise ValueError("Input cannot be empty.")
    return s

def print_header(title: str) -> None:
    print("\n" + "-" * 8, title, "-" * 8)

# ---------- AES (GCM) ----------

@dataclass
class AESGCMResult:
    nonce_b64: str
    ciphertext_b64: str
    tag_b64: str

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> AESGCMResult:
    nonce = get_random_bytes(12)  # 96-bit nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return AESGCMResult(b64e(nonce), b64e(ciphertext), b64e(tag))

def aes_gcm_decrypt(key: bytes, nonce_b64: str, ciphertext_b64: str, tag_b64: str, aad: Optional[bytes] = None) -> bytes:
    nonce = b64d(nonce_b64)
    ciphertext = b64d(ciphertext_b64)
    tag = b64d(tag_b64)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ---------- File helpers ----------

def read_file_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def write_file_bytes(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)

# ---------- Menu ----------

MENU = """
--- AES-GCM Encryption Tool ---
1. Encrypt Text (AES-GCM)  
2. Decrypt Text (AES-GCM)
3. Encrypt File (AES-GCM)
4. Decrypt File (AES-GCM)
5. Exit
"""

# ---------- CLI ----------

def main() -> None:
    while True:
        print(MENU)
        choice = input("Enter your choice: ").strip()

        try:
            if choice == '1':
                text = input_nonempty("Enter text: ").encode('utf-8')
                key = get_random_bytes(32)  # AES-256
                res = aes_gcm_encrypt(key, text)
                print_header("AES-GCM Encryption Result")
                print(f"Key (Base64, store securely): {b64e(key)}")
                print(f"Nonce: {res.nonce_b64}")
                print(f"Tag: {res.tag_b64}")
                print(f"Ciphertext: {res.ciphertext_b64}")

            elif choice == '2':
                key_b64 = input_nonempty("Enter AES Key (Base64): ")
                nonce_b64 = input_nonempty("Enter Nonce (Base64): ")
                tag_b64 = input_nonempty("Enter Tag (Base64): ")
                ct_b64 = input_nonempty("Enter Ciphertext (Base64): ")
                key = b64d(key_b64)
                pt = aes_gcm_decrypt(key, nonce_b64, ct_b64, tag_b64)
                print_header("Decrypted Text")
                print(pt.decode('utf-8'))

            elif choice == '3':
                path = input_nonempty("Path to file to encrypt: ").strip()
                if not os.path.isfile(path):
                    raise FileNotFoundError(f"File not found: {path}")
                data = read_file_bytes(path)
                key = get_random_bytes(32)
                res = aes_gcm_encrypt(key, data, aad=os.path.basename(path).encode('utf-8'))
                out = {
                    "alg": "AES-GCM",
                    "k": b64e(key),
                    "n": res.nonce_b64,
                    "t": res.tag_b64,
                    "c": res.ciphertext_b64,
                    "name": os.path.basename(path),
                }
                out_path = path + ".enc.json"
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(out, f)
                print_header("File Encrypted")
                print(f"Wrote: {out_path}")
                print("Store the key (k) securely; anyone with it can decrypt.")

            elif choice == '4':
                path = input_nonempty("Path to .enc.json: ").strip()
                if not os.path.isfile(path):
                    raise FileNotFoundError(f"File not found: {path}")
                with open(path, "r", encoding="utf-8") as f:
                    obj = json.load(f)
                if obj.get("alg") != "AES-GCM":
                    raise ValueError("Unsupported file format.")
                key = b64d(obj["k"])
                data = aes_gcm_decrypt(
                    key, obj["n"], obj["c"], obj["t"],
                    aad=obj.get("name","").encode('utf-8') if obj.get("name") else None
                )
                out_name = obj.get("name") or "decrypted.bin"
                out_path = os.path.join(os.path.dirname(path), out_name + ".dec")
                write_file_bytes(out_path, data)
                print_header("File Decrypted")
                print(f"Wrote: {out_path}")

            elif choice == '5':
                print("Exiting...")
                break

            else:
                print("Invalid choice. Please try again.")

        except Exception as e:
            print_header("Error")
            print(f"{type(e).__name__}: {e}")

if __name__ == "__main__":
    main()
