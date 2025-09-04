# 🔐 Encryption Tool

A simple **command-line encryption tool** built with Python that supports secure text and file encryption using **AES-GCM** (Galois/Counter Mode).  
AES-GCM provides both **confidentiality** (encryption) and **integrity/authentication** (prevents tampering).  

---

## ✨ Features

- **Text Encryption (AES-GCM)**  
  Encrypt any text securely with a randomly generated 256-bit key.  

- **Text Decryption (AES-GCM)**  
  Decrypt ciphertext back to plaintext using the key, nonce, and tag.  

- **File Encryption (AES-GCM)**  
  Encrypt files of any size with AES-GCM. Metadata (filename, key, nonce, tag, ciphertext) is stored in a `.enc.json` file.  

- **File Decryption (AES-GCM)**  
  Decrypt previously encrypted `.enc.json` files back to their original content.  

- **Cross-platform**: Works on **Linux**, **macOS**, and **Windows**.  

---

## 📦 Requirements

- Python **3.8+**
- [PyCryptodome](https://pypi.org/project/pycryptodome/)

Install dependencies:
```bash
pip install pycryptodome
```
