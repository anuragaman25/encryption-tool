# Encryption Tool

A simple **command-line encryption tool** built with Python that supports secure text and file encryption using **AES-GCM** (Galois/Counter Mode).  
AES-GCM provides both **confidentiality** (encryption) and **integrity/authentication** (prevents tampering).  



## Features

- **Text Encryption (AES-GCM)**  
  Encrypt any text securely with a randomly generated 256-bit key.  

- **Text Decryption (AES-GCM)**  
  Decrypt ciphertext back to plaintext using the key, nonce, and tag.  

- **File Encryption (AES-GCM)**  
  Encrypt files of any size with AES-GCM. Metadata (filename, key, nonce, tag, ciphertext) is stored in a `.enc.json` file.  

- **File Decryption (AES-GCM)**  
  Decrypt previously encrypted `.enc.json` files back to their original content.  

- **Cross-platform**: Works on **Linux**, **macOS**, and **Windows**.

  <br>

>[!TIP]
>- Never share your AES key – anyone with the key can decrypt your data.<br>
>- The tool uses AES-256-GCM, which is currently secure for practical use.
>- File encryption stores everything in JSON (.enc.json) except the key.
>- Always back up your key before encrypting important files.

## Requirements

- Python **3.8+**
- [PyCryptodome](https://pypi.org/project/pycryptodome/)

Install dependencies:
```bash
pip install pycryptodome
```

## Usage

Run the script:
```bash
python encryptor.py
```
#### You’ll see the menu:

```bash
--- AES-GCM Encryption Tool ---
1. Encrypt Text (AES-GCM)  
2. Decrypt Text (AES-GCM)
3. Encrypt File (AES-GCM)
4. Decrypt File (AES-GCM)
5. Exit
```
## Tech Stack

- Python 3.8+
- PyCryptodome for cryptographic operations

## License

This project is licensed under the MIT License.
You are free to use, modify, and distribute it with attribution.

## Author

### Anurag Aman
- [LinkedIn](https://linkedin.com/in/anuragaman25) <br>
- [Github](https://github.com/anuragaman25)
