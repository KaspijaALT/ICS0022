# Secure Password Manager

https://github.com/KaspijaALT/ICS0022

## Project Scope

Terminal captures master password via masked prompt and passes it to User Management module. Given module verifies password against stored Argon2id hash before allowing further actions. Once verified, the encryption module derives 256 bit data encryption key in memory decrypts the vault payload from the local file into a temporary buffer for the duration of the command, and re-encrypts and writes it back on any change. Plaintext credentials and the derived key exists only inside process memory and are forcefully made zero after use.

This scheme is a single process, local CLI application, theres no network listener and no server component, so the pirmary trust boundaries are the CLI input (untrusted stdin / argv reaching the application) and the file system boundary (the application writing to and reading from disk, where an arbitrary actor with local file access could tamper with the vault at rest).

## Planned Command-Line Interface

- `python main.py init` — initialize a new vault and set the master password
- `python main.py unlock` — authenticate and open an interactive session
- `python main.py add` — securely prompt for and add a new credential entry
- `python main.py get <label>` — retrieve and display a decrypted entry
- `python main.py delete <label>` — securely remove a credential entry

## Build & Run

Python 3.11 will be used for development, built in memory management primitives and alignment with the web backend build for ICS0027.

- Cryptography – openssl c-bindings for AES-256-GCM, handling authenticated encryption natively.
- Argon2-cffi – C level Argon2id key derivation, avoiding manual, error prone memory handling.
- Getpass and argparse – standard library modules for masked password input and CLI argument parsing.

```bash
python -m venv venv
source venv/bin/activate
pip install cryptography argon2-cffi
python main.py --help
```