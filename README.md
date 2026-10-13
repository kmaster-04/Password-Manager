# Local Password Manager

A fully offline, command-line password manager that stores credentials in a single encrypted vault file. Designed for users who need strong credential protection without trusting a third-party cloud service — particularly journalists, legal aid workers, and human rights defenders operating in high-risk environments.

---

## Features

- **Local-only storage** — no network, no cloud, no telemetry
- **AES-256-GCM authenticated encryption** for the vault file
- **PBKDF2-HMAC-SHA256** key derivation with 1,400,000 iterations and a random 16-byte salt
- **Cryptographically secure password generation** using Python's `secrets` module
- **Automatic session lock** after 5 minutes of inactivity
- **Full CRUD operations** on stored credentials
- **No plaintext leakage** — the vault file contains no readable metadata

---

## Requirements

- Python 3.10 or higher
- pip

---

## Installation

1. Clone or download the project folder.

2. Create and activate a virtual environment:

   **Windows (PowerShell):**
   python -m venv venv
venv\Scripts\Activate.ps1

**Windows (Command Prompt):**
python -m venv venv
venv\Scripts\activate.bat

**Linux / macOS:**
python3 -m venv venv
source venv/bin/activate

3. Install dependencies:
pip install -r requirements.txt

4. Verify the installation by running the test suite:
python -m pytest tests/ -v

All tests should pass.

---

## Usage

### Create a new vault
python main.py create

You will be prompted to enter and confirm a master password. The vault file (`vault.vault`) is created in the current directory.

> **Important:** The master password is never stored anywhere. If you forget it, your data cannot be recovered.

To create a vault at a custom path:
python main.py create --vault-path myvault.vault

### Start the interactive shell
python main.py shell

Enter your master password when prompted. You will see the `pwmgr>` prompt.

To specify a custom vault and timeout:
python main.py shell --vault-path myvault.vault --timeout 600

### Generate a random password without a vault
python main.py generate --length 24

---

## Interactive Shell Commands

Once inside the shell (`pwmgr>` prompt):

| Command | Description |
|---|---|
| `help` | Show all available commands |
| `list` | List all stored services and usernames |
| `add` | Add a new credential (interactive prompts) |
| `get <service>` | Retrieve credentials matching a service name |
| `update <service>` | Update a stored credential (interactive prompts) |
| `delete <service>` | Delete all credentials matching a service name |
| `generate [length]` | Generate a random password (default length: 20) |
| `lock` | Lock the vault immediately |
| `exit` | Lock and exit the application |

Service matching is case-insensitive and supports partial matches — for example, `get bank` will match `mybank.com`.

---

## Example Session
vQ9@xPz!4Rt7NwYb3
Credential added and saved.
pwmgr> list
example.com: alice
pwmgr> get example.com
Service: example.com
Username: alice
Password: 8k#Lm2$vQ9@xPz!4Rt7NwYb3
pwmgr> exit
Exiting.

---

## Security Design

### Cryptographic parameters

| Component | Choice | Rationale |
|---|---|---|
| Key derivation | PBKDF2-HMAC-SHA256 | Widely vetted, standardised (RFC 2898) |
| Iterations | 1,400,000 | Calibrated so each derivation takes ≥ 0.5 s on the development machine |
| Salt | 16 random bytes per vault write | Prevents rainbow-table attacks and ensures unique keys |
| Vault encryption | AES-256-GCM | Provides both confidentiality and integrity (tamper detection) |
| Nonce | 12 random bytes per encryption | Unique per write, as required by GCM |
| Password generation | Python `secrets` module | Cryptographically secure random source |

### Vault file format

The vault file is a plain-text file containing three base64-encoded fields separated by pipe characters:

base64(salt) | base64(nonce) | base64(ciphertext + GCM tag)

None of these fields reveal any plaintext metadata. A hex dump of the file shows only random-looking bytes.

### Memory handling

- The master password is never written to disk or logged.
- The derived key and decrypted credentials are held in memory only while the session is unlocked.
- On lock or exit, these values are explicitly cleared.
- The vault locks automatically after 5 minutes of inactivity (configurable via `--timeout`).

### Threat model

This tool is designed to resist an attacker who obtains a copy of the encrypted vault file and has unlimited offline computing power, but does not know the master password and has no access to the running process. Under these conditions:

- Each password guess costs at least 0.5 seconds of PBKDF2 work.
- A dictionary attack using the 100 most common passwords yields zero successful decryptions.
- No plaintext service names, usernames, or passwords are recoverable from the vault file.

---

## Testing

The project includes an automated test suite covering:

- Cryptographic correctness (encryption/decryption round-trip, tamper detection, wrong-password rejection)
- Vault CRUD operations and persistence across sessions
- Password generator behaviour (length, character sets, uniqueness)
- Session lifecycle (lock, memory clearing, timeout)

Run all tests:
python -m pytest tests/ -v

Run a specific module's tests:
python -m pytest tests/test_vault.py -v

---

## Security Benchmark Scripts

The following scripts were used to validate the security properties documented above.

**PBKDF2 timing benchmark:**
python benchmark_pbkdf2.py
Measures the time taken for a single key derivation across multiple runs and reports the median. The iteration count was calibrated to ensure the median exceeds 0.5 seconds.

**Dictionary attack simulation:**
python benchmark_dictionary.py
Attempts to decrypt a test vault using a list of common passwords (`rockyou_sample.txt`). Confirms that no weak password succeeds.

**Hex dump inspection:**
certutil -encodehex benchmark_vault.vault hexdump.txt
Produces a hex representation of the vault file, used to verify that no plaintext strings appear.

---

## Known Limitations

- **Clipboard integration is not functional** on the current development environment. Passwords are displayed in the terminal instead. Users should manually clear their terminal or avoid displaying passwords in shared environments.
- **Linux-only testing was intended**, but the tool has been validated on Windows. Behaviour on macOS is untested.
- **No graphical interface.** The tool is command-line only.
- **No master password recovery.** This is by design.
- **Memory wiping is best-effort.** Python cannot guarantee that sensitive data is removed from all memory locations; OS-level protections such as `mlock` are not used.
- **No support for multi-user vaults, cloud synchronisation, or hardware tokens.**

---

## Project Structure
password-manager/
├── crypto_utils.py Key derivation, encryption, decryption
├── vault.py Vault file I/O and CRUD helpers
├── password_gen.py Random password generator
├── session.py Session lifecycle and auto-lock
├── cli.py Command-line interface
├── main.py Entry point
├── benchmark_pbkdf2.py PBKDF2 timing benchmark
├── benchmark_dictionary.py Dictionary attack simulation
├── rockyou_sample.txt Sample wordlist for the dictionary attack
├── requirements.txt Python dependencies
├── README.md This file
├── tests/
│ ├── test_crypto_utils.py
│ ├── test_vault.py
│ ├── test_password_gen.py
│ └── test_session.py
└── docs/
├── quick_start_guide.md
├── consent_form.md
├── usability_tasks.md
└── sus_questionnaire.md

---

## Dependencies

- [`cryptography`](https://cryptography.io/) — cryptographic primitives
- [`pyperclip`](https://pypi.org/project/pyperclip/) — clipboard access (currently non-functional; see Known Limitations)
- [`pytest`](https://pytest.org/) — test framework (development only)

All dependencies are listed in `requirements.txt`.

---

## References

- Florencio, D., & Herley, C. (2007). A large-scale study of web password habits. *Proceedings of the 16th International Conference on World Wide Web*, 657–666.
- Li, Z., He, W., Akhawe, D., & Song, D. (2014). The emperor's new password manager: Security analysis of web-based password managers. *Proceedings of the 23rd USENIX Security Symposium*, 465–480.
- National Institute of Standards and Technology. (2017). *Digital identity guidelines: Authentication and lifecycle management* (NIST SP 800-63B).
- OWASP Foundation. (2021). *Password storage cheat sheet*.
- Silver, D., Jana, S., Boneh, D., Chen, E., & Jackson, C. (2014). Password managers: Attacks and defenses. *Proceedings of the 23rd USENIX Security Symposium*, 449–464.
- Verizon. (2023). *2023 data breach investigations report*.

---

## Author

Capstone project — Special Topics in Computer Science.
