# Password Manager — Quick Start Guide

## What it is
A local, offline password manager. Your credentials are stored in an encrypted file on your computer. No internet connection is used.

## First-time setup
1. Open a terminal in the project folder.
2. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
3. Create a new vault:
python main.py create
4. Enter a master password when prompted (twice).
Remember it — it cannot be recovered.
5. Your encrypted vault file (`vault.vault`) is now created.

## Daily use
1. Start the application:
python main.py shell
2. Enter your master password.
3. You will see the prompt: `pwmgr>`
4. Available commands:

| Command | Description |
|---------|-------------|
| `list` | Show all stored services |
| `add` | Add a new credential (follow prompts) |
| `get <service>` | Retrieve credentials for a service |
| `update <service>` | Update a stored credential |
| `delete <service>` | Delete a credential |
| `generate [length]` | Generate a random password |
| `lock` | Lock the vault immediately |
| `exit` | Lock and quit |

## Generating a password without the vault
python main.py generate --length 24

## Tips
- The vault locks automatically after 5 minutes of inactivity.
- Type `help` at the `pwmgr>` prompt to see all commands again.
- If you forget your master password, your data cannot be recovered.