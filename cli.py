import argparse
import getpass
import sys
import time
import threading

import vault
import password_gen
import totp
import passkey
import health_audit
import biometric_auth
from session import VaultSession

try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except Exception:
    CLIPBOARD_AVAILABLE = False

DEFAULT_VAULT_PATH = "vault.vault"
PASSKEY_DEFAULT_KEY_PATH = "passkey_device.pem"
CLIPBOARD_CLEAR_SECONDS = 15
COMMON_PASSWORDS_FILE = "rockyou_sample.txt"


def prompt_master_password(confirm=False):
    pw = getpass.getpass("Master password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm master password: ")
        if pw != pw2:
            print("Passwords do not match.")
            sys.exit(1)
    return pw


def copy_to_clipboard_with_clear(password: str):
    if not CLIPBOARD_AVAILABLE:
        return False
    try:
        pyperclip.copy(password)
    except Exception:
        return False

    def _clear():
        time.sleep(CLIPBOARD_CLEAR_SECONDS)
        try:
            pyperclip.copy("")
        except Exception:
            pass

    threading.Thread(target=_clear, daemon=True).start()
    return True


def create_vault_command(args):
    path = args.vault_path or DEFAULT_VAULT_PATH
    try:
        master_pw = prompt_master_password(confirm=True)
        vault.create_vault(path, master_pw)
        print(f"Vault created at {path}")
    except FileExistsError:
        print(f"Error: vault already exists at {path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error creating vault: {e}")
        sys.exit(1)


def generate_password_command(args):
    print(password_gen.generate_password(length=args.length))


def enroll_passkey_command(args):
    path = args.vault_path or DEFAULT_VAULT_PATH
    key_path = args.key_path or PASSKEY_DEFAULT_KEY_PATH
    try:
        master_pw = prompt_master_password()
        vault.load_vault(path, master_pw)
    except FileNotFoundError:
        print(f"Vault not found at {path}.")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    enrollment_path = passkey.enroll(path, master_pw, key_path)
    print("Passkey enrolled successfully.")
    print(f"  Device key:        {key_path}")
    print(f"  Enrollment record: {enrollment_path}")


def enroll_biometric_command(args):
    path = args.vault_path or DEFAULT_VAULT_PATH
    try:
        master_pw = prompt_master_password()
        vault.load_vault(path, master_pw)
    except FileNotFoundError:
        print(f"Vault not found at {path}.")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print("Starting biometric enrollment...")
    success = biometric_auth.enroll_biometric(path, master_pw)
    if success:
        print(f"Biometric enrolled. Record saved to "
              f"{biometric_auth.biometric_file_path(path)}")
    else:
        print("Biometric enrollment cancelled or failed.")
        sys.exit(1)


def shell_command(args):
    path = args.vault_path or DEFAULT_VAULT_PATH

    if args.biometric:
        try:
            master_pw = biometric_auth.unlock_biometric(
                path,
                skip_distance_check=getattr(args, "skip_distance", False),
            )
            print("Unlocked with biometric (face verified).")
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
    elif args.passkey:
        key_path = args.key_path or PASSKEY_DEFAULT_KEY_PATH
        try:
            master_pw = passkey.unlock_with_passkey(path, key_path)
            print("Unlocked with passkey (device key verified).")
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        try:
            master_pw = prompt_master_password()
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(1)

    try:
        credentials = vault.load_vault(path, master_pw)
    except FileNotFoundError:
        print(f"Vault not found at {path}. Use 'create' first.")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    session = VaultSession(path, master_pw, credentials, timeout_seconds=args.timeout)
    print("Vault unlocked. Type 'help' for available commands.")

    while not session.is_locked():
        try:
            cmd_line = input("pwmgr> ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if not cmd_line:
            continue

        parts = cmd_line.split()
        cmd = parts[0].lower()
        args_rest = parts[1:]

        if cmd == "help":
            print("Commands:")
            print("  list                     - list all stored services")
            print("  add                      - add a new credential (prompts)")
            print("  get <service>            - retrieve credentials for a service")
            print("  update <service>         - update a credential (prompts)")
            print("  delete <service>         - delete credentials for a service")
            print("  generate [length]        - generate a random password")
            print("  setotp <service>         - attach a TOTP secret to a credential")
            print("  code <service>           - show the current 2FA code")
            print("  audit                    - run a password health audit")
            print("  lock                     - lock the vault immediately")
            print("  exit                     - lock and exit")

        elif cmd == "list":
            entries = vault.list_credentials(session.credentials)
            if not entries:
                print("No credentials stored.")
            else:
                for service, username in entries:
                    print(f"{service}: {username}")

        elif cmd == "add":
            service = input("Service: ")
            username = input("Username: ")
            choice = input("Generate password? (y/n): ").lower()
            if choice == 'y':
                try:
                    length = int(input("Password length (default 20): ") or "20")
                except ValueError:
                    length = 20
                pwd = password_gen.generate_password(length=length)
                print(f"Generated password: {pwd}")
            else:
                pwd = getpass.getpass("Password: ")

            totp_choice = input("Attach a TOTP secret now? (y/n): ").lower()
            totp_secret = None
            if totp_choice == 'y':
                candidate = input("Base32 TOTP secret: ").strip()
                if candidate:
                    try:
                        totp.generate_totp(candidate)
                        totp_secret = candidate
                    except Exception as e:
                        print(f"Invalid TOTP secret, skipping: {e}")

            vault.add_credential(session.credentials, service, username,
                                 pwd, totp_secret)
            vault.save_vault(session.vault_path, session.master_password,
                             session.credentials)
            session.touch()
            print("Credential added and saved.")

        elif cmd == "get":
            if len(args_rest) < 1:
                print("Usage: get <service>")
                continue
            matches = vault.get_credential(session.credentials, args_rest[0])
            if not matches:
                print("No matching credentials.")
            else:
                if copy_to_clipboard_with_clear(matches[0]['password']):
                    print(f"Password copied to clipboard. "
                          f"Will clear in {CLIPBOARD_CLEAR_SECONDS} seconds.")
                for cred in matches:
                    print(f"Service: {cred['service']}")
                    print(f"Username: {cred['username']}")
                    print(f"Password: {cred['password']}")
                    if "totp_secret" in cred:
                        try:
                            current_code = totp.generate_totp(cred["totp_secret"])
                            print(f"2FA Code: {current_code}  "
                                  f"(expires in {totp.seconds_remaining()}s)")
                        except Exception:
                            print("2FA Code: [error generating code]")
            session.touch()

        elif cmd == "update":
            if len(args_rest) < 1:
                print("Usage: update <service>")
                continue
            if not vault.get_credential(session.credentials, args_rest[0]):
                print("No matching credentials.")
                continue
            new_username = input("New username (leave blank to keep): ")
            new_password = getpass.getpass("New password (leave blank to keep): ")
            updated = vault.update_credential(
                session.credentials, args_rest[0],
                new_username if new_username else None,
                new_password if new_password else None,
            )
            if updated:
                vault.save_vault(session.vault_path, session.master_password,
                                 session.credentials)
                session.touch()
                print("Credential updated.")

        elif cmd == "delete":
            if len(args_rest) < 1:
                print("Usage: delete <service>")
                continue
            deleted = vault.delete_credential(session.credentials, args_rest[0])
            vault.save_vault(session.vault_path, session.master_password,
                             session.credentials)
            session.touch()
            print(f"Deleted {deleted} credential(s).")

        elif cmd == "setotp":
            if len(args_rest) < 1:
                print("Usage: setotp <service>")
                continue
            matches = vault.get_credential(session.credentials, args_rest[0])
            if not matches:
                print("No matching credentials.")
                continue
            secret_input = input("Secret: ").strip()
            if not secret_input:
                continue
            try:
                totp.generate_totp(secret_input)
            except Exception as e:
                print(f"Invalid TOTP secret: {e}")
                continue
            if vault.set_totp_secret(session.credentials, args_rest[0],
                                     secret_input):
                vault.save_vault(session.vault_path, session.master_password,
                                 session.credentials)
                session.touch()
                print(f"TOTP secret attached to {matches[0]['service']}.")

        elif cmd == "code":
            if len(args_rest) < 1:
                print("Usage: code <service>")
                continue
            matches = vault.get_credential(session.credentials, args_rest[0])
            if not matches:
                print("No matching credentials.")
                continue
            cred = matches[0]
            if "totp_secret" not in cred:
                print(f"No TOTP secret stored for {cred['service']}.")
                continue
            try:
                print(f"{cred['service']}")
                print(f"  Code: {totp.generate_totp(cred['totp_secret'])}")
                print(f"  Expires in {totp.seconds_remaining()} seconds")
            except Exception as e:
                print(f"Error generating code: {e}")
            session.touch()

        elif cmd == "audit":
            common = health_audit.load_common_passwords(COMMON_PASSWORDS_FILE)
            report = health_audit.audit_vault(session.credentials,
                                              common_passwords=common)
            health_audit.print_report(report)
            session.touch()

        elif cmd == "generate":
            length = 20
            if len(args_rest) >= 1:
                try:
                    length = int(args_rest[0])
                except ValueError:
                    pass
            print(f"Generated password: "
                  f"{password_gen.generate_password(length=length)}")
            session.touch()

        elif cmd == "lock":
            session.lock()
            print("Vault locked.")
            break

        elif cmd == "exit":
            session.lock()
            print("Exiting.")
            break

        else:
            print("Unknown command. Type 'help' for options.")

    if not session.is_locked():
        session.lock()


def main():
    parser = argparse.ArgumentParser(description="Local encrypted password manager")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_create = subparsers.add_parser("create", help="Create a new vault")
    p_create.add_argument("--vault-path", default=DEFAULT_VAULT_PATH)
    p_create.set_defaults(func=create_vault_command)

    p_gen = subparsers.add_parser("generate", help="Generate a random password")
    p_gen.add_argument("--length", type=int, default=20)
    p_gen.set_defaults(func=generate_password_command)

    p_enroll = subparsers.add_parser("enroll-passkey",
                                     help="Enroll a passkey for the vault")
    p_enroll.add_argument("--vault-path", default=DEFAULT_VAULT_PATH)
    p_enroll.add_argument("--key-path", default=PASSKEY_DEFAULT_KEY_PATH)
    p_enroll.set_defaults(func=enroll_passkey_command)

    p_bio = subparsers.add_parser("enroll-biometric",
                                  help="Enroll face recognition for the vault")
    p_bio.add_argument("--vault-path", default=DEFAULT_VAULT_PATH)
    p_bio.set_defaults(func=enroll_biometric_command)

    p_shell = subparsers.add_parser("shell", help="Start interactive vault session")
    p_shell.add_argument("--vault-path", default=DEFAULT_VAULT_PATH)
    p_shell.add_argument("--timeout", type=int, default=300)
    p_shell.add_argument("--passkey", action="store_true",
                         help="Unlock using the enrolled passkey")
    p_shell.add_argument("--key-path", default=PASSKEY_DEFAULT_KEY_PATH)
    p_shell.add_argument("--biometric", action="store_true",
                         help="Unlock using face recognition")
    p_shell.add_argument("--skip-distance", action="store_true",
                         help="DEMO ONLY: bypass the biometric distance check")
    p_shell.set_defaults(func=shell_command)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()