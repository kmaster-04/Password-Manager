import io
import contextlib
import os
import tkinter as tk
from tkinter import ttk, messagebox

import vault
import password_gen
import totp
import health_audit
import passkey
import biometric_auth
from session import VaultSession

DEFAULT_VAULT_PATH = "vault.vault"
PASSKEY_DEFAULT_KEY_PATH = "passkey_device.pem"
COMMON_PASSWORDS_FILE = "rockyou_sample.txt"
LOCK_CHECK_INTERVAL_MS = 2000
TOTP_UPDATE_INTERVAL_MS = 1000


class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("920x620")
        self.root.minsize(760, 500)

        self.session = None
        self.vault_path = DEFAULT_VAULT_PATH
        self._lock_check_id = None
        self._totp_update_id = None

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.show_unlock_screen()

    def _clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_unlock_screen(self):
        self._cancel_timers()
        self.session = None
        self._clear_root()

        frame = ttk.Frame(self.root, padding=40)
        frame.pack(expand=True)

        ttk.Label(frame, text="Password Manager",
                  font=("Segoe UI", 20, "bold")).grid(
            row=0, column=0, columnspan=2, pady=(0, 30))

        ttk.Label(frame, text="Vault file:").grid(
            row=1, column=0, sticky="e", padx=(0, 10), pady=6)
        self.path_var = tk.StringVar(value=DEFAULT_VAULT_PATH)
        ttk.Entry(frame, textvariable=self.path_var, width=32).grid(
            row=1, column=1, pady=6)

        ttk.Label(frame, text="Master password:").grid(
            row=2, column=0, sticky="e", padx=(0, 10), pady=6)
        self.password_var = tk.StringVar()
        pw_entry = ttk.Entry(frame, textvariable=self.password_var,
                             show="*", width=32)
        pw_entry.grid(row=2, column=1, pady=6)
        pw_entry.bind("<Return>", lambda e: self._unlock_with_password())

        ttk.Button(frame, text="Unlock with password",
                   command=self._unlock_with_password).grid(
            row=3, column=0, columnspan=2, pady=(20, 6), sticky="ew")
        ttk.Button(frame, text="Unlock with passkey",
                   command=self._unlock_with_passkey).grid(
            row=4, column=0, columnspan=2, pady=6, sticky="ew")
        ttk.Button(frame, text="Unlock with face recognition",
                   command=self._unlock_with_biometric).grid(
            row=5, column=0, columnspan=2, pady=6, sticky="ew")

        self.status_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.status_var, foreground="#a00",
                  wraplength=360).grid(row=6, column=0, columnspan=2,
                                       pady=(14, 0))
        pw_entry.focus_set()

    def _unlock_with_password(self):
        path = self.path_var.get().strip() or DEFAULT_VAULT_PATH
        password = self.password_var.get()
        if not password:
            self.status_var.set("Enter your master password.")
            return
        try:
            credentials = vault.load_vault(path, password)
        except FileNotFoundError:
            self.status_var.set(f"Vault not found: {path}")
            return
        except ValueError as e:
            self.status_var.set(str(e))
            return
        self._begin_session(path, password, credentials)

    def _unlock_with_passkey(self):
        path = self.path_var.get().strip() or DEFAULT_VAULT_PATH
        try:
            password = passkey.unlock_with_passkey(path, PASSKEY_DEFAULT_KEY_PATH)
        except (FileNotFoundError, ValueError) as e:
            self.status_var.set(str(e))
            return
        try:
            credentials = vault.load_vault(path, password)
        except Exception as e:
            self.status_var.set(f"Vault load failed after passkey unlock: {e}")
            return
        self._begin_session(path, password, credentials)

    def _unlock_with_biometric(self):
        path = self.path_var.get().strip() or DEFAULT_VAULT_PATH
        self.status_var.set("Opening webcam — blink twice and hold still.")
        self.root.update_idletasks()
        try:
            password = biometric_auth.unlock_biometric(path)
        except (FileNotFoundError, ValueError) as e:
            self.status_var.set(str(e))
            return
        except Exception as e:
            self.status_var.set(f"Biometric error: {e}")
            return
        try:
            credentials = vault.load_vault(path, password)
        except Exception as e:
            self.status_var.set(f"Vault load failed after biometric unlock: {e}")
            return
        self._begin_session(path, password, credentials)

    def _begin_session(self, path, password, credentials):
        self.vault_path = path
        self.session = VaultSession(path, password, credentials,
                                    timeout_seconds=300)
        self.show_main_screen()
        self._schedule_lock_check()

    def show_main_screen(self):
        self._clear_root()

        header = ttk.Frame(self.root, padding=(12, 8))
        header.pack(fill="x")
        ttk.Label(header, text=f"Vault: {self.vault_path}",
                  font=("Segoe UI", 11, "bold")).pack(side="left")
        ttk.Button(header, text="Lock",
                   command=self._lock_now).pack(side="right")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._build_credentials_tab()
        self._build_totp_tab()
        self._build_audit_tab()
        self._refresh_credentials()

    def _lock_now(self):
        if self.session:
            self.session.lock()
        self.show_unlock_screen()

    def _schedule_lock_check(self):
        if self._lock_check_id:
            self.root.after_cancel(self._lock_check_id)
        self._lock_check_id = self.root.after(LOCK_CHECK_INTERVAL_MS,
                                              self._check_lock)

    def _check_lock(self):
        if self.session and self.session.is_locked():
            messagebox.showinfo("Vault locked",
                                "The vault locked automatically due to inactivity.")
            self.show_unlock_screen()
            return
        self._schedule_lock_check()

    def _cancel_timers(self):
        for attr in ("_lock_check_id", "_totp_update_id"):
            ident = getattr(self, attr, None)
            if ident:
                try:
                    self.root.after_cancel(ident)
                except Exception:
                    pass
                setattr(self, attr, None)

    def _on_close(self):
        if self.session:
            self.session.lock()
        self._cancel_timers()
        self.root.destroy()

    def _build_credentials_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="Credentials")

        left = ttk.Frame(tab)
        left.pack(side="left", fill="both", expand=True)

        columns = ("service", "username", "twofa")
        self.tree = ttk.Treeview(left, columns=columns, show="headings",
                                 selectmode="browse")
        self.tree.heading("service", text="Service")
        self.tree.heading("username", text="Username")
        self.tree.heading("twofa", text="2FA")
        self.tree.column("service", width=200)
        self.tree.column("username", width=180)
        self.tree.column("twofa", width=60, anchor="center")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>",
                       lambda e: self._show_selected_details())

        scrollbar = ttk.Scrollbar(left, orient="vertical",
                                  command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        right = ttk.Frame(tab, padding=(12, 0))
        right.pack(side="right", fill="y")

        ttk.Label(right, text="Details",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))

        self.detail_service = tk.StringVar(value="—")
        self.detail_username = tk.StringVar(value="—")
        self.detail_password = tk.StringVar(value="—")
        self.detail_totp = tk.StringVar(value="—")

        for label, var in [
            ("Service:", self.detail_service),
            ("Username:", self.detail_username),
            ("Password:", self.detail_password),
            ("TOTP:", self.detail_totp),
        ]:
            row = ttk.Frame(right)
            row.pack(anchor="w", pady=2, fill="x")
            ttk.Label(row, text=label, width=10).pack(side="left")
            ttk.Label(row, textvariable=var,
                      wraplength=240).pack(side="left")

        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=12)

        ttk.Button(right, text="Add",
                   command=self._add_credential).pack(fill="x", pady=3)
        ttk.Button(right, text="Edit",
                   command=self._edit_credential).pack(fill="x", pady=3)
        ttk.Button(right, text="Delete",
                   command=self._delete_credential).pack(fill="x", pady=3)
        ttk.Button(right, text="Copy password",
                   command=self._copy_password).pack(fill="x", pady=3)
        ttk.Button(right, text="Refresh",
                   command=self._refresh_credentials).pack(fill="x",
                                                           pady=(15, 3))

    def _refresh_credentials(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        if not self.session:
            return
        for i, cred in enumerate(self.session.credentials):
            twofa = "yes" if "totp_secret" in cred else "no"
            self.tree.insert("", "end", iid=str(i),
                             values=(cred["service"], cred["username"], twofa))
        self._refresh_totp_tab()

    def _selected_index(self):
        selection = self.tree.selection()
        if not selection:
            return None
        return int(selection[0])

    def _show_selected_details(self):
        idx = self._selected_index()
        if idx is None or not self.session:
            return
        cred = self.session.credentials[idx]
        self.detail_service.set(cred["service"])
        self.detail_username.set(cred["username"])
        self.detail_password.set("•" * len(cred["password"]))
        if "totp_secret" in cred:
            try:
                code = totp.generate_totp(cred["totp_secret"])
                self.detail_totp.set(f"{code} ({totp.seconds_remaining()}s)")
            except Exception:
                self.detail_totp.set("(error)")
        else:
            self.detail_totp.set("not configured")

    def _save(self):
        vault.save_vault(self.session.vault_path,
                         self.session.master_password,
                         self.session.credentials)
        self.session.touch()

    def _add_credential(self):
        dialog = CredentialDialog(self.root, title="Add credential")
        self.root.wait_window(dialog)
        if dialog.result is None:
            return
        service, username, password, totp_secret = dialog.result
        vault.add_credential(self.session.credentials, service, username,
                             password, totp_secret)
        self._save()
        self._refresh_credentials()

    def _edit_credential(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("Edit", "Select a credential first.")
            return
        cred = self.session.credentials[idx]
        dialog = CredentialDialog(self.root, title="Edit credential",
                                  credential=cred)
        self.root.wait_window(dialog)
        if dialog.result is None:
            return
        service, username, password, totp_secret = dialog.result
        cred["service"] = service
        cred["username"] = username
        cred["password"] = password
        if totp_secret:
            cred["totp_secret"] = totp_secret
        elif "totp_secret" in cred:
            del cred["totp_secret"]
        self._save()
        self._refresh_credentials()

    def _delete_credential(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("Delete", "Select a credential first.")
            return
        cred = self.session.credentials[idx]
        if not messagebox.askyesno("Delete",
                                   f"Delete credentials for {cred['service']}?"):
            return
        del self.session.credentials[idx]
        self._save()
        self._refresh_credentials()

    def _copy_password(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("Copy", "Select a credential first.")
            return
        password = self.session.credentials[idx]["password"]
        try:
            import pyperclip
            pyperclip.copy(password)
            self.detail_password.set("copied to clipboard")
        except Exception:
            self.detail_password.set("clipboard unavailable")
        self.session.touch()

    def _build_totp_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="2FA Codes")

        ttk.Label(tab, text="Select a service to see its live code",
                  font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 8))

        self.totp_tree = ttk.Treeview(tab, columns=("service",),
                                      show="headings",
                                      selectmode="browse", height=10)
        self.totp_tree.heading("service", text="Service")
        self.totp_tree.column("service", width=260)
        self.totp_tree.pack(fill="x")
        self.totp_tree.bind("<<TreeviewSelect>>",
                            lambda e: self._update_totp_display())

        code_frame = ttk.Frame(tab, padding=(0, 20))
        code_frame.pack(anchor="w")

        self.totp_code_var = tk.StringVar(value="------")
        self.totp_timer_var = tk.StringVar(value="")

        ttk.Label(code_frame, textvariable=self.totp_code_var,
                  font=("Consolas", 36, "bold")).pack(anchor="w")
        ttk.Label(code_frame, textvariable=self.totp_timer_var,
                  font=("Segoe UI", 11)).pack(anchor="w", pady=(4, 0))

    def _refresh_totp_tab(self):
        for row in self.totp_tree.get_children():
            self.totp_tree.delete(row)
        if not self.session:
            return
        for i, cred in enumerate(self.session.credentials):
            if "totp_secret" in cred:
                self.totp_tree.insert("", "end", iid=str(i),
                                      values=(cred["service"],))
        self._schedule_totp_update()

    def _schedule_totp_update(self):
        if self._totp_update_id:
            self.root.after_cancel(self._totp_update_id)
        self._totp_update_id = self.root.after(TOTP_UPDATE_INTERVAL_MS,
                                               self._tick_totp)

    def _tick_totp(self):
        self._update_totp_display()
        self._schedule_totp_update()

    def _update_totp_display(self):
        if not self.session:
            return
        selection = self.totp_tree.selection()
        if not selection:
            self.totp_code_var.set("------")
            self.totp_timer_var.set("")
            return
        idx = int(selection[0])
        cred = self.session.credentials[idx]
        if "totp_secret" not in cred:
            self.totp_code_var.set("------")
            self.totp_timer_var.set("No TOTP secret stored.")
            return
        try:
            code = totp.generate_totp(cred["totp_secret"])
            remaining = totp.seconds_remaining()
            self.totp_code_var.set(f"{code[:3]} {code[3:]}")
            self.totp_timer_var.set(f"Expires in {remaining} seconds")
        except Exception as e:
            self.totp_code_var.set("error")
            self.totp_timer_var.set(str(e))

    def _build_audit_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="Health Audit")

        header = ttk.Frame(tab)
        header.pack(fill="x")
        ttk.Label(header, text="Password health audit",
                  font=("Segoe UI", 11, "bold")).pack(side="left")
        ttk.Button(header, text="Run audit",
                   command=self._run_audit).pack(side="right")

        self.audit_text = tk.Text(tab, wrap="word",
                                  font=("Consolas", 10), height=20)
        self.audit_text.pack(fill="both", expand=True, pady=(10, 0))

    def _run_audit(self):
        if not self.session:
            return
        common = health_audit.load_common_passwords(COMMON_PASSWORDS_FILE)
        report = health_audit.audit_vault(self.session.credentials,
                                          common_passwords=common)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            health_audit.print_report(report)
        self.audit_text.delete("1.0", "end")
        self.audit_text.insert("1.0", buf.getvalue())
        self.session.touch()


class CredentialDialog(tk.Toplevel):
    def __init__(self, parent, title="Credential", credential=None):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.result = None
        self.transient(parent)

        pad = {"padx": 8, "pady": 5}

        ttk.Label(self, text="Service:").grid(row=0, column=0, sticky="e", **pad)
        self.service_var = tk.StringVar(
            value=credential["service"] if credential else "")
        ttk.Entry(self, textvariable=self.service_var,
                  width=34).grid(row=0, column=1, **pad)

        ttk.Label(self, text="Username:").grid(row=1, column=0, sticky="e", **pad)
        self.username_var = tk.StringVar(
            value=credential["username"] if credential else "")
        ttk.Entry(self, textvariable=self.username_var,
                  width=34).grid(row=1, column=1, **pad)

        ttk.Label(self, text="Password:").grid(row=2, column=0, sticky="e", **pad)
        self.password_var = tk.StringVar(
            value=credential["password"] if credential else "")
        ttk.Entry(self, textvariable=self.password_var,
                  width=34, show="*").grid(row=2, column=1, **pad)

        ttk.Button(self, text="Generate",
                   command=self._generate).grid(row=2, column=2, **pad)

        ttk.Label(self, text="TOTP secret:").grid(row=3, column=0,
                                                  sticky="e", **pad)
        self.totp_var = tk.StringVar(
            value=credential.get("totp_secret", "") if credential else "")
        ttk.Entry(self, textvariable=self.totp_var,
                  width=34).grid(row=3, column=1, **pad)

        ttk.Label(self, text="(leave blank if none)").grid(
            row=4, column=1, sticky="w", padx=8)

        buttons = ttk.Frame(self, padding=(8, 12))
        buttons.grid(row=5, column=0, columnspan=3, sticky="ew")
        ttk.Button(buttons, text="Save",
                   command=self._save).pack(side="right", padx=4)
        ttk.Button(buttons, text="Cancel",
                   command=self._cancel).pack(side="right")

        self.bind("<Return>", lambda e: self._save())
        self.bind("<Escape>", lambda e: self._cancel())

        self.update_idletasks()
        try:
            px = (parent.winfo_rootx() + (parent.winfo_width() // 2)
                  - (self.winfo_width() // 2))
            py = (parent.winfo_rooty() + (parent.winfo_height() // 2)
                  - (self.winfo_height() // 2))
            self.geometry(f"+{max(0, px)}+{max(0, py)}")
        except Exception:
            pass

        self.grab_set()
        self.focus_force()

    def _generate(self):
        self.password_var.set(password_gen.generate_password(length=20))

    def _cancel(self):
        self.result = None
        self.destroy()

    def _save(self):
        service = self.service_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        totp_secret = self.totp_var.get().strip() or None

        if not service or not username or not password:
            messagebox.showwarning("Missing fields",
                                   "Service, username, and password are required.",
                                   parent=self)
            return

        if totp_secret:
            try:
                totp.generate_totp(totp_secret)
            except Exception as e:
                messagebox.showwarning("Invalid TOTP secret", str(e), parent=self)
                return

        self.result = (service, username, password, totp_secret)
        self.destroy()


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("vista")
    except Exception:
        pass
    PasswordManagerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()