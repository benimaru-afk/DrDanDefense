import tkinter as tk
from tkinter import messagebox
import random

from auth import (
    login,
    logout,
    get_logged_in_user,
    notifications_enabled,
    set_notifications_enabled,
)

from email_notifier import (
    send_verification_email,
    send_notification_confirmation,
)


class AccountPage(tk.Frame):
    def __init__(self, parent, colors):
        super().__init__(parent, bg=colors["bg_dark"])
        self.colors = colors

        self.bg = colors.get("bg_dark", "#1f1f1f")
        self.card = "#2b2b2b"
        self.orange = "#ff6b35"
        self.white = "#ffffff"
        self.gray = "#cfcfcf"
        self.green = "#40c463"
        self.red = "#ff4d4d"

        self.pending_email = None
        self.verification_code = None
        self.notification_var = tk.BooleanVar(value=False)

        self.show_correct_page()

    def clear_page(self):
        for widget in self.winfo_children():
            widget.destroy()

    def show_correct_page(self):
        if get_logged_in_user():
            self.show_account_home()
        else:
            self.show_login_page()

    # ---------------- LOGIN PAGE ----------------

    def show_login_page(self):
        self.clear_page()

        tk.Label(
            self,
            text="My Account",
            bg=self.bg,
            fg=self.white,
            font=("Segoe UI", 28, "bold")
        ).pack(pady=(45, 10))

        tk.Label(
            self,
            text="Login to receive security alerts when attacks are detected.",
            bg=self.bg,
            fg=self.gray,
            font=("Segoe UI", 13)
        ).pack(pady=(0, 25))

        login_card = tk.Frame(self, bg=self.card, padx=45, pady=35)
        login_card.pack(pady=10)

        tk.Label(
            login_card,
            text="📧 Enter your email",
            bg=self.card,
            fg=self.white,
            font=("Segoe UI", 17, "bold")
        ).pack(pady=(0, 15))

        self.email_entry = tk.Entry(
            login_card,
            width=38,
            font=("Segoe UI", 14),
            bg="#3a3a3a",
            fg=self.white,
            insertbackground=self.white,
            relief="flat"
        )
        self.email_entry.pack(ipady=8, pady=8)

        tk.Button(
            login_card,
            text="Send Verification Code",
            command=self.handle_login,
            bg=self.orange,
            fg=self.white,
            activebackground=self.orange,
            activeforeground=self.white,
            font=("Segoe UI", 13, "bold"),
            width=24,
            relief="flat",
            cursor="hand2"
        ).pack(pady=20)

        tk.Label(
            login_card,
            text="This login is only used for email attack notifications.",
            bg=self.card,
            fg=self.gray,
            font=("Segoe UI", 11)
        ).pack(pady=(5, 0))

    def handle_login(self):
        email = self.email_entry.get().strip()

        if email == "":
            messagebox.showwarning("Missing Email", "Please enter an email first.")
            return

        if "@" not in email or "." not in email:
            messagebox.showwarning("Invalid Email", "Please enter a valid email address.")
            return

        self.pending_email = email
        self.verification_code = str(random.randint(100000, 999999))

        try:
            send_verification_email(email, self.verification_code)
            self.show_verification_page()
        except Exception as e:
            messagebox.showerror(
                "Email Error",
                f"Could not send verification email:\n\n{e}"
            )

    # ---------------- VERIFICATION PAGE ----------------

    def show_verification_page(self):
        self.clear_page()

        tk.Label(
            self,
            text="Verify Your Email",
            bg=self.bg,
            fg=self.white,
            font=("Segoe UI", 28, "bold")
        ).pack(pady=(45, 10))

        tk.Label(
            self,
            text=f"We sent a 6-digit code to {self.pending_email}",
            bg=self.bg,
            fg=self.gray,
            font=("Segoe UI", 13)
        ).pack(pady=(0, 25))

        verify_card = tk.Frame(self, bg=self.card, padx=45, pady=35)
        verify_card.pack(pady=10)

        tk.Label(
            verify_card,
            text="🔐 Enter Verification Code",
            bg=self.card,
            fg=self.white,
            font=("Segoe UI", 17, "bold")
        ).pack(pady=(0, 15))

        self.code_entry = tk.Entry(
            verify_card,
            width=18,
            font=("Segoe UI", 18),
            justify="center",
            bg="#3a3a3a",
            fg=self.white,
            insertbackground=self.white,
            relief="flat"
        )
        self.code_entry.pack(ipady=8, pady=8)

        tk.Button(
            verify_card,
            text="Verify & Login",
            command=self.verify_code,
            bg=self.orange,
            fg=self.white,
            activebackground=self.orange,
            activeforeground=self.white,
            font=("Segoe UI", 13, "bold"),
            width=18,
            relief="flat",
            cursor="hand2"
        ).pack(pady=(18, 8))

        tk.Button(
            verify_card,
            text="Back",
            command=self.show_login_page,
            bg="#444444",
            fg=self.white,
            activebackground="#555555",
            activeforeground=self.white,
            font=("Segoe UI", 12, "bold"),
            width=12,
            relief="flat",
            cursor="hand2"
        ).pack(pady=5)

    def verify_code(self):
        entered_code = self.code_entry.get().strip()

        if entered_code == self.verification_code:
            login(self.pending_email)
            messagebox.showinfo("Verified", "Email verified successfully.")
            self.show_account_home()
        else:
            messagebox.showerror("Wrong Code", "That verification code is incorrect.")

    # ---------------- ACCOUNT HOME PAGE ----------------

    def show_account_home(self):
        self.clear_page()

        email = get_logged_in_user()
        self.notification_var.set(notifications_enabled())

        tk.Label(
            self,
            text="Welcome Back 👋",
            bg=self.bg,
            fg=self.white,
            font=("Segoe UI", 28, "bold")
        ).pack(pady=(40, 5))

        tk.Label(
            self,
            text="Your alert settings and account info are below.",
            bg=self.bg,
            fg=self.gray,
            font=("Segoe UI", 13)
        ).pack(pady=(0, 20))

        card = tk.Frame(self, bg=self.card, padx=45, pady=35)
        card.pack(pady=10)

        tk.Label(
            card,
            text="🛡️ Security Alert Account",
            bg=self.card,
            fg=self.white,
            font=("Segoe UI", 20, "bold")
        ).pack(anchor="w", pady=(0, 20))

        self.add_info_row(card, "Account Email", email)
        self.add_info_row(card, "Verification", "Verified ✅")
        self.add_info_row(card, "Account Type", "Local Session")
        self.add_info_row(card, "Purpose", "Attack detection email alerts")

        status_text = "ON ✅" if notifications_enabled() else "OFF ❌"
        self.status_label = tk.Label(
            card,
            text=f"Email Notifications: {status_text}",
            bg=self.card,
            fg=self.green if notifications_enabled() else self.red,
            font=("Segoe UI", 13, "bold")
        )
        self.status_label.pack(anchor="w", pady=(20, 8))

        toggle_frame = tk.Frame(card, bg=self.card)
        toggle_frame.pack(anchor="w", pady=8)

        tk.Checkbutton(
            toggle_frame,
            text="Send me email notifications when an attack is detected",
            variable=self.notification_var,
            command=self.handle_notification_toggle,
            bg=self.card,
            fg=self.white,
            selectcolor="#3a3a3a",
            activebackground=self.card,
            activeforeground=self.white,
            font=("Segoe UI", 12),
            cursor="hand2"
        ).pack(anchor="w")

        tk.Label(
            card,
            text=(
                "When this is ON, the dashboard will email this account "
                "after a scan detects a network attack."
            ),
            bg=self.card,
            fg=self.gray,
            font=("Segoe UI", 11),
            wraplength=620,
            justify="left"
        ).pack(anchor="w", pady=(8, 25))

        tk.Button(
            card,
            text="Log Out",
            command=self.handle_logout,
            bg="#444444",
            fg=self.white,
            activebackground="#555555",
            activeforeground=self.white,
            font=("Segoe UI", 12, "bold"),
            width=16,
            relief="flat",
            cursor="hand2"
        ).pack(anchor="w")

    def add_info_row(self, parent, label, value):
        row = tk.Frame(parent, bg=self.card)
        row.pack(anchor="w", fill="x", pady=4)

        tk.Label(
            row,
            text=f"{label}:",
            bg=self.card,
            fg=self.gray,
            font=("Segoe UI", 12, "bold"),
            width=18,
            anchor="w"
        ).pack(side="left")

        tk.Label(
            row,
            text=value,
            bg=self.card,
            fg=self.white,
            font=("Segoe UI", 12),
            anchor="w"
        ).pack(side="left")

    def handle_notification_toggle(self):
        email = get_logged_in_user()
        wants_on = self.notification_var.get()

        if wants_on:
            confirm = messagebox.askyesno(
                "Confirm Email Notifications",
                f"Are you sure you want to send attack email notifications to:\n\n{email}?"
            )

            if confirm:
                try:
                    set_notifications_enabled(True)
                    send_notification_confirmation(email)
                    messagebox.showinfo(
                        "Notifications Enabled",
                        f"Email notifications are now ON.\n\nA confirmation email was sent to:\n{email}"
                    )
                except Exception as e:
                    set_notifications_enabled(False)
                    self.notification_var.set(False)
                    messagebox.showerror(
                        "Email Error",
                        f"Notifications could not be enabled because the confirmation email failed:\n\n{e}"
                    )
            else:
                self.notification_var.set(False)
                set_notifications_enabled(False)

        else:
            set_notifications_enabled(False)
            messagebox.showinfo(
                "Notifications Off",
                "Email notifications have been turned off."
            )

        self.show_account_home()

    def handle_logout(self):
        confirm = messagebox.askyesno(
            "Log Out",
            "Are you sure you want to log out?"
        )

        if confirm:
            logout()
            self.pending_email = None
            self.verification_code = None
            self.show_login_page()
