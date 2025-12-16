import tkinter as tk
from tkinter import messagebox
from ui.create_admin import CreateAdminWindow
from ui.create_user import CreateUserWindow
from services.user_service import login_user


def open_admin_dashboard(root):
    dashboard = tk.Toplevel(root)
    dashboard.title("Dashboard Administrateur")
    dashboard.geometry("400x200")

    tk.Label(
        dashboard,
        text="Dashboard Administrateur",
        font=("Helvetica", 14, "bold")
    ).pack(pady=10)

    tk.Button(
        dashboard,
        text="Créer un Administrateur",
        command=lambda: CreateAdminWindow(dashboard)
    ).pack(pady=10)

    tk.Button(
        dashboard,
        text="Créer un Utilisateur",
        command=lambda: CreateUserWindow(dashboard)
    ).pack(pady=10)


class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptosoft - Connexion")
        self.root.geometry("400x300")
        self.root.resizable(False, False)

        tk.Label(
            self.root,
            text="Connexion",
            font=("Helvetica", 16, "bold")
        ).pack(pady=20)

        tk.Label(self.root, text="Email :").pack()
        self.email_entry = tk.Entry(self.root, width=30)
        self.email_entry.pack(pady=5)

        tk.Label(self.root, text="Mot de passe :").pack()
        self.password_entry = tk.Entry(self.root, show="*", width=30)
        self.password_entry.pack(pady=5)

        tk.Button(
            self.root,
            text="Se connecter",
            command=self.login,
            bg="#4CAF50",
            fg="white",
            relief=tk.FLAT
        ).pack(pady=15)

        # ✅ Bouton création de compte utilisateur
        tk.Button(
            self.root,
            text="Créer un compte",
            command=self.create_account
        ).pack(pady=5)

    def create_account(self):
        # Ouvrir la fenêtre de création d'administrateur
        CreateAdminWindow(self.root)

    def login(self):
        email = self.email_entry.get()
        password = self.password_entry.get()

        if not email or not password:
            messagebox.showerror(
                "Erreur",
                "Veuillez entrer l'email et le mot de passe."
            )
            return

        user = login_user(email, password)

        if not user:
            messagebox.showerror(
                "Erreur",
                "Email ou mot de passe incorrect."
            )
            return

        # Nettoyage de la fenêtre login
        for widget in self.root.winfo_children():
            widget.destroy()

        if user["role"] == "ADMIN":
            open_admin_dashboard(self.root)
        else:
            open_user_dashboard(self.root, user)


class UserDashboard:
    def __init__(self, parent, user):
        self.window = tk.Toplevel(parent)
        self.window.title("Dashboard Utilisateur")
        self.window.geometry("400x200")

        tk.Label(
            self.window,
            text=f"Bonjour {user['name']}, vous êtes {user['role']}.",
            font=("Helvetica", 14)
        ).pack(pady=50)

        tk.Button(
            self.window,
            text="Fermer",
            command=self.window.destroy
        ).pack()



def open_user_dashboard(root, user):
    UserDashboard(root, user)
