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

        if user["first_login"] == 1:
            ChangePasswordWindow(self.root, user)
        elif user["role"] == "ADMIN":
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
            text=f"Bonjour {user['firstname']} {user['lastname']}, vous êtes {user['role']}.",
            font=("Helvetica", 14)
        ).pack(pady=50)

        tk.Button(
            self.window,
            text="Fermer",
            command=self.window.destroy
        ).pack()



def open_user_dashboard(root, user):
    UserDashboard(root, user)


class ChangePasswordWindow:
    def __init__(self, parent, user):
        self.parent = parent
        self.user = user
        self.window = tk.Toplevel(parent)
        self.window.title("Changer le mot de passe")
        self.window.geometry("400x300")

        tk.Label(
            self.window,
            text="Vous devez changer votre mot de passe temporaire.",
            font=("Helvetica", 12)
        ).pack(pady=10)

        tk.Label(self.window, text="Nouveau mot de passe:").pack()
        self.new_password_entry = tk.Entry(self.window, show="*", width=30)
        self.new_password_entry.pack(pady=5)

        tk.Label(self.window, text="Confirmer le mot de passe:").pack()
        self.confirm_password_entry = tk.Entry(self.window, show="*", width=30)
        self.confirm_password_entry.pack(pady=5)

        tk.Button(
            self.window,
            text="Changer",
            command=self.change_password,
            bg="#4CAF50",
            fg="white",
            relief=tk.FLAT
        ).pack(pady=15)

    def change_password(self):
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if not new_password or not confirm_password:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs.")
            return

        if len(new_password) < 8:
            messagebox.showerror("Erreur", "Le mot de passe doit contenir au moins 8 caractères.")
            return

        if new_password != confirm_password:
            messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas.")
            return

        # Mettre à jour le mot de passe
        from services.user_service import update_password
        update_password(self.user["id"], new_password)

        messagebox.showinfo("Succès", "Mot de passe changé avec succès.")

        # Fermer la fenêtre et ouvrir le dashboard
        self.window.destroy()
        if self.user["role"] == "ADMIN":
            open_admin_dashboard(self.parent)
        else:
            open_user_dashboard(self.parent, self.user)
