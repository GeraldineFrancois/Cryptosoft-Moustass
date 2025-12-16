import tkinter as tk
from tkinter import messagebox
from db.user_repository import get_user_by_email
from db.log_repository import insert_user_log
from security.hashing import hash_password
from services.auth_services import authenticate_user

# === Classe pour gérer l'affichage de l'interface ===
class LoginUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptosoft - Secure Login")
        self.root.geometry("400x300") 
        self.root.config(bg="#F4F6F8")

        # Ajouter un titre de page
        self.title_label = tk.Label(self.root, text="Bienvenue sur Cryptosoft", font=("Arial", 18, "bold"), bg="#F4F6F8", fg="#4B8B3B")
        self.title_label.pack(pady=20)

        # Email Label et Entry
        self.email_label = tk.Label(self.root, text="Email : ", font=("Arial", 12), bg="#F4F6F8")
        self.email_label.pack(pady=5)
        self.email_entry = self.create_entry()
        self.email_entry.pack(pady=5)

        # Mot de passe Label et Entry
        self.password_label = tk.Label(self.root, text="Mot de passe : ", font=("Arial", 12), bg="#F4F6F8")
        self.password_label.pack(pady=5)
        self.password_entry = self.create_entry(show="*")
        self.password_entry.pack(pady=5)

        # Bouton pour montrer/masquer le mot de passe
        self.toggle_password_button = tk.Button(self.root, text="👁️", command=self.toggle_password, font=("Arial", 12), bg="#F4F6F8", bd=0)
        self.toggle_password_button.pack(pady=5)

        # Bouton de connexion
        self.login_button = tk.Button(self.root, text="Se connecter", command=None, font=("Arial", 14), bg="#4B8B3B", fg="white", relief="flat", width=20)
        self.login_button.pack(pady=20)

        # Zone de message d'erreur
        self.error_message = tk.Label(self.root, text="", font=("Arial", 10), fg="red", bg="#F4F6F8")
        self.error_message.pack(pady=5)

    def create_entry(self, show=None):
        """Créer un champ de saisie avec un style moderne."""
        entry = tk.Entry(self.root, font=("Arial", 12), bd=0, relief="solid", fg="#4B8B3B", width=25, show=show)
        entry.config(highlightbackground="#4B8B3B", highlightthickness=2)
        return entry

    def toggle_password(self):
        """Afficher ou masquer le mot de passe."""
        if self.password_entry.cget("show") == "*":
            self.password_entry.config(show="")
            self.toggle_password_button.config(text="🙈")
        else:
            self.password_entry.config(show="*")
            self.toggle_password_button.config(text="👁️")

    def set_login_callback(self, callback):
        """Associer une fonction de callback au bouton de connexion."""
        self.login_button.config(command=callback)

    def show_error_message(self, message):
        """Afficher un message d'erreur."""
        self.error_message.config(text=message)

    def get_email(self):
        """Retourner l'email saisi."""
        return self.email_entry.get()

    def get_password(self):
        """Retourner le mot de passe saisi."""
        return self.password_entry.get()
    
    def login(self):
        email = self.ui.get_email()
        password = self.ui.get_password()

        user, status = authenticate_user(email, password)

        if status == "USER_NOT_FOUND":
            self.ui.show_error_message("Utilisateur introuvable")
            return

        if status == "INVALID_PASSWORD":
            self.ui.show_error_message("Mot de passe incorrect")
            return

        if status == "FIRST_LOGIN":
            self.open_change_password_window(user)

        messagebox.showinfo("Succès", f"Bienvenue {user['firstname']}")


# === Classe pour gérer la logique de connexion ===
class LoginHandler:
    def __init__(self, ui):
        self.ui = ui
        # Associer la méthode de connexion au bouton "Se connecter"
        self.ui.set_login_callback(self.login)

    def login(self):
        """Gérer la connexion de l'utilisateur."""
        email = self.ui.get_email()
        password = self.ui.get_password()

        # Validation des champs vides
        if not email or not password:
            self.ui.show_error_message("Veuillez remplir tous les champs.")
            return

        user = get_user_by_email(email)

        if not user:
            self.ui.show_error_message("Utilisateur non trouvé.")
            return

        hashed = hash_password(password, user["password_salt"])

        if hashed != user["password_hash"]:
            self.ui.show_error_message("Mot de passe incorrect.")
            return

        # Première connexion
        if user["first_login"]:
            messagebox.showinfo("Info", "Vous devez changer votre mot de passe.")
            return

        self.ui.show_error_message("")  # Réinitialiser le message d'erreur
        messagebox.showinfo("Succès", f"Bienvenue {user['firstname']} !")

# === Classe principale ===
class LoginApp:
    def __init__(self):
        self.root = tk.Tk()
        # Créer l'interface utilisateur
        self.ui = LoginUI(self.root)
        # Créer un gestionnaire pour la logique de connexion
        self.login_handler = LoginHandler(self.ui)
        # Lancer l'application
        self.root.mainloop()
