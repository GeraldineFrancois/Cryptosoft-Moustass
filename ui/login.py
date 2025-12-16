import tkinter as tk
from tkinter import messagebox
from db.database import get_user_by_email
from security.hashing import hash_password

class LoginWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Cryptosoft - Secure Login")

        tk.Label(self.root, text="Email :").grid(row=0, column=0, padx=10, pady=10)
        tk.Label(self.root, text="Mot de passe :").grid(row=1, column=0, padx=10, pady=10)

        self.email_entry = tk.Entry(self.root)
        self.password_entry = tk.Entry(self.root, show="*")

        self.email_entry.grid(row=0, column=1)
        self.password_entry.grid(row=1, column=1)

        tk.Button(self.root, text="Se connecter", command=self.login).grid(row=2, column=0, columnspan=2, pady=10)

        self.root.mainloop()

    def login(self):
        email = self.email_entry.get()
        password = self.password_entry.get()

        user = get_user_by_email(email)

        if not user:
            messagebox.showerror("Erreur", "Utilisateur non trouvé.")
            return

        hashed = hash_password(password, user["password_salt"])

        if hashed != user["password_hash"]:
            messagebox.showerror("Erreur", "Mot de passe incorrect.")
            return

        # Première connexion
        if user["first_login"]:
            messagebox.showinfo("Info", "Vous devez changer votre mot de passe.")
            # Ici on ouvrira la fenêtre de changement de mot de passe
            return

        messagebox.showinfo("Succès", f"Bienvenue {user['firstname']} !")
