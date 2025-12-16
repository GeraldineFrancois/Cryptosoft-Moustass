import tkinter as tk
from tkinter import messagebox
from services.password_services import generate_salt, hash_password
from db.user_repository import update_user_password

class ChangePasswordWindow:
    def __init__(self, user):
        self.user = user
        self.root = tk.Toplevel()
        self.root.title("Changer mot de passe")

        tk.Label(self.root, text="Nouveau mot de passe").pack(pady=5)
        self.pwd1 = tk.Entry(self.root, show="*")
        self.pwd1.pack(pady=5)

        tk.Label(self.root, text="Confirmer mot de passe").pack(pady=5)
        self.pwd2 = tk.Entry(self.root, show="*")
        self.pwd2.pack(pady=5)

        tk.Button(self.root, text="Valider", command=self.submit).pack(pady=10)

    def submit(self):
        if self.pwd1.get() != self.pwd2.get():
            messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas")
            return

        salt = generate_salt()
        password_hash = hash_password(self.pwd1.get(), salt)

        update_user_password(
            user_id=self.user["id"],
            password_hash=password_hash,
            password_salt=salt
        )

        messagebox.showinfo("Succès", "Mot de passe modifié avec succès")
        self.root.destroy()
