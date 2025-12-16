import tkinter as tk
from tkinter import messagebox

from security.validator import validate_name, validate_email, validate_password
from security.hashing import hash_password, generate_salt
from db.database import insert_user


class CreateUserWindow:
    def __init__(self):
        self.root = tk.Toplevel()
        self.root.title("Créer un compte utilisateur")

        tk.Label(self.root, text="Prénom :").grid(row=0, column=0, padx=10, pady=5)
        tk.Label(self.root, text="Nom :").grid(row=1, column=0, padx=10, pady=5)
        tk.Label(self.root, text="Email :").grid(row=2, column=0, padx=10, pady=5)
        tk.Label(self.root, text="Mot de passe par défaut :").grid(row=3, column=0, padx=10, pady=5)

        self.firstname_entry = tk.Entry(self.root)
        self.lastname_entry = tk.Entry(self.root)
        self.email_entry = tk.Entry(self.root)
        self.password_entry = tk.Entry(self.root)

        self.firstname_entry.grid(row=0, column=1)
        self.lastname_entry.grid(row=1, column=1)
        self.email_entry.grid(row=2, column=1)
        self.password_entry.grid(row=3, column=1)

        tk.Button(
            self.root,
            text="Créer l'utilisateur",
            command=self.create_user
        ).grid(row=4, column=0, columnspan=2, pady=10)


    def create_user(self):
        firstname = self.firstname_entry.get()
        lastname = self.lastname_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()

        # 1. Validations
        if not validate_name(firstname):
            messagebox.showerror("Erreur", "Le prénom est invalide.")
            return

        if not validate_name(lastname):
            messagebox.showerror("Erreur", "Le nom est invalide.")
            return

        if not validate_email(email):
            messagebox.showerror("Erreur", "Email invalide.")
            return

        if not validate_password(password):
            messagebox.showerror("Erreur", "Mot de passe non conforme.")
            return

        # 2. Hash + Salt
        password_salt = generate_salt()
        password_hash = hash_password(password, password_salt)

        # 3. Do NOT generate or store private keys here. The user will generate keys client-side on first login.

        # 4. Enregistrer en DB (no private key stored)
        insert_user(firstname, lastname, email, password_hash, password_salt)

        messagebox.showinfo("Succès", "Utilisateur créé avec succès !")
