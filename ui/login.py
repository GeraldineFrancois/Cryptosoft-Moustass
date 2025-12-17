import tkinter as tk
from tkinter import messagebox
from ui.create_admin import CreateAdminWindow
from ui.create_user import CreateUserWindow
from services.user_service import login_user


class AdminDashboard:
    def __init__(self, parent, admin_user):
        self.parent = parent
        self.admin_user = admin_user
        self.window = tk.Toplevel(parent)
        self.window.title("Dashboard Administrateur")
        self.window.geometry("500x400")

        tk.Label(
            self.window,
            text=f"Bienvenue {admin_user['firstname']} {admin_user['lastname']} (Admin)",
            font=("Helvetica", 14, "bold")
        ).pack(pady=10)

        tk.Button(
            self.window,
            text="Créer un Administrateur",
            command=self.create_admin
        ).pack(pady=5)

        tk.Button(
            self.window,
            text="Créer un Utilisateur",
            command=self.create_user
        ).pack(pady=5)

        tk.Button(
            self.window,
            text="Signer un fichier",
            command=self.sign_file
        ).pack(pady=5)

        tk.Button(
            self.window,
            text="Vérifier une signature",
            command=self.verify_signature
        ).pack(pady=5)

        tk.Button(
            self.window,
            text="Fermer",
            command=self.window.destroy
        ).pack(pady=10)

    def create_admin(self):
        CreateAdminWindow(self.window)

    def create_user(self):
        CreateUserWindow(self.window)

    def sign_file(self):
        SignFileWindow(self.window, self.admin_user)

    def verify_signature(self):
        VerifySignatureWindow(self.window)


class SignFileWindow:
    def __init__(self, parent, admin_user):
        self.parent = parent
        self.admin_user = admin_user
        self.window = tk.Toplevel(parent)
        self.window.title("Signer un fichier")
        self.window.geometry("500x400")

        tk.Label(self.window, text="Fichiers uploadés:").pack(pady=5)

        self.file_listbox = tk.Listbox(self.window, width=50, height=10)
        self.file_listbox.pack(pady=5)

        self.load_files()

        tk.Label(self.window, text="Votre clé privée (PEM):").pack(pady=5)
        self.private_key_text = tk.Text(self.window, height=5, width=50)
        self.private_key_text.pack(pady=5)

        tk.Button(
            self.window,
            text="Signer le fichier sélectionné",
            command=self.sign_selected_file,
            bg="#4CAF50",
            fg="white"
        ).pack(pady=10)

    def load_files(self):
        from services.user_service import get_uploaded_files
        try:
            files = get_uploaded_files()
            self.files = files
            for f in files:
                self.file_listbox.insert(tk.END, f"{f['file_name']} (par {f['firstname']} {f['lastname']})")
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de charger les fichiers: {str(e)}")

    def sign_selected_file(self):
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showerror("Erreur", "Sélectionnez un fichier.")
            return

        file_info = self.files[selection[0]]
        private_key_pem = self.private_key_text.get("1.0", tk.END).strip()

        if not private_key_pem:
            messagebox.showerror("Erreur", "Entrez votre clé privée.")
            return

        from services.user_service import sign_file
        try:
            signature = sign_file(self.admin_user['id'], file_info['id'], private_key_pem)
            messagebox.showinfo("Succès", f"Fichier signé avec succès.\nSignature: {signature[:50]}...")
            self.window.destroy()
        except Exception as e:
            messagebox.showerror("Erreur", f"Échec de la signature: {str(e)}")


class VerifySignatureWindow:
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("Vérifier une signature")
        self.window.geometry("500x300")

        tk.Label(self.window, text="Fichiers avec signatures:").pack(pady=5)

        self.file_listbox = tk.Listbox(self.window, width=50, height=10)
        self.file_listbox.pack(pady=5)

        self.load_signed_files()

        tk.Button(
            self.window,
            text="Vérifier la signature sélectionnée",
            command=self.verify_selected
        ).pack(pady=10)

    def load_signed_files(self):
        from db.database import get_connection
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT cf.id, cf.file_name, u.firstname, u.lastname
            FROM code_files cf
            JOIN signatures s ON cf.id = s.file_id
            JOIN users u ON cf.user_id = u.id
        """)
        files = cursor.fetchall()
        cursor.close()
        conn.close()
        self.files = files
        for f in files:
            self.file_listbox.insert(tk.END, f"{f['file_name']} (par {f['firstname']} {f['lastname']})")

    def verify_selected(self):
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showerror("Erreur", "Sélectionnez un fichier.")
            return

        file_info = self.files[selection[0]]
        from services.user_service import verify_file_signature
        try:
            valid = verify_file_signature(file_info['id'])
            if valid:
                messagebox.showinfo("Succès", "La signature est valide.")
            else:
                messagebox.showerror("Erreur", "La signature est invalide.")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la vérification: {str(e)}")


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
            AdminDashboard(self.root, user)
        else:
            open_user_dashboard(self.root, user)


class UserDashboard:
    def __init__(self, parent, user):
        self.parent = parent
        self.user = user
        self.window = tk.Toplevel(parent)
        self.window.title("Dashboard Utilisateur")
        self.window.geometry("400x300")

        tk.Label(
            self.window,
            text=f"Bonjour {user['firstname']} {user['lastname']}, vous êtes {user['role']}.",
            font=("Helvetica", 14)
        ).pack(pady=20)

        tk.Button(
            self.window,
            text="Uploader un fichier de code source",
            command=self.upload_file,
            bg="#4CAF50",
            fg="white",
            relief=tk.FLAT
        ).pack(pady=10)

        tk.Button(
            self.window,
            text="Fermer",
            command=self.window.destroy
        ).pack(pady=10)

    def upload_file(self):
        from tkinter import filedialog
        from services.user_service import upload_file
        import tkinter.messagebox as messagebox

        file_path = filedialog.askopenfilename(
            title="Sélectionner un fichier de code source",
            filetypes=[("Tous les fichiers", "*.*")]
        )
        if file_path:
            try:
                file_name, file_hash = upload_file(self.user['id'], file_path)
                messagebox.showinfo("Succès", f"Fichier '{file_name}' uploadé avec succès.\nHash: {file_hash}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Échec de l'upload: {str(e)}")



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
            AdminDashboard(self.parent, self.user)
        else:
            open_user_dashboard(self.parent, self.user)
