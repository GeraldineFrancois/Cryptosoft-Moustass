import tkinter as tk
from tkinter import messagebox
import tkinter.ttk as ttk
from ui.create_admin import CreateAdminWindow
from ui.create_user import CreateUserWindow
from services.user_service import login_user

# Style constants
PRIMARY_BUTTON_STYLE = 'Primary.TButton'
SUCCESS_BUTTON_STYLE = 'Success.TButton'
DANGER_BUTTON_STYLE = 'Danger.TButton'
HEADER_LABEL_STYLE = 'Header.TLabel'
CARD_FRAME_STYLE = 'Card.TFrame'

# Message constants
SUCCESS_MESSAGE = "Succès"

# Define modern styles
def setup_styles():
    style = ttk.Style()
    style.theme_use('clam')  # Modern theme

    # Button styles
    style.configure('TButton', font=('Helvetica', 10, 'bold'), padding=6)
    style.configure(PRIMARY_BUTTON_STYLE, background='#007bff', foreground='white')
    style.map(PRIMARY_BUTTON_STYLE, background=[('active', '#0056b3')])

    style.configure(SUCCESS_BUTTON_STYLE, background='#28a745', foreground='white')
    style.map(SUCCESS_BUTTON_STYLE, background=[('active', '#1e7e34')])

    style.configure(DANGER_BUTTON_STYLE, background='#dc3545', foreground='white')
    style.map(DANGER_BUTTON_STYLE, background=[('active', '#bd2130')])

    # Label styles
    style.configure('TLabel', font=('Helvetica', 10))
    style.configure(HEADER_LABEL_STYLE, font=('Helvetica', 16, 'bold'), foreground='#333')

    # Entry styles
    style.configure('TEntry', padding=5)

    # Frame styles
    style.configure(CARD_FRAME_STYLE, background='#f8f9fa', relief='raised', borderwidth=1)

setup_styles()


class AdminDashboard:
    def __init__(self, parent, admin_user):
        self.parent = parent
        self.admin_user = admin_user
        self.window = tk.Toplevel(parent)
        self.window.title("Dashboard Administrateur")
        self.window.geometry("550x450")
        self.window.configure(bg='#f0f0f0')

        main_frame = ttk.Frame(self.window, style=CARD_FRAME_STYLE, padding=20)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        ttk.Label(main_frame, text=f"Bienvenue {admin_user['firstname']} {admin_user['lastname']}", style=HEADER_LABEL_STYLE).pack(pady=(0, 20))

        # Buttons in a grid
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)

        ttk.Button(btn_frame, text="Créer Admin", style=PRIMARY_BUTTON_STYLE, command=self.create_admin).grid(row=0, column=0, padx=5, pady=5, sticky='ew')
        ttk.Button(btn_frame, text="Créer Utilisateur", style=PRIMARY_BUTTON_STYLE, command=self.create_user).grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        ttk.Button(btn_frame, text="Signer Fichier", style=SUCCESS_BUTTON_STYLE, command=self.sign_file).grid(row=1, column=0, padx=5, pady=5, sticky='ew')
        ttk.Button(btn_frame, text="Vérifier Signature", style=SUCCESS_BUTTON_STYLE, command=self.verify_signature).grid(row=1, column=1, padx=5, pady=5, sticky='ew')

        ttk.Button(btn_frame, text="Fermer", style=DANGER_BUTTON_STYLE, command=self.window.destroy).grid(row=2, column=0, columnspan=2, pady=10, sticky='ew')

        # Configure grid
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)

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
        self.window.geometry("550x500")
        self.window.configure(bg='#f0f0f0')

        main_frame = ttk.Frame(self.window, style=CARD_FRAME_STYLE, padding=20)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        ttk.Label(main_frame, text="Signer un fichier", style=HEADER_LABEL_STYLE).pack(pady=(0, 10))

        ttk.Label(main_frame, text="Fichiers uploadés:").pack(anchor='w', pady=(0, 5))
        self.file_listbox = tk.Listbox(main_frame, width=50, height=8, font=('Courier', 9))
        self.file_listbox.pack(pady=(0, 10), fill=tk.X)

        self.load_files()

        ttk.Label(main_frame, text="Votre clé privée (PEM):").pack(anchor='w', pady=(0, 5))
        self.private_key_text = tk.Text(main_frame, height=6, width=50, font=('Courier', 8))
        self.private_key_text.pack(pady=(0, 10), fill=tk.X)

        ttk.Button(main_frame, text="Signer le fichier sélectionné", style=SUCCESS_BUTTON_STYLE, command=self.sign_selected_file).pack(fill=tk.X)

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
            messagebox.showinfo(SUCCESS_MESSAGE, f"Fichier signé avec succès.\nSignature: {signature[:50]}...")
            self.window.destroy()
        except Exception as e:
            messagebox.showerror("Erreur", f"Échec de la signature: {str(e)}")


class VerifySignatureWindow:
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("Vérifier une signature")
        self.window.geometry("550x400")
        self.window.configure(bg='#f0f0f0')

        main_frame = ttk.Frame(self.window, style=CARD_FRAME_STYLE, padding=20)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        ttk.Label(main_frame, text="🔍 Vérifier une signature", style=HEADER_LABEL_STYLE).pack(pady=(0, 10))

        ttk.Label(main_frame, text="Fichiers avec signatures:").pack(anchor='w', pady=(0, 5))
        self.file_listbox = tk.Listbox(main_frame, width=50, height=10, font=('Courier', 9))
        self.file_listbox.pack(pady=(0, 10), fill=tk.X)

        self.load_signed_files()

        ttk.Button(main_frame, text="Vérifier la signature sélectionnée", style=PRIMARY_BUTTON_STYLE, command=self.verify_selected).pack(fill=tk.X)

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
                messagebox.showinfo(SUCCESS_MESSAGE, "La signature est valide.")
            else:
                messagebox.showerror("Erreur", "La signature est invalide.")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la vérification: {str(e)}")


class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptosoft - Connexion")
        self.root.geometry("450x350")
        self.root.resizable(False, False)
        self.root.configure(bg='#f0f0f0')

        # Main frame
        main_frame = ttk.Frame(self.root, style=CARD_FRAME_STYLE, padding=20)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        # Header
        ttk.Label(main_frame, text="Cryptosoft", style=HEADER_LABEL_STYLE).pack(pady=(0, 20))

        ttk.Label(main_frame, text="Email :").pack(anchor='w')
        self.email_entry = ttk.Entry(main_frame, width=40)
        self.email_entry.pack(pady=(0, 10), fill=tk.X)

        ttk.Label(main_frame, text="Mot de passe :").pack(anchor='w')
        self.password_entry = ttk.Entry(main_frame, width=40, show="*")
        self.password_entry.pack(pady=(0, 20), fill=tk.X)

        # Buttons frame
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)

        ttk.Button(btn_frame, text="Se connecter", style=SUCCESS_BUTTON_STYLE, command=self.login).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="Créer un compte", command=self.create_account).pack(side=tk.RIGHT)

    def create_account(self):
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
        self.window.geometry("450x350")
        self.window.configure(bg='#f0f0f0')

        main_frame = ttk.Frame(self.window, style=CARD_FRAME_STYLE, padding=20)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        ttk.Label(main_frame, text=f"Bonjour {user['firstname']} {user['lastname']}", style=HEADER_LABEL_STYLE).pack(pady=(0, 20))

        ttk.Button(main_frame, text="Uploader un fichier", style=SUCCESS_BUTTON_STYLE, command=self.upload_file).pack(pady=10, fill=tk.X)

        ttk.Button(main_frame, text="Fermer", style=DANGER_BUTTON_STYLE, command=self.window.destroy).pack(pady=10, fill=tk.X)

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
        self.window.geometry("450x350")
        self.window.configure(bg='#f0f0f0')

        main_frame = ttk.Frame(self.window, style=CARD_FRAME_STYLE, padding=20)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        ttk.Label(main_frame, text="Changer le mot de passe", style=HEADER_LABEL_STYLE).pack(pady=(0, 10))
        ttk.Label(main_frame, text="Vous devez changer votre mot de passe temporaire.").pack(pady=(0, 20))

        ttk.Label(main_frame, text="Nouveau mot de passe:").pack(anchor='w')
        self.new_password_entry = ttk.Entry(main_frame, show="*", width=40)
        self.new_password_entry.pack(pady=(0, 10), fill=tk.X)

        ttk.Label(main_frame, text="Confirmer le mot de passe:").pack(anchor='w')
        self.confirm_password_entry = ttk.Entry(main_frame, show="*", width=40)
        self.confirm_password_entry.pack(pady=(0, 20), fill=tk.X)

        ttk.Button(main_frame, text="Changer", style=SUCCESS_BUTTON_STYLE, command=self.change_password).pack(fill=tk.X)

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

        messagebox.showinfo(SUCCESS_MESSAGE, "Mot de passe changé avec succès.")

        # Fermer la fenêtre et ouvrir le dashboard
        self.window.destroy()
        if self.user["role"] == "ADMIN":
            AdminDashboard(self.parent, self.user)
        else:
            open_user_dashboard(self.parent, self.user)
