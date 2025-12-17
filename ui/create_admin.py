import tkinter as tk
from tkinter import messagebox
from services.user_service import create_admin


class CreateAdminWindow:
    """Fenêtre de création d'administrateur ouverte comme Toplevel.

    Accepts an optional `parent` so it can be opened from a dashboard.
    """

    def __init__(self, parent=None):
        self.window = tk.Toplevel(parent) if parent is not None else tk.Toplevel()
        self.window.title("Créer un administrateur")
        self.window.geometry("400x300")

        tk.Label(self.window, text="Nom").pack()
        self.name_entry = tk.Entry(self.window)
        self.name_entry.pack()

        tk.Label(self.window, text="Email").pack()
        self.email_entry = tk.Entry(self.window)
        self.email_entry.pack()

        tk.Button(self.window, text="Créer Admin", command=self.on_submit).pack(pady=20)

    def on_submit(self):
        name = self.name_entry.get()
        email = self.email_entry.get()

        try:
            temp_password = create_admin(name, email)
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de créer l'admin : {e}")
            return

        messagebox.showinfo(
            "Admin créé",
            f"L'admin a été créé.\nMot de passe temporaire : {temp_password}"
        )

        try:
            self.window.destroy()
        except Exception:
            pass
