import tkinter as tk
from ui.create_admin import CreateAdminWindow
from ui.create_user import CreateUserWindow

def open_admin_dashboard(root):
    dashboard = tk.Toplevel(root)
    dashboard.title("Dashboard Administrateur")
    dashboard.geometry("400x200")

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
