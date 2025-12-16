import tkinter as tk
from ui.login import open_admin_dashboard

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw() 
    open_admin_dashboard(root)
    root.mainloop()
