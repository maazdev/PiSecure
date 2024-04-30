import shutil
import bcrypt
import readsalt
import tkinter as tk
from tkinter import ttk

def sessionkey():
    result = []
    def chngusr(path, username, session2_button, session_button, password_entry):
        shutil.rmtree(f"{path}{username}")
        username_entry.config(state='normal')
        password_entry.delete(0, tk.END)
        password_entry.config(state='disabled')
        session_button.config(text="Find Session", command=find_session)
        session2_button.grid_forget()
    def find_session():
        username = username_entry.get()
        salt, path = readsalt.rs(username)
        if salt == -1:
            # If session already exists by this username, return values which throw error
            result.append((-1, path, -1))
            window.destroy()
        else:
            # If session does not exist, continue generation of key
            password_entry.config(state='normal')
            session_button.config(text="Start One Time Session", command=lambda: start_one_time_session(salt, path))
            error_label.config(text="")
            username_entry.config(state='disabled')
            session2_button = ttk.Button(window, text="Change Username", command=lambda: chngusr(path, username, session2_button, session_button, password_entry))
            session2_button.grid(row=3, column=0, padx=10, pady=10, sticky="w")
            return salt, path

    def start_one_time_session(salt, path):
        password = password_entry.get()
        if len(password) < 8:
            error_label.config(text="Password must be at least 8 characters long.")
            return

        # If the password is valid, compute the session key
        password = password.encode()
        ukey = bcrypt.kdf(password, salt, desired_key_bytes=32, rounds=100)
        result.append((ukey, path, username_entry.get()))
        window.destroy()  # Close the window

    def toggle_password():
        if show_password_var.get():
            password_entry.config(show="")
        else:
            password_entry.config(show="*")

    window = tk.Tk()
    window.title("Session Finder")

    window.focus_force()

    # Username label and entry
    username_label = ttk.Label(window, text="Username:")
    username_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
    username_entry = ttk.Entry(window)
    username_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

    # Password label and entry
    password_label = ttk.Label(window, text="Password:")
    password_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
    password_entry = ttk.Entry(window, show="*", state="disabled")  # Initially hide the password
    password_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

    # Show password checkbox
    show_password_var = tk.BooleanVar(value=False)
    show_password_checkbox = ttk.Checkbutton(
        window, text="Show Password", variable=show_password_var, command=toggle_password
    )
    show_password_checkbox.grid(row=2, column=1, padx=10, pady=10, sticky="w")

    # Button
    session_button = ttk.Button(window, text="Find Session", command=find_session)
    session_button.grid(row=3, column=1, padx=10, pady=10, sticky="e")

    # Error label placeholder
    error_label = ttk.Label(window, text="")
    error_label.grid(row=4, column=0, columnspan=2, sticky="w")

    window.mainloop()

    # Return the result or None if no interaction
    return result[0] if result else None
