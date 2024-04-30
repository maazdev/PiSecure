import cv2
import pisec
import pidesec
import platform
import pauseprev
import keycreate
import tkinter as tk
import tkinter.messagebox as messagebox
from PIL import Image, ImageTk

ctr = 0
ready_for_next = True
path = None

# Function to update camera preview
def update_preview():
    global frame, ready_for_next
    if pauseprev.preview_active:
        camera_label.after(1000, update_preview)
        return
    ret, frame = cap.read()
    if ret:
        cv2image = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        img = Image.fromarray(cv2image)
        width = int(root.winfo_screenwidth()/1.4)
        height = int(root.winfo_screenheight()/1.4)
        img = img.resize((width, height), Image.Resampling.NEAREST)
        imgtk = ImageTk.PhotoImage(image=img)
        camera_label.config(image=imgtk)
        camera_label.image = imgtk
        if ready_for_next:
            camera_label.after(10, update_preview)

# Function to capture image
def capture_image(ukey):
    global ctr, ready_for_next
    if ready_for_next:
        if ctr == 0:
            ctr += 1
        cv2.imwrite(f"{path}{username}/image{ctr}.jpg", frame)
        ready_for_next = pisec.encrypt(ukey, path, ctr, username)
        ctr += 1
        ctr_label.config(text=f"Count: {ctr-1}")


# Function to handle button click
def new_session_button_click(root):
    global ctr, ready_for_next, path
    ctr = 0
    ready_for_next = True
    cap.release()
    root.destroy()
    login_screen()  # Redirect to login


# Function for login screen
def login_screen():
    global path, username
    ukey, path, username = keycreate.sessionkey()
    root = tk.Tk()
    root.withdraw()
    if ukey == -1 and username == -1:
        choice = messagebox.askquestion(
            title="Username Exists",
            message="Username already in use!\nClick YES to launch Decrypter | Click NO to try again.\n(NOTE: PiSecure supports one-time sessions only)",
            icon="warning",
        )
        if choice == "yes":
            root.destroy()
            gocam = pidesec.create_window_decrypt(path, choice)
            if gocam == 1:
                pauseprev.preview_active = False
                login_screen()
        elif choice == "no":
            root.destroy()
            login_screen()

    else:
        root.destroy()
        create_app_window(ukey)


# Function to create main application window
def create_app_window(ukey):
    global cap, camera_label, capture_button, decrypt_button, new_session_button, ctr_label, wrn_label, root

    def on_close():
        cap.release()
        root.destroy()
    
    root = tk.Tk()
    root.title("PiSecure")
    if platform.system() == "Windows":
        root.state('zoomed')
    else:
        root.attributes('-zoomed', 1)
    root.protocol("WM_DELETE_WINDOW", on_close)

    cap = cv2.VideoCapture(0)

    # Create camera label for full-window preview
    camera_label = tk.Label(root)
    camera_label.pack(side=tk.TOP)

    # Button container frame
    button_frame = tk.Frame(root, bg="gray")
    button_frame.pack(fill=tk.X, side=tk.BOTTOM)

    # Capture button
    capture_button = tk.Button(button_frame, text="Capture", command=lambda: capture_image(ukey),
                                bg="gray", fg="white", font=("Arial", 16, "bold"))
    capture_button.pack(side=tk.LEFT, expand=True)

    # Decrypt button
    decrypt_button = tk.Button(button_frame, text="Decrypt", command=lambda: pidesec.create_window_decrypt(path),
                                bg="lightblue", fg="black", font=("Arial", 14, "bold"))
    decrypt_button.pack(side=tk.RIGHT, expand=True)

    # New session button
    new_session_button = tk.Button(button_frame, text="New Session", command=lambda: new_session_button_click(root),
                                bg="lightgreen", fg="black", font=("Arial", 14, "bold"))
    new_session_button.pack(side=tk.LEFT, expand=True)

    # Counter label
    ctr_label = tk.Label(root, text=f"Count: {ctr}", font=("Arial", 16, "bold"))
    ctr_label.pack(side=tk.TOP, anchor=tk.W, padx=10, pady=10)

    # Warning label
    wrn_label = tk.Label(root, text=f"CLOSING PISECURE OR STARTING NEW SESSION WILL END {username}'s ONE-TIME SESSION", font=("Arial", 16, "bold"))
    wrn_label.pack(side=tk.BOTTOM, anchor=tk.E, padx=10, pady=10)

    # Start the update preview loop
    update_preview()

    root.mainloop()


# Start the application by showing the login screen
login_screen()
