import cv2
import glob
import json
import bcrypt
import base64
import pauseprev
import numpy as np
import matplotlib.pyplot as plt
from Crypto.Cipher import ChaCha20
from tkinter import Tk, Label, Entry, Button, Text, END


def decrypt_image(path, username, image_index, password):
    with open(f"{path}{username}/{username}.json", 'r') as f:
        result2 = json.load(f)
    b64_2 = json.loads(result2)
    salt = base64.b64decode(b64_2['salt'])
    ukey = bcrypt.kdf(password, salt, desired_key_bytes=32, rounds=100)

    with open(f"{path}{username}/encryptedimage{image_index}.json", 'r') as f:
        result = json.load(f)
    b64 = json.loads(result)
    nonce = base64.b64decode(b64['nonce'])
    ciphertext = base64.b64decode(b64['ciphertext'])

    cipher = ChaCha20.new(key=ukey, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    shape = b64['shape']
    finalres = np.frombuffer(plaintext, dtype=np.uint8).reshape(shape)

    cv2.imwrite(f"{path}{username}/image{image_index}.jpg", finalres[:, :, ::-1])
    display_image(finalres)


def display_image(image):
    plt.imshow(image.astype('uint8'))
    plt.show()


def decrypt_all(path, username, password, tcount):
    with open(f"{path}{username}/{username}.json", 'r') as f:
        result2 = json.load(f)
    b64_2 = json.loads(result2)
    salt = base64.b64decode(b64_2['salt'])
    ukey = bcrypt.kdf(password, salt, desired_key_bytes=32, rounds=100)

    for i in range(1, tcount + 1):
        with open(f"{path}{username}/encryptedimage{i}.json", 'r') as f:
            result = json.load(f)
        b64 = json.loads(result)
        nonce = base64.b64decode(b64['nonce'])
        ciphertext = base64.b64decode(b64['ciphertext'])
        cipher = ChaCha20.new(key=ukey, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        shape = b64['shape']
        finalres = np.frombuffer(plaintext, dtype=np.uint8).reshape(shape)
        cv2.imwrite(f"{path}{username}/image{i}.jpg", finalres[:, :, ::-1])
        display_image(finalres)


def create_window_decrypt(path, choice=None):
    # Use a shared variable to track the preview flag value
    pauseprev.preview_active = True
    result = [0]  # Default value is 0 unless "Return to Login" is pressed
    
    # Function to handle the window close by X button
    def on_close():
        pauseprev.preview_active = False
        window.destroy()  # Close the window
    window = Tk()
    window.title("Image Decrypter")
    window.protocol("WM_DELETE_WINDOW", on_close)
    window.focus_force()
    prevv = ""
    def changed(event):
        newv = username_entry.get()
        if prevv != newv:
            image_index_entry.delete(0, END)
            password_entry.delete(0, END)
            image_index_entry.config(state='disabled')
            password_entry.config(state='disabled')
            decrypt_button.config(state='disabled')
        
    # Username Label and Entry
    username_label = Label(window, text="Username:")
    username_label.pack(pady=5)
    username_entry = Entry(window)
    username_entry.pack(pady=5)
    username_entry.bind("<KeyRelease>", changed)

    # Image Index Label and Entry
    image_index_label = Label(window, text="Image Index")
    image_index_label.pack(pady=5)
    image_index_entry = Entry(window, state='disabled')
    image_index_entry.pack(pady=5)

    # Password Label and Entry
    password_label = Label(window, text="Password:")
    password_label.pack(pady=5)
    password_entry = Entry(window, show="*", state="disabled")  # Hide password input
    password_entry.pack(pady=5)

    # Text box placeholder for messages
    message_box = Text(window, height=5, width=50, state="normal")
    message_box.config(state='normal')
    message_box.delete(END, "end")
    message_box.insert(END, "")
    message_box.config(state='disabled')
    message_box.pack(fill="both", expand=True, pady=5)

    # Find Session button
    find_sesh_button = Button(window, text="Find Session", command=lambda: sessiongetter(
        path, username_entry.get(), message_box, decrypt_button, password_entry, image_index_entry))
    find_sesh_button.pack(side="left", padx=5, pady=5)

    # Decrypt button
    decrypt_button = Button(window, text="Decrypt", command=lambda: decrypt_handler(
        path, username_entry.get(), password_entry.get(), image_index_entry.get(), message_box), state="disabled")
    decrypt_button.pack(side="right", padx=5, pady=5)
    
    # Return to Login Button (only visible if choice == "yes" i.e username/session already exists)
    return_to_login_button = None
    if choice == "yes":
        return_to_login_button = Button(window, text="Return to Login", command=lambda: [window.destroy(), result.__setitem__(0, 1)])
        return_to_login_button.pack(side="bottom", anchor="center", padx=5, pady=5)

    window.mainloop()

    return result[0]


def sessiongetter(path, username, message_box, decrypt_button, password_entry, image_index_entry):
    try:
        global tcount
        json_files = glob.glob(f"{path}{username}/*.json")
        tcount = len(json_files) - 1
        if tcount == 0:
            message_box.config(state='normal')
            message_box.delete(END, "end")
            message_box.insert(END, f"\nSession has NO images!")
            message_box.see(END)
            message_box.config(state='disabled')
            image_index_entry.config(state='disabled')
            password_entry.config(state='disabled')
            decrypt_button.config(state='disabled')
        elif tcount == -1:
            message_box.config(state='normal')
            message_box.delete(END, "end")
            message_box.insert(END, f"\nNo Session found!")
            message_box.see(END)
            message_box.config(state='disabled')
            image_index_entry.config(state='disabled')
            password_entry.config(state='disabled')
            decrypt_button.config(state='disabled')
        else:
            message_box.config(state='normal')
            message_box.delete(END, "end")
            message_box.insert(END, f"\n\nThere are {tcount} images in this session.\nIndex starts from 1.\nEnter 0 to decrypt ALL (TIME CONSUMING)\n")
            message_box.see(END)
            message_box.config(state='disabled')
            decrypt_button.config(state="normal")
            image_index_entry.config(state='normal')
            image_index_entry.delete(0, END)
            password_entry.config(state="normal")
            password_entry.delete(0, END)
    except Exception as e:
        message_box.config(state='normal')
        message_box.delete(END, "end")
        message_box.insert(END, f"Error: {str(e)}\n")
        message_box.see(END)
        message_box.config(state='disabled')

def decrypt_handler(path, username, password, image_index, message_box):
    try:
        password = password.encode()
        image_index = int(image_index)
        if image_index == 0:
            decrypt_all(path, username, password, tcount)
        else:
            decrypt_image(path, username, image_index, password)
        message_box.config(state='normal')
        message_box.delete(END, "end")
        if image_index == 0:
          message_box.insert(END, "Decrypted all images successfully!\n")
          message_box.see(END)
          message_box.config(state='disabled')
        else:
          message_box.insert(END, f"Decrypted image #{image_index} successfully!\n")
          message_box.see(END)
          message_box.config(state='disabled')
    except Exception as e:
        message_box.config(state='normal')
        message_box.delete(END, "end")
        message_box.insert(END, f"Error: {str(e)}\n")
        message_box.see(END)
        message_box.config(state='disabled')
