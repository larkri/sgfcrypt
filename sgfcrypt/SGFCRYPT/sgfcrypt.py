import sgf
import tkinter as tk
from tkinter import filedialog
from tkinter.font import Font

# Global variables to store encryption_key_data and decryption_key_data
encryption_key_data = []
decryption_key_data = []

# Encryption function
def encrypt(message, encryption_key_data):
    encrypted_message = []
    for char, (move, comment) in zip(message, encryption_key_data):
        encrypted_char = chr((ord(move[0]) + len(comment) + ord(char)) % 128)
        encrypted_message.append(encrypted_char)
    return ''.join(encrypted_message)

# Decryption function
def decrypt(encrypted_message, decryption_key_data):
    decrypted_message = []
    for char, (move, comment) in zip(encrypted_message, decryption_key_data):
        decrypted_char = chr((ord(char) - len(comment) - ord(move[0])) % 128)
        decrypted_message.append(decrypted_char)
    return ''.join(decrypted_message)

# Load SGF file and extract key data for encryption
def load_encryption_key_sgf(file_path):
    with open(file_path, 'r') as f:
        sgf_content = f.read()
    collection = sgf.parse(sgf_content)
    game = collection[0]
    key_data = []
    for node in game.rest:
        move_property = node.properties.get('B') or node.properties.get('W')
        if move_property:
            key_data.append((move_property[0], node.properties.get('C', [''])[0]))
    return key_data

# Load SGF file and extract key data for decryption
def load_decryption_key_sgf(file_path):
    with open(file_path, 'r') as f:
        sgf_content = f.read()
    collection = sgf.parse(sgf_content)
    game = collection[0]
    key_data = []
    for node in game.rest:
        move_property = node.properties.get('B') or node.properties.get('W')
        if move_property:
            key_data.append((move_property[0], node.properties.get('C', [''])[0]))
    return key_data

# GUI functions
def select_encryption_key_file():
    global encryption_key_data
    encryption_key_path = filedialog.askopenfilename(filetypes=[("SGF files", "*.sgf")])
    if encryption_key_path:
        encryption_key_data = load_encryption_key_sgf(encryption_key_path)
        encryption_key_file_label.config(text=encryption_key_path)

def select_decryption_key_file():
    global decryption_key_data
    decryption_key_path = filedialog.askopenfilename(filetypes=[("SGF files", "*.sgf")])
    if decryption_key_path:
        decryption_key_data = load_decryption_key_sgf(decryption_key_path)
        decryption_key_file_label.config(text=decryption_key_path)

# Encryption function
def encrypt_message():
    message = message_box.get()
    encrypted_msg = encrypt(message, encryption_key_data)
    encrypted_output_enc.config(state=tk.NORMAL)
    encrypted_output_enc.delete(0, tk.END)
    encrypted_output_enc.insert(0, encrypted_msg)

# Decryption function
def decrypt_message():
    encrypted_msg = encrypted_output_dec.get()
    decrypted_msg = decrypt(encrypted_msg, decryption_key_data)
    decrypted_output.config(state=tk.NORMAL)
    decrypted_output.delete(0, tk.END)
    decrypted_output.insert(0, decrypted_msg)

# Create GUI
root = tk.Tk()
root.title("SGFCRYPT")

# Set window icon
root.iconbitmap(r'C:\Users\Kristoffer Larsson\Desktop\SGFCRYPT\sgfcrypt\SGFCRYPT\sgfcrypt_icon.ico')

# Encryption section
encryption_label_font = Font(root, weight="bold")
encryption_label = tk.Label(root, text="Encryption", font=encryption_label_font)
encryption_label.pack()

encryption_key_file_label = tk.Label(root, text="No encryption key file selected")
encryption_key_file_label.pack()

select_encryption_key_button = tk.Button(root, text="Select Encryption Key SGF File", command=select_encryption_key_file)
select_encryption_key_button.pack(pady=5)

message_label_enc = tk.Label(root, text="Enter message for Encryption:")
message_label_enc.pack()

message_box = tk.Entry(root)
message_box.pack()

encrypt_button = tk.Button(root, text="Encrypt Message", state=tk.NORMAL, command=encrypt_message)
encrypt_button.pack(pady=5)

encrypted_output_enc = tk.Entry(root, state=tk.DISABLED)
encrypted_output_enc.pack()

# Padding to create space between sections
padding_label = tk.Label(root, text="", height=1)
padding_label.pack()

# Draw a line to separate the sections
line_canvas = tk.Canvas(root, height=2, width=300, bg="black")
line_canvas.pack()

# Padding to create space between sections
padding_label = tk.Label(root, text="", height=1)
padding_label.pack()

# Decryption section
decryption_label_font = Font(root, weight="bold")
decryption_label = tk.Label(root, text="Decryption", font=decryption_label_font)
decryption_label.pack()

decryption_key_file_label = tk.Label(root, text="No decryption key file selected")
decryption_key_file_label.pack()

select_decryption_key_button = tk.Button(root, text="Select Decryption Key SGF File", command=select_decryption_key_file)
select_decryption_key_button.pack(pady=5)

encrypted_output_dec = tk.Entry(root)
encrypted_output_dec.pack()

decrypt_button = tk.Button(root, text="Decrypt Message", state=tk.NORMAL, command=decrypt_message)
decrypt_button.pack(pady=5)

decrypted_output = tk.Entry(root, state=tk.DISABLED)
decrypted_output.pack()

# Adjust the default window position and size
default_window_x = root.winfo_screenwidth() // 2 - 150  # Half the window width
default_window_y = (root.winfo_screenheight() // 2) - 200  # Move the window slightly down
root.geometry(f"300x400+{default_window_x}+{default_window_y}")  # Adjust the window size

root.mainloop()
