import tkinter as tk
from tkinter import ttk, scrolledtext
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import socket
import json

# Caesar Cipher
def caesar_encrypt(plaintext: str, shift: int) -> str:
    shift = shift % 26
    ciphertext = []
    steps = []
    
    # Create alphabet table
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    steps.append("Caesar Cipher Steps:")
    steps.append("Alphabet Table:")
    steps.append("A B C D E F G H I J K L M N O P Q R S T U V W X Y Z")
    steps.append("↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓")
    shifted = ''.join([alphabet[(i + shift) % 26] for i in range(26)])
    steps.append(" ".join(shifted))
    steps.append("")
    
    # Process each character
    steps.append("Character Processing:")
    steps.append("Original | Shift | Result")
    steps.append("-" * 30)
    
    for c in plaintext:
        if c.isalpha():
            offset = ord('A') if c.isupper() else ord('a')
            original = c
            shifted_char = chr((ord(c) - offset + shift) % 26 + offset)
            steps.append(f"{original:^8} | {shift:^5} | {shifted_char:^6}")
            ciphertext.append(shifted_char)
        else:
            ciphertext.append(c)
            steps.append(f"{c:^8} |  -   | {c:^6}")
    
    return ''.join(ciphertext), steps

# Autokey Cipher
def autokey_encrypt(plaintext: str, keyword: str) -> str:
    plaintext_upper = plaintext.upper()
    keyword_upper = ''.join([c.upper() for c in keyword if c.isalpha()])
    steps = []
    
    steps.append("\nAutokey Cipher Steps:")
    steps.append(f"Keyword: {keyword_upper}")
    steps.append(f"Plaintext: {plaintext_upper}")
    
    letters = []
    indices = []
    for i, c in enumerate(plaintext_upper):
        if c.isalpha():
            letters.append(c)
            indices.append(i)
    
    keystream = list(keyword_upper)
    for c in letters:
        if len(keystream) >= len(letters):
            break
        keystream.append(c)
    keystream = keystream[:len(letters)]
    
    steps.append("\nKeystream Generation:")
    steps.append("Position | Keyword | Plaintext | Keystream")
    steps.append("-" * 50)
    
    for i, (k, p) in enumerate(zip(keyword_upper + ''.join(letters), letters)):
        if i < len(letters):
            steps.append(f"{i:^8} | {k:^7} | {p:^9} | {keystream[i]:^9}")
    
    steps.append("\nEncryption Process:")
    steps.append("Position | Plaintext | Key | Formula | Result")
    steps.append("-" * 60)
    
    encrypted_letters = []
    for i, (p, k) in enumerate(zip(letters, keystream)):
        p_num = ord(p) - ord('A')
        k_num = ord(k) - ord('A')
        c_num = (p_num + k_num) % 26
        c = chr(c_num + ord('A'))
        encrypted_letters.append(c)
        formula = f"({p_num} + {k_num}) mod 26 = {c_num}"
        steps.append(f"{i:^8} | {p:^9} | {k:^3} | {formula:^20} | {c:^6}")
    
    ciphertext = list(plaintext_upper)
    for i, c in zip(indices, encrypted_letters):
        ciphertext[i] = c
    
    return ''.join(ciphertext), steps

class EncryptionSender:
    def __init__(self, master):
        self.master = master
        master.title("Encryption & Sender")
        
        # Set minimum window size
        master.minsize(1000, 800)  # Increased size for better visibility
        
        # Configure grid weights for the main window
        master.grid_rowconfigure(0, weight=1)
        master.grid_columnconfigure(0, weight=1)
        
        # Create main frame
        main_frame = ttk.Frame(master)
        main_frame.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Create scrollable frame for RSA keys
        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw", width=980)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Configure grid weights for scrollable frame
        for i in range(8):  # 8 rows in total
            self.scrollable_frame.grid_rowconfigure(i, weight=1)
        for i in range(3):  # 3 columns
            self.scrollable_frame.grid_columnconfigure(i, weight=1)
        
        # GUI layout
        self.text_label = ttk.Label(self.scrollable_frame, text="Input Text:")
        self.text_label.grid(row=0, column=0, sticky="nw", padx=5, pady=5)
        self.text_input = scrolledtext.ScrolledText(self.scrollable_frame, width=60, height=6)
        self.text_input.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky="nsew")
        
        self.caesar_label = ttk.Label(self.scrollable_frame, text="Caesar Shift Key:")
        self.caesar_label.grid(row=1, column=0, sticky="nw", padx=5, pady=5)
        self.caesar_key = ttk.Entry(self.scrollable_frame, width=40)
        self.caesar_key.grid(row=1, column=1, sticky="nw", padx=5, pady=5)
        
        self.autokey_label = ttk.Label(self.scrollable_frame, text="Autokey Keyword:")
        self.autokey_label.grid(row=2, column=0, sticky="nw", padx=5, pady=5)
        self.autokey_key = ttk.Entry(self.scrollable_frame, width=40)
        self.autokey_key.grid(row=2, column=1, sticky="nw", padx=5, pady=5)
        
        # RSA Key Section
        self.rsa_frame = ttk.LabelFrame(self.scrollable_frame, text="RSA Keys (Optional)")
        self.rsa_frame.grid(row=3, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")
        self.rsa_frame.grid_columnconfigure(1, weight=1)
        
        self.rsa_e_label = ttk.Label(self.rsa_frame, text="RSA e:")
        self.rsa_e_label.grid(row=0, column=0, sticky="nw", padx=5, pady=5)
        self.rsa_e_entry = ttk.Entry(self.rsa_frame, width=60)
        self.rsa_e_entry.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        
        self.rsa_d_label = ttk.Label(self.rsa_frame, text="RSA d:")
        self.rsa_d_label.grid(row=1, column=0, sticky="nw", padx=5, pady=5)
        self.rsa_d_entry = ttk.Entry(self.rsa_frame, width=60)
        self.rsa_d_entry.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        
        self.rsa_n_label = ttk.Label(self.rsa_frame, text="RSA n:")
        self.rsa_n_label.grid(row=2, column=0, sticky="nw", padx=5, pady=5)
        self.rsa_n_entry = ttk.Entry(self.rsa_frame, width=60)
        self.rsa_n_entry.grid(row=2, column=1, sticky="nsew", padx=5, pady=5)
        
        self.generate_rsa_btn = ttk.Button(self.rsa_frame, text="Generate New RSA Keys", command=self.generate_rsa_keys)
        self.generate_rsa_btn.grid(row=3, column=0, columnspan=2, pady=5)
        
        # Network Settings
        self.network_frame = ttk.LabelFrame(self.scrollable_frame, text="Network Settings")
        self.network_frame.grid(row=4, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")
        self.network_frame.grid_columnconfigure(1, weight=1)
        
        self.ip_label = ttk.Label(self.network_frame, text="Receiver IP:")
        self.ip_label.grid(row=0, column=0, sticky="nw", padx=5, pady=5)
        self.ip_entry = ttk.Entry(self.network_frame, width=40)
        self.ip_entry.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        self.ip_entry.insert(0, "127.0.0.1")  # Default to localhost
        
        self.port_label = ttk.Label(self.network_frame, text="Port:")
        self.port_label.grid(row=1, column=0, sticky="nw", padx=5, pady=5)
        self.port_entry = ttk.Entry(self.network_frame, width=40)
        self.port_entry.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        self.port_entry.insert(0, "5000")  # Default port
        
        # Buttons frame
        self.button_frame = ttk.Frame(self.scrollable_frame)
        self.button_frame.grid(row=5, column=0, columnspan=3, pady=10)
        
        self.encrypt_send_btn = ttk.Button(self.button_frame, text="Encrypt & Send", command=self.encrypt_and_send)
        self.encrypt_send_btn.pack(side=tk.LEFT, padx=5)
        
        # Encryption Steps Display
        self.steps_frame = ttk.LabelFrame(self.scrollable_frame, text="Encryption Steps")
        self.steps_frame.grid(row=6, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")
        self.steps_frame.grid_columnconfigure(0, weight=1)
        
        self.steps_area = scrolledtext.ScrolledText(self.steps_frame, width=80, height=15)
        self.steps_area.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        
        # Status section
        self.status_frame = ttk.LabelFrame(self.scrollable_frame, text="Status")
        self.status_frame.grid(row=7, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")
        self.status_frame.grid_columnconfigure(0, weight=1)
        
        self.output_area = scrolledtext.ScrolledText(self.status_frame, width=60, height=4)
        self.output_area.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        
        # Configure canvas and scrollbar
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        
        # Store RSA key
        self.rsa_key = None
        
        # Bind window resize event
        master.bind("<Configure>", self.on_window_resize)
        
    def on_window_resize(self, event):
        # Update canvas width when window is resized
        if event.widget == self.master:
            self.scrollable_frame.configure(width=event.width - 40)  # 40 pixels for padding and scrollbar

    def generate_rsa_keys(self):
        try:
            # Generate new RSA key
            self.rsa_key = RSA.generate(2048)
            public_key = self.rsa_key.publickey()
            
            # Update GUI
            self.rsa_e_entry.delete(0, tk.END)
            self.rsa_e_entry.insert(0, str(public_key.e))
            self.rsa_d_entry.delete(0, tk.END)
            self.rsa_d_entry.insert(0, str(self.rsa_key.d))
            self.rsa_n_entry.delete(0, tk.END)
            self.rsa_n_entry.insert(0, str(public_key.n))
            
            # Show RSA key generation steps
            self.steps_area.delete("1.0", tk.END)
            self.steps_area.insert(tk.END, "RSA Key Generation Steps:\n")
            self.steps_area.insert(tk.END, f"1. Generated 2048-bit RSA key pair\n")
            self.steps_area.insert(tk.END, f"2. Public Exponent (e): {public_key.e}\n")
            self.steps_area.insert(tk.END, f"3. Private Exponent (d): {self.rsa_key.d}\n")
            self.steps_area.insert(tk.END, f"4. Modulus (n): {public_key.n}\n")
            
            self.output_area.delete("1.0", tk.END)
            self.output_area.insert(tk.END, "New RSA keys generated successfully!")
        except Exception as e:
            self.output_area.delete("1.0", tk.END)
            self.output_area.insert(tk.END, f"Error generating RSA keys: {str(e)}")

    def encrypt_and_send(self):
        input_text = self.text_input.get("1.0", tk.END).strip()
        
        # Validate Caesar shift
        if not self.caesar_key.get().isdigit():
            self.output_area.delete("1.0", tk.END)
            self.output_area.insert(tk.END, "Caesar shift must be an integer")
            return
        caesar_shift = int(self.caesar_key.get())
        autokey_keyword = self.autokey_key.get()
        
        # Clear previous steps
        self.steps_area.delete("1.0", tk.END)
        
        # Encrypt with Caesar and Autokey
        caesar_ct, caesar_steps = caesar_encrypt(input_text, caesar_shift)
        autokey_ct, autokey_steps = autokey_encrypt(caesar_ct, autokey_keyword)
        
        # Display encryption steps
        self.steps_area.insert(tk.END, "\n".join(caesar_steps))
        self.steps_area.insert(tk.END, "\n" + "="*80 + "\n")
        self.steps_area.insert(tk.END, "\n".join(autokey_steps))
        
        # Handle RSA keys
        try:
            if self.rsa_key is None:
                # Check if RSA keys are provided in the GUI
                if all([self.rsa_e_entry.get(), self.rsa_d_entry.get(), self.rsa_n_entry.get()]):
                    # Use provided keys
                    e = int(self.rsa_e_entry.get())
                    d = int(self.rsa_d_entry.get())
                    n = int(self.rsa_n_entry.get())
                    self.rsa_key = RSA.construct((n, e, d))
                else:
                    # Generate new keys
                    self.generate_rsa_keys()
            
            public_key = self.rsa_key.publickey()
            cipher_rsa = PKCS1_OAEP.new(public_key)
            
            # Split Autokey ciphertext into chunks
            chunk_size = 214
            autokey_bytes = autokey_ct.encode('utf-8')
            chunks = [autokey_bytes[i:i+chunk_size] for i in range(0, len(autokey_bytes), chunk_size)]
            
            # Show RSA encryption steps
            self.steps_area.insert(tk.END, "\n" + "="*80 + "\n")
            self.steps_area.insert(tk.END, "\nRSA Encryption Steps:\n")
            self.steps_area.insert(tk.END, f"1. Using RSA key with modulus: {public_key.n}\n")
            self.steps_area.insert(tk.END, f"2. Split message into {len(chunks)} chunks of max {chunk_size} bytes\n")
            
            # Encrypt each chunk and encode with Base64
            encrypted_chunks = []
            for i, chunk in enumerate(chunks):
                encrypted_chunk = cipher_rsa.encrypt(chunk)
                encrypted_chunks.append(base64.b64encode(encrypted_chunk).decode('utf-8'))
                self.steps_area.insert(tk.END, f"3. Chunk {i+1}: Encrypted and Base64 encoded\n")
            
            # Prepare data to send
            data = {
                'encrypted_text': ",".join(encrypted_chunks),
                'caesar_shift': caesar_shift,
                'autokey_keyword': autokey_keyword,
                'rsa_e': public_key.e,
                'rsa_d': self.rsa_key.d,
                'rsa_n': public_key.n
            }
            
            # Create socket and send data
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.ip_entry.get(), int(self.port_entry.get())))
                s.sendall(json.dumps(data).encode('utf-8'))
                
            self.output_area.delete("1.0", tk.END)
            self.output_area.insert(tk.END, "Message encrypted and sent successfully!")
            
        except Exception as e:
            self.output_area.delete("1.0", tk.END)
            self.output_area.insert(tk.END, f"Error: {str(e)}")

def main():
    root = tk.Tk()
    app = EncryptionSender(root)
    root.mainloop()

if __name__ == "__main__":
    main() 