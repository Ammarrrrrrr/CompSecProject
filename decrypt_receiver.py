import tkinter as tk
from tkinter import ttk, scrolledtext
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import socket
import json
import threading

# Caesar Cipher
def caesar_decrypt(ciphertext: str, shift: int) -> str:
    return caesar_encrypt(ciphertext, -shift)

def caesar_encrypt(plaintext: str, shift: int) -> str:
    shift = shift % 26
    ciphertext = []
    for c in plaintext:
        if c.isalpha():
            offset = ord('A') if c.isupper() else ord('a')
            shifted = (ord(c) - offset + shift) % 26
            ciphertext.append(chr(shifted + offset))
        else:
            ciphertext.append(c)
    return ''.join(ciphertext)

# Autokey Cipher
def autokey_decrypt(ciphertext: str, keyword: str) -> str:
    ciphertext_upper = ciphertext.upper()
    keyword_upper = ''.join([c.upper() for c in keyword if c.isalpha()])
    
    letters = []
    indices = []
    for i, c in enumerate(ciphertext_upper):
        if c.isalpha():
            letters.append(c)
            indices.append(i)
    
    if not keyword_upper:
        return ciphertext
    
    keystream = list(keyword_upper)
    decrypted_letters = []
    for c in letters:
        if not keystream:
            break
        k = keystream.pop(0)
        c_num = ord(c) - ord('A')
        k_num = ord(k) - ord('A')
        p_num = (c_num - k_num) % 26
        p_char = chr(p_num + ord('A'))
        decrypted_letters.append(p_char)
        keystream.append(p_char)
    
    plaintext = list(ciphertext_upper)
    for i, p in zip(indices, decrypted_letters):
        plaintext[i] = p
    return ''.join(plaintext)

class DecryptionReceiver:
    def __init__(self, master):
        self.master = master
        master.title("Decryption Receiver")
        
        # GUI layout
        self.port_label = ttk.Label(master, text="Listen Port:")
        self.port_label.grid(row=0, column=0, sticky=tk.W)
        self.port_entry = ttk.Entry(master)
        self.port_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
        self.port_entry.insert(0, "5000")  # Default port
        
        self.start_btn = ttk.Button(master, text="Start Listening", command=self.start_listening)
        self.start_btn.grid(row=1, column=1, padx=5, pady=5)
        
        self.output_label = ttk.Label(master, text="Received & Decrypted Message:")
        self.output_label.grid(row=2, column=0, sticky=tk.W)
        self.output_area = scrolledtext.ScrolledText(master, width=40, height=4)
        self.output_area.grid(row=2, column=1, columnspan=2, padx=5, pady=5)
        
        self.status_label = ttk.Label(master, text="Status:")
        self.status_label.grid(row=3, column=0, sticky=tk.W)
        self.status_area = scrolledtext.ScrolledText(master, width=40, height=2)
        self.status_area.grid(row=3, column=1, columnspan=2, padx=5, pady=5)
        
        self.server_socket = None
        self.is_listening = False

    def start_listening(self):
        if self.is_listening:
            self.stop_listening()
            return
        
        try:
            port = int(self.port_entry.get())
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(1)
            
            self.is_listening = True
            self.start_btn.config(text="Stop Listening")
            self.status_area.delete("1.0", tk.END)
            self.status_area.insert(tk.END, f"Listening on port {port}...")
            
            # Start listening in a separate thread
            threading.Thread(target=self.listen_for_messages, daemon=True).start()
            
        except Exception as e:
            self.status_area.delete("1.0", tk.END)
            self.status_area.insert(tk.END, f"Error starting server: {str(e)}")

    def stop_listening(self):
        if self.server_socket:
            self.server_socket.close()
        self.is_listening = False
        self.start_btn.config(text="Start Listening")
        self.status_area.delete("1.0", tk.END)
        self.status_area.insert(tk.END, "Server stopped")

    def listen_for_messages(self):
        while self.is_listening:
            try:
                client_socket, address = self.server_socket.accept()
                with client_socket:
                    data = client_socket.recv(4096).decode('utf-8')
                    if data:
                        self.process_received_data(data)
            except Exception as e:
                if self.is_listening:  # Only show error if we're still supposed to be listening
                    self.status_area.delete("1.0", tk.END)
                    self.status_area.insert(tk.END, f"Error receiving message: {str(e)}")

    def process_received_data(self, data):
        try:
            # Parse received data
            received_data = json.loads(data)
            
            # Extract data
            encrypted_text = received_data['encrypted_text']
            caesar_shift = received_data['caesar_shift']
            autokey_keyword = received_data['autokey_keyword']
            rsa_e = received_data['rsa_e']
            rsa_d = received_data['rsa_d']
            rsa_n = received_data['rsa_n']
            
            # Reconstruct RSA key
            rsa_key = RSA.construct((rsa_n, rsa_e, rsa_d))
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            
            # Decrypt chunks
            encrypted_chunks = encrypted_text.split(",")
            decrypted_bytes = bytearray()
            
            for chunk in encrypted_chunks:
                decoded_chunk = base64.b64decode(chunk)
                decrypted_chunk = cipher_rsa.decrypt(decoded_chunk)
                decrypted_bytes.extend(decrypted_chunk)
            
            # Decode and decrypt Autokey + Caesar
            autokey_ct = decrypted_bytes.decode('utf-8')
            caesar_pt = autokey_decrypt(autokey_ct, autokey_keyword)
            plaintext = caesar_decrypt(caesar_pt, caesar_shift)
            
            # Update GUI
            self.output_area.delete("1.0", tk.END)
            self.output_area.insert(tk.END, plaintext)
            self.status_area.delete("1.0", tk.END)
            self.status_area.insert(tk.END, "Message received and decrypted successfully!")
            
        except Exception as e:
            self.status_area.delete("1.0", tk.END)
            self.status_area.insert(tk.END, f"Error processing message: {str(e)}")

def main():
    root = tk.Tk()
    app = DecryptionReceiver(root)
    root.mainloop()

if __name__ == "__main__":
    main() 