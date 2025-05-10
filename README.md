# Layered Encryption System

## Overview
This project implements a secure, multi-layered encryption system combining classical and modern cryptographic techniques: Caesar Cipher, Autokey Cipher, and RSA. It features a client-server architecture for secure communication over a network, with layered encryption and decryption for enhanced security.

## Features
- **Layered Encryption:** Combines Caesar, Autokey, and RSA ciphers for strong security
- **Client-Server Communication:** Secure message exchange over TCP/IP
- **Manual or Automatic Key Management:** Supports both user-provided and auto-generated RSA keys
- **User-Friendly Interface:** Simple to use for both sender and receiver
- **Performance and Security Analysis:** Includes cryptanalysis and performance metrics
- **Professional Report and Presentation:** LaTeX report and PowerPoint generator included

## Project Structure
```
├── encrypt_sender.py         # Sender/client application
├── decrypt_receiver.py       # Receiver/server application
├── report.tex                # LaTeX report (with diagrams, theory, and results)
├── presentation.pptx         # PowerPoint presentation
├── requirements.txt          # Python dependencies
├── README.md                 # This file
```

## Requirements
- Python 3.7+


Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Usage
### 1. Run the Sender and Receiver
- Start the receiver/server:
  ```bash
  python decrypt_receiver.py
  ```
- Start the sender/client:
  ```bash
  python encrypt_sender.py
  ```
- Follow the prompts to input messages and keys.


## Authors
- **Ammar Elsayed** (ID: 222321)
- **Ahmed Walid** (ID: 222332)

**Course:** Computer Security, MSA University  
**Instructor:** Dr. Ali Somaie

## License
This project is for educational purposes. Please cite the authors if you use or adapt this work.
