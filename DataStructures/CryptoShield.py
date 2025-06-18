import os
import base64
import customtkinter
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hmac


customtkinter.set_appearance_mode("System")  
customtkinter.set_default_color_theme("blue")  

class CryptoShieldApp(customtkinter.CTk):
    def __init__(self):
        super().__init__()

       
        self.title("CryptoShield: Secure Messaging Tool")
        self.geometry("900x700") 
        self.grid_columnconfigure(0, weight=1) 
        self.grid_rowconfigure(0, weight=1)   

        self.status_label = customtkinter.CTkLabel(self, text="", text_color="green", wraplength=800)
        self.status_label.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="ew")

     
        self.private_key_pem_file = "private_key.pem"
        
        self.private_key = self._load_or_generate_rsa_key() 
        self.public_key = self.private_key.public_key() if self.private_key else None
        self.hmac_secret_key = os.urandom(32) 

       
        self.tabview = customtkinter.CTkTabview(self, width=850, height=600)
        self.tabview.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

        
        self.tab_aes = self.tabview.add("AES Encryption/Decryption")
        self.tab_hash = self.tabview.add("SHA-256 Hashing")
        self.tab_rsa = self.tabview.add("RSA Sign/Verify")
        self.tab_hmac = self.tabview.add("HMAC Authentication")

       
        for tab in [self.tab_aes, self.tab_hash, self.tab_rsa, self.tab_hmac]:
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_columnconfigure(1, weight=1) 
            tab.grid_rowconfigure(0, weight=0) 
            tab.grid_rowconfigure(1, weight=1) 

        self._create_aes_tab()
        self._create_hash_tab()
        self._create_rsa_tab()
        self._create_hmac_tab()


    # --- Helper to display messages ---
    def _show_status(self, message, is_error=False):
        """Displays a status message to the user."""
        self.status_label.configure(text=message, text_color="red" if is_error else "green")

    # --- RSA Key Management ---
    def _load_or_generate_rsa_key(self):
        """Loads an existing RSA private key or generates a new one."""
        private_key = self._load_rsa_private_key(self.private_key_pem_file)
        if private_key is None:
            self._show_status(f"Private key file '{self.private_key_pem_file}' not found. Generating a new one...", is_error=False)
            private_key, _ = self._generate_rsa_key_pair()
            self._save_rsa_private_key(private_key, self.private_key_pem_file)
            self._show_status(f"New private key generated and saved to {self.private_key_pem_file}", is_error=False)
        else:
            self._show_status(f"Private key loaded from {self.private_key_pem_file}", is_error=False)
        return private_key

    # --- Cryptography Functions (Copied from original code, prefixed with _) ---
    def _generate_rsa_key_pair(self):
        """Generates a new RSA private and public key pair (2048-bit)."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def _save_rsa_private_key(self, private_key, filename="private_key.pem"):
        """Saves the RSA private key to a file in PEM format."""
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(filename, "wb") as f:
            f.write(pem)

    def _load_rsa_private_key(self, filename="private_key.pem"):
        """Loads the RSA private key from a file."""
        try:
            with open(filename, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            return private_key
        except FileNotFoundError:
            return None
        except Exception as e:
            self._show_status(f"Error loading private key: {e}. Please ensure the file is valid.", is_error=True)
            return None

    def _derive_aes_key_from_password(self, password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        """Derives an AES key from a password using PBKDF2HMAC."""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        return key, salt

    def _aes_encrypt(self, plaintext: str, key: bytes) -> tuple[bytes, bytes]:
        """Encrypts plaintext using AES in CBC mode with PKCS7 padding."""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, iv

    def _aes_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> str:
        """Decrypts ciphertext using AES in CBC mode, removing PKCS7 padding."""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        return plaintext.decode('utf-8')

    def _sha256_hash(self, data: str) -> str:
        """Computes the SHA-256 hash of the given data."""
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data.encode('utf-8'))
        return digest.finalize().hex()

    def _rsa_sign(self, private_key: rsa.RSAPrivateKey, message: str) -> bytes:
        """Digitally signs a message using RSA private key and SHA-256 with PSS padding."""
        signature = private_key.sign(
            message.encode('utf-8'),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def _rsa_verify_signature(self, public_key: rsa.RSAPublicKey, message: str, signature: bytes) -> bool:
        """Verifies an RSA digital signature using public key and SHA-256 with PSS padding."""
        try:
            public_key.verify(
                signature,
                message.encode('utf-8'),
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def _hmac_generate(self, key: bytes, message: str) -> bytes:
        """Generates an HMAC for a message using SHA-256."""
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message.encode('utf-8'))
        return h.finalize()

    def _hmac_verify(self, key: bytes, message: str, tag: bytes) -> bool:
        """Verifies an HMAC tag for a message using SHA-256."""
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message.encode('utf-8'))
        try:
            h.verify(tag)
            return True
        except Exception:
            return False

    # --- AES Tab UI and Logic ---
    def _create_aes_tab(self):
        # Frame for encryption inputs and outputs
        encrypt_frame = customtkinter.CTkFrame(self.tab_aes)
        encrypt_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        encrypt_frame.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(encrypt_frame, text="Encrypt Message").pack(pady=5)
        self.aes_encrypt_message_entry = customtkinter.CTkTextbox(encrypt_frame, height=80, width=350)
        self.aes_encrypt_message_entry.pack(pady=5, padx=5, fill="x")
        self.aes_encrypt_message_entry.insert("0.0", "Enter your secret message here.")

        customtkinter.CTkLabel(encrypt_frame, text="Password").pack(pady=5)
        self.aes_encrypt_password_entry = customtkinter.CTkEntry(encrypt_frame, show="*") # Show stars for password
        self.aes_encrypt_password_entry.pack(pady=5, padx=5, fill="x")

        encrypt_button = customtkinter.CTkButton(encrypt_frame, text="Encrypt", command=self._perform_aes_encrypt)
        encrypt_button.pack(pady=10)

        customtkinter.CTkLabel(encrypt_frame, text="Encryption Results:").pack(pady=5)
        customtkinter.CTkLabel(encrypt_frame, text="Salt (Base64):").pack(pady=2, anchor="w", padx=5)
        self.aes_encrypt_salt_output = customtkinter.CTkTextbox(encrypt_frame, height=40, width=350)
        self.aes_encrypt_salt_output.pack(pady=2, padx=5, fill="x")
        customtkinter.CTkLabel(encrypt_frame, text="IV (Base64):").pack(pady=2, anchor="w", padx=5)
        self.aes_encrypt_iv_output = customtkinter.CTkTextbox(encrypt_frame, height=40, width=350)
        self.aes_encrypt_iv_output.pack(pady=2, padx=5, fill="x")
        customtkinter.CTkLabel(encrypt_frame, text="Ciphertext (Base64):").pack(pady=2, anchor="w", padx=5)
        self.aes_encrypt_ciphertext_output = customtkinter.CTkTextbox(encrypt_frame, height=80, width=350)
        self.aes_encrypt_ciphertext_output.pack(pady=2, padx=5, fill="x")

        # Frame for decryption inputs and outputs
        decrypt_frame = customtkinter.CTkFrame(self.tab_aes)
        decrypt_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        decrypt_frame.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(decrypt_frame, text="Decrypt Message").pack(pady=5)
        customtkinter.CTkLabel(decrypt_frame, text="Ciphertext (Base64):").pack(pady=2, anchor="w", padx=5)
        self.aes_decrypt_ciphertext_entry = customtkinter.CTkTextbox(decrypt_frame, height=80, width=350)
        self.aes_decrypt_ciphertext_entry.pack(pady=2, padx=5, fill="x")

        customtkinter.CTkLabel(decrypt_frame, text="IV (Base64):").pack(pady=2, anchor="w", padx=5)
        self.aes_decrypt_iv_entry = customtkinter.CTkEntry(decrypt_frame)
        self.aes_decrypt_iv_entry.pack(pady=2, padx=5, fill="x")

        customtkinter.CTkLabel(decrypt_frame, text="Salt (Base64):").pack(pady=2, anchor="w", padx=5)
        self.aes_decrypt_salt_entry = customtkinter.CTkEntry(decrypt_frame)
        self.aes_decrypt_salt_entry.pack(pady=2, padx=5, fill="x")

        customtkinter.CTkLabel(decrypt_frame, text="Password:").pack(pady=5)
        self.aes_decrypt_password_entry = customtkinter.CTkEntry(decrypt_frame, show="*")
        self.aes_decrypt_password_entry.pack(pady=5, padx=5, fill="x")

        decrypt_button = customtkinter.CTkButton(decrypt_frame, text="Decrypt", command=self._perform_aes_decrypt)
        decrypt_button.pack(pady=10)

        customtkinter.CTkLabel(decrypt_frame, text="Decrypted Message:").pack(pady=5)
        self.aes_decrypt_plaintext_output = customtkinter.CTkTextbox(decrypt_frame, height=80, width=350)
        self.aes_decrypt_plaintext_output.pack(pady=5, padx=5, fill="x")

    def _perform_aes_encrypt(self):
        message = self.aes_encrypt_message_entry.get("0.0", "end").strip()
        password = self.aes_encrypt_password_entry.get().strip()

        if not message or not password:
            self._show_status("Message and password are required for encryption.", is_error=True)
            return

        try:
            aes_key, salt = self._derive_aes_key_from_password(password)
            ciphertext, iv = self._aes_encrypt(message, aes_key)

            self.aes_encrypt_salt_output.delete("0.0", "end")
            self.aes_encrypt_salt_output.insert("0.0", base64.b64encode(salt).decode('utf-8'))
            self.aes_encrypt_iv_output.delete("0.0", "end")
            self.aes_encrypt_iv_output.insert("0.0", base64.b64encode(iv).decode('utf-8'))
            self.aes_encrypt_ciphertext_output.delete("0.0", "end")
            self.aes_encrypt_ciphertext_output.insert("0.0", base64.b64encode(ciphertext).decode('utf-8'))
            self._show_status("Message encrypted successfully!", is_error=False)
        except Exception as e:
            self._show_status(f"Encryption error: {e}", is_error=True)

    def _perform_aes_decrypt(self):
        ciphertext_b64 = self.aes_decrypt_ciphertext_entry.get("0.0", "end").strip()
        iv_b64 = self.aes_decrypt_iv_entry.get().strip()
        salt_b64 = self.aes_decrypt_salt_entry.get().strip()
        password = self.aes_decrypt_password_entry.get().strip()

        if not all([ciphertext_b64, iv_b64, salt_b64, password]):
            self._show_status("All fields are required for decryption.", is_error=True)
            return

        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            iv = base64.b64decode(iv_b64)
            salt = base64.b64decode(salt_b64)

            aes_key, _ = self._derive_aes_key_from_password(password, salt)
            plaintext = self._aes_decrypt(ciphertext, aes_key, iv)

            self.aes_decrypt_plaintext_output.delete("0.0", "end")
            self.aes_decrypt_plaintext_output.insert("0.0", plaintext)
            self._show_status("Message decrypted successfully!", is_error=False)
        except Exception as e:
            self._show_status(f"Decryption error. Please check your inputs. Details: {e}", is_error=True)

    # --- Hash Tab UI and Logic ---
    def _create_hash_tab(self):
        customtkinter.CTkLabel(self.tab_hash, text="Message to Hash").pack(pady=10)
        self.hash_message_entry = customtkinter.CTkTextbox(self.tab_hash, height=100)
        self.hash_message_entry.pack(pady=5, padx=10, fill="both", expand=True)
        self.hash_message_entry.insert("0.0", "Type your message here to get its SHA-256 hash.")

        hash_button = customtkinter.CTkButton(self.tab_hash, text="Compute SHA-256 Hash", command=self._perform_sha256_hash)
        hash_button.pack(pady=10)

        customtkinter.CTkLabel(self.tab_hash, text="SHA-256 Hash Result:").pack(pady=10)
        self.hash_output = customtkinter.CTkTextbox(self.tab_hash, height=50)
        self.hash_output.pack(pady=5, padx=10, fill="x")

    def _perform_sha256_hash(self):
        message = self.hash_message_entry.get("0.0", "end").strip()
        if not message:
            self._show_status("Please enter a message to hash.", is_error=True)
            return

        hashed_message = self._sha256_hash(message)
        self.hash_output.delete("0.0", "end")
        self.hash_output.insert("0.0", hashed_message)
        self._show_status("Message hashed successfully!", is_error=False)

    # --- RSA Tab UI and Logic ---
    def _create_rsa_tab(self):
        # Frame for RSA Signing
        sign_frame = customtkinter.CTkFrame(self.tab_rsa)
        sign_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        sign_frame.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(sign_frame, text="Sign Message").pack(pady=5)
        self.rsa_sign_message_entry = customtkinter.CTkTextbox(sign_frame, height=80)
        self.rsa_sign_message_entry.pack(pady=5, padx=5, fill="x")
        self.rsa_sign_message_entry.insert("0.0", "Enter the message you want to digitally sign.")

        sign_button = customtkinter.CTkButton(sign_frame, text="Sign Message", command=self._perform_rsa_sign)
        sign_button.pack(pady=10)

        customtkinter.CTkLabel(sign_frame, text="Signature (Base64):").pack(pady=5, anchor="w", padx=5)
        self.rsa_signature_output = customtkinter.CTkTextbox(sign_frame, height=80)
        self.rsa_signature_output.pack(pady=5, padx=5, fill="x")

        customtkinter.CTkLabel(sign_frame, text="Your RSA Public Key (PEM):").pack(pady=5, anchor="w", padx=5)
        self.rsa_public_key_output = customtkinter.CTkTextbox(sign_frame, height=120)
        self.rsa_public_key_output.pack(pady=5, padx=5, fill="both", expand=True)

        if self.public_key:
            public_key_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            self.rsa_public_key_output.insert("0.0", public_key_pem)
        else:
            self.rsa_public_key_output.insert("0.0", "RSA Public Key not available (private key not loaded).")
            sign_button.configure(state="disabled") # Disable if no key

        # Frame for RSA Verification
        verify_frame = customtkinter.CTkFrame(self.tab_rsa)
        verify_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        verify_frame.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(verify_frame, text="Verify Signature").pack(pady=5)
        customtkinter.CTkLabel(verify_frame, text="Original Message:").pack(pady=2, anchor="w", padx=5)
        self.rsa_verify_message_entry = customtkinter.CTkTextbox(verify_frame, height=80)
        self.rsa_verify_message_entry.pack(pady=2, padx=5, fill="x")

        customtkinter.CTkLabel(verify_frame, text="Signature (Base64):").pack(pady=2, anchor="w", padx=5)
        self.rsa_verify_signature_entry = customtkinter.CTkTextbox(verify_frame, height=80)
        self.rsa_verify_signature_entry.pack(pady=2, padx=5, fill="x")

        customtkinter.CTkLabel(verify_frame, text="Public Key (PEM):").pack(pady=2, anchor="w", padx=5)
        self.rsa_verify_public_key_entry = customtkinter.CTkTextbox(verify_frame, height=120)
        self.rsa_verify_public_key_entry.pack(pady=2, padx=5, fill="both", expand=True)

        verify_button = customtkinter.CTkButton(verify_frame, text="Verify Signature", command=self._perform_rsa_verify)
        verify_button.pack(pady=10)

        customtkinter.CTkLabel(verify_frame, text="Verification Result:").pack(pady=5)
        self.rsa_verify_result_output = customtkinter.CTkLabel(verify_frame, text="", font=customtkinter.CTkFont(size=14, weight="bold"))
        self.rsa_verify_result_output.pack(pady=5)

    def _perform_rsa_sign(self):
        if not self.private_key:
            self._show_status("RSA Private Key not loaded. Cannot sign message.", is_error=True)
            return

        message = self.rsa_sign_message_entry.get("0.0", "end").strip()
        if not message:
            self._show_status("Please enter a message to sign.", is_error=True)
            return

        try:
            signature = self._rsa_sign(self.private_key, message)
            self.rsa_signature_output.delete("0.0", "end")
            self.rsa_signature_output.insert("0.0", base64.b64encode(signature).decode('utf-8'))
            self._show_status("Message signed successfully!", is_error=False)
        except Exception as e:
            self._show_status(f"Error signing message: {e}", is_error=True)

    def _perform_rsa_verify(self):
        original_message = self.rsa_verify_message_entry.get("0.0", "end").strip()
        signature_b64 = self.rsa_verify_signature_entry.get("0.0", "end").strip()
        public_key_pem_str = self.rsa_verify_public_key_entry.get("0.0", "end").strip()

        if not all([original_message, signature_b64, public_key_pem_str]):
            self._show_status("All fields are required for signature verification.", is_error=True)
            return

        try:
            signature = base64.b64decode(signature_b64)
            public_key = serialization.load_pem_public_key(
                public_key_pem_str.encode('utf-8'),
                backend=default_backend()
            )

            if self._rsa_verify_signature(public_key, original_message, signature):
                self.rsa_verify_result_output.configure(text="VERIFIED! Message integrity and sender authenticity confirmed.", text_color="green")
                self._show_status("Signature verified successfully!", is_error=False)
            else:
                self.rsa_verify_result_output.configure(text="FAILED! Message altered or invalid signature.", text_color="red")
                self._show_status("Signature verification failed.", is_error=True)
        except Exception as e:
            self._show_status(f"Error during signature verification. Details: {e}", is_error=True)
            self.rsa_verify_result_output.configure(text="ERROR during verification.", text_color="red")

    # --- HMAC Tab UI and Logic ---
    def _create_hmac_tab(self):
        # Frame for HMAC Generation
        generate_frame = customtkinter.CTkFrame(self.tab_hmac)
        generate_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        generate_frame.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(generate_frame, text="Generate HMAC").pack(pady=5)
        self.hmac_message_entry = customtkinter.CTkTextbox(generate_frame, height=80)
        self.hmac_message_entry.pack(pady=5, padx=5, fill="x")
        self.hmac_message_entry.insert("0.0", "Enter the message to generate an HMAC for.")

        generate_hmac_button = customtkinter.CTkButton(generate_frame, text="Generate HMAC", command=self._perform_hmac_generate)
        generate_hmac_button.pack(pady=10)

        customtkinter.CTkLabel(generate_frame, text="HMAC Tag (Base64):").pack(pady=5, anchor="w", padx=5)
        self.hmac_tag_output = customtkinter.CTkTextbox(generate_frame, height=80)
        self.hmac_tag_output.pack(pady=5, padx=5, fill="x")
        customtkinter.CTkLabel(generate_frame, text=f"HMAC Secret Key (This is random for this session):", wraplength=300).pack(pady=5, anchor="w", padx=5)
        self.hmac_secret_key_display = customtkinter.CTkTextbox(generate_frame, height=40)
        self.hmac_secret_key_display.insert("0.0", base64.b64encode(self.hmac_secret_key).decode('utf-8'))
        self.hmac_secret_key_display.configure(state="disabled") # Disable editing
        self.hmac_secret_key_display.pack(pady=5, padx=5, fill="x")


        # Frame for HMAC Verification
        verify_frame = customtkinter.CTkFrame(self.tab_hmac)
        verify_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        verify_frame.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(verify_frame, text="Verify HMAC").pack(pady=5)
        customtkinter.CTkLabel(verify_frame, text="Received Message:").pack(pady=2, anchor="w", padx=5)
        self.hmac_verify_message_entry = customtkinter.CTkTextbox(verify_frame, height=80)
        self.hmac_verify_message_entry.pack(pady=2, padx=5, fill="x")

        customtkinter.CTkLabel(verify_frame, text="Received HMAC Tag (Base64):").pack(pady=2, anchor="w", padx=5)
        self.hmac_verify_tag_entry = customtkinter.CTkTextbox(verify_frame, height=80)
        self.hmac_verify_tag_entry.pack(pady=2, padx=5, fill="x")
        
        customtkinter.CTkLabel(verify_frame, text=f"Shared HMAC Secret Key (Copy from left or from sender):", wraplength=300).pack(pady=5, anchor="w", padx=5)
        self.hmac_verify_secret_key_entry = customtkinter.CTkEntry(verify_frame)
        self.hmac_verify_secret_key_entry.pack(pady=5, padx=5, fill="x")
        self.hmac_verify_secret_key_entry.insert(0, base64.b64encode(self.hmac_secret_key).decode('utf-8')) # Pre-fill for testing

        verify_hmac_button = customtkinter.CTkButton(verify_frame, text="Verify HMAC", command=self._perform_hmac_verify)
        verify_hmac_button.pack(pady=10)

        customtkinter.CTkLabel(verify_frame, text="Verification Result:").pack(pady=5)
        self.hmac_verify_result_output = customtkinter.CTkLabel(verify_frame, text="", font=customtkinter.CTkFont(size=14, weight="bold"))
        self.hmac_verify_result_output.pack(pady=5)

    def _perform_hmac_generate(self):
        message = self.hmac_message_entry.get("0.0", "end").strip()
        if not message:
            self._show_status("Please enter a message to generate HMAC for.", is_error=True)
            return

        try:
            hmac_tag = self._hmac_generate(self.hmac_secret_key, message)
            self.hmac_tag_output.delete("0.0", "end")
            self.hmac_tag_output.insert("0.0", base64.b64encode(hmac_tag).decode('utf-8'))
            self._show_status("HMAC generated successfully!", is_error=False)
        except Exception as e:
            self._show_status(f"Error generating HMAC: {e}", is_error=True)

    def _perform_hmac_verify(self):
        received_message = self.hmac_verify_message_entry.get("0.0", "end").strip()
        hmac_tag_b64 = self.hmac_verify_tag_entry.get("0.0", "end").strip()
        shared_secret_key_b64 = self.hmac_verify_secret_key_entry.get().strip()


        if not all([received_message, hmac_tag_b64, shared_secret_key_b64]):
            self._show_status("All fields are required for HMAC verification.", is_error=True)
            return

        try:
            hmac_tag = base64.b64decode(hmac_tag_b64)
            shared_secret_key = base64.b64decode(shared_secret_key_b64)

            if self._hmac_verify(shared_secret_key, received_message, hmac_tag):
                self.hmac_verify_result_output.configure(text="VERIFIED! Message integrity and authenticity confirmed.", text_color="green")
                self._show_status("HMAC verified successfully!", is_error=False)
            else:
                self.hmac_verify_result_output.configure(text="FAILED! Message altered or invalid HMAC.", text_color="red")
                self._show_status("HMAC verification failed.", is_error=True)
        except Exception as e:
            self._show_status(f"Error during HMAC verification. Details: {e}", is_error=True)
            self.hmac_verify_result_output.configure(text="ERROR during verification.", text_color="red")


if __name__ == "__main__":
    app = CryptoShieldApp()
    app.mainloop()
