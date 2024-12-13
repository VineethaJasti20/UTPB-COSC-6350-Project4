import socket
import threading
import os
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

def log(message):
    print(f"[{datetime.now().isoformat()}] SERVER: {message}")

class WPA3ServerHandler:
    def __init__(self):
        # Generate ECDH key pair for the server
        self._server_private_key = ec.generate_private_key(ec.SECP384R1())
        self.server_public_key = self._server_private_key.public_key()

        self.a_nonce = os.urandom(32)
        self.s_nonce = None
        self.session_key = None

    def derive_session_key(self, client_pub_key, a_nonce, s_nonce):
        # ECDH shared secret
        shared_secret = self._server_private_key.exchange(ec.ECDH(), client_pub_key)

        # Use HKDF to derive the session key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=a_nonce + s_nonce
        )
        self.session_key = hkdf.derive(shared_secret)
        return self.session_key

    def encrypt_message(self, plaintext_msg):
        if self.session_key is None:
            raise ValueError("Session key not established")

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_msg.encode()) + encryptor.finalize()

        return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

    def decrypt_message(self, encrypted_msg):
        if self.session_key is None:
            raise ValueError("Session key not established")

        raw_data = base64.b64decode(encrypted_msg.encode())
        iv = raw_data[:16]
        tag = raw_data[16:32]
        ciphertext = raw_data[32:]

        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()


def handle_client(client_sock, client_addr, wpa3_server):
    try:
        log(f"Accepted connection from {client_addr}")

        # Step 1: Send ANonce and server public key
        srv_pub_bytes = wpa3_server.server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_sock.send(wpa3_server.a_nonce + srv_pub_bytes)
        log("Sent ANonce and server's public key to client.")

        # Step 2: Receive SNonce and client public key
        incoming_data = client_sock.recv(4096)
        wpa3_server.s_nonce = incoming_data[:32]
        cli_pub_key = serialization.load_pem_public_key(incoming_data[32:])
        log("Received SNonce and client's public key.")

        # Step 3: Derive the session key
        session_key = wpa3_server.derive_session_key(cli_pub_key, wpa3_server.a_nonce, wpa3_server.s_nonce)
        log(f"Session key established: {session_key.hex()}")

        # Step 4: Send an encrypted test message
        encrypted_test = wpa3_server.encrypt_message("Welcome to our secure WPA3 channel!")
        client_sock.send(encrypted_test.encode())
        log(f"Sent initial encrypted message: {encrypted_test}")

        # Receive encrypted response from client
        encrypted_reply = client_sock.recv(4096).decode()
        decrypted_reply = wpa3_server.decrypt_message(encrypted_reply)
        log(f"Received encrypted packet from client: {encrypted_reply}")
        log(f"Decrypted client's response: {decrypted_reply}")

        # Continuously exchange encrypted packets
        while True:
            enc_client_msg = client_sock.recv(4096).decode()
            if not enc_client_msg:
                break

            # Decrypt client's message
            dec_client_msg = wpa3_server.decrypt_message(enc_client_msg)
            log(f"Received encrypted packet: {enc_client_msg}")
            log(f"Decrypted client's message: {dec_client_msg}")

            # Send back encrypted response
            response_text = f"Server received: {dec_client_msg}"
            enc_server_response = wpa3_server.encrypt_message(response_text)
            client_sock.send(enc_server_response.encode())
            log(f"Sent encrypted reply: {enc_server_response}")
            log(f"Original response message: {response_text}")

    except Exception as e:
        log(f"Error handling client {client_addr}: {e}")
    finally:
        client_sock.close()
        log(f"Connection closed with {client_addr}")


def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(('0.0.0.0', 12345))
    server_sock.listen(5)
    log("WPA3 AP is now listening on 0.0.0.0:12345")

    while True:
        client_socket, client_address = server_sock.accept()
        wpa3_server = WPA3ServerHandler()
        thread = threading.Thread(target=handle_client, args=(client_socket, client_address, wpa3_server))
        thread.start()


if __name__ == "__main__":
    main()
