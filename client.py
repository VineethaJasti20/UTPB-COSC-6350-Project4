import socket
import os
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

def log(message):
    print(f"[{datetime.now().isoformat()}] CLIENT: {message}")

class WPA3ClientHandler:
    def __init__(self):
        # Generate ECDH key pair for the client
        self._client_private_key = ec.generate_private_key(ec.SECP384R1())
        self._client_public_key = self._client_private_key.public_key()

        # Nonces and session key placeholders
        self.a_nonce = None
        self.s_nonce = os.urandom(32)
        self.session_key = None

    def derive_session_key(self, ap_public_key, anonce, snonce):
        # Perform ECDH to get a shared secret
        shared_secret = self._client_private_key.exchange(ec.ECDH(), ap_public_key)

        # Derive the session key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=anonce + snonce
        )
        self.session_key = hkdf.derive(shared_secret)
        return self.session_key

    def encrypt_message(self, plaintext_msg):
        if self.session_key is None:
            raise ValueError("Session key not established before encryption.")

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_msg.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

    def decrypt_message(self, encrypted_msg):
        if self.session_key is None:
            raise ValueError("Session key not established before decryption.")

        raw_data = base64.b64decode(encrypted_msg.encode())
        iv = raw_data[:16]
        tag = raw_data[16:32]
        ciphertext = raw_data[32:]

        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()


def main():
    # Connect to the AP
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(('localhost', 12345))
    log("Connected to the Access Point.")

    wpa3_client = WPA3ClientHandler()

    # Step 1: Receive ANonce and AP public key
    received_data = client_sock.recv(4096)
    wpa3_client.a_nonce = received_data[:32]
    ap_pub_key = serialization.load_pem_public_key(received_data[32:])
    log("Received ANonce and AP's public key.")

    # Step 2: Send SNonce and client's public key
    client_public_bytes = wpa3_client._client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_sock.send(wpa3_client.s_nonce + client_public_bytes)
    log("Sent SNonce and client's public key to AP.")

    # Step 3: Derive session key
    session_key = wpa3_client.derive_session_key(ap_pub_key, wpa3_client.a_nonce, wpa3_client.s_nonce)
    log(f"Session key derived: {session_key.hex()}")

    # Step 4: Receive encrypted initial message from AP
    encrypted_test = client_sock.recv(4096).decode()
    decrypted_test = wpa3_client.decrypt_message(encrypted_test)
    log(f"Received encrypted packet: {encrypted_test}")
    log(f"Decrypted initial message: {decrypted_test}")

    # Send encrypted acknowledgment to AP
    client_response = "Client acknowledges secure communication!"
    enc_response = wpa3_client.encrypt_message(client_response)
    client_sock.send(enc_response.encode())
    log(f"Sent encrypted acknowledgment: {enc_response}")

    # Further communication packets
    packets_to_send = [
        "Hello from the client side.",
        "Sending a second test message.",
        "This should be fully encrypted."
    ]

    for message in packets_to_send:
        # Encrypt and send message
        enc_msg = wpa3_client.encrypt_message(message)
        client_sock.send(enc_msg.encode())
        log(f"Sent encrypted packet: {enc_msg}")
        log(f"Original client message: {message}")

        # Receive and decrypt response from server
        enc_server_reply = client_sock.recv(4096).decode()
        dec_server_reply = wpa3_client.decrypt_message(enc_server_reply)
        log(f"Received encrypted response: {enc_server_reply}")
        log(f"Decrypted server response: {dec_server_reply}")

    client_sock.close()
    log("Connection closed.")


if __name__ == "__main__":
    main()
