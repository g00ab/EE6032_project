import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class Entity:
    def __init__(self):
        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()  # Extract public key

    def key_generation(self):
        """Export keys in PEM format"""
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # print("Private Key:\n", private_pem.decode())  # Save this securely
        print("Public Key:\n", public_pem.decode())    # Share this with sender
        return private_pem.decode(), public_pem.decode()
    
    def save_private_key(self, filename="private.pem"):
        with open(filename, "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b"mypassword"),
            ))

    def save_public_key(self, filename="public.pem"):
        with open(filename, "wb") as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))


class Actions:
    def __init__(self, entity):
        self.private_key = entity.private_key  # Get private key from Entity
        self.public_key = entity.public_key    # Get public key from Entity
        self.ciphertext = None  # Store encrypted message

    # def encrypt(self, message):
    #     """Encrypts a message using RSA public key"""
    #     self.ciphertext = self.public_key.encrypt(
    #         message,
    #         padding.OAEP(
    #             mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #             algorithm=hashes.SHA256(),
    #             label=None
    #         )
    #     )
    #     print("Encrypted Message:", self.ciphertext)
    #     return self.ciphertext
    
    def encrypt(self, message):
        """Encrypts a message and signs it using RSA"""
        signature = self.sign_message(message.decode())  # Sign the message

        # Combine the message and signature
        message_with_signature = message + b"||" + signature

        # Encrypt the combined message
        self.ciphertext = self.public_key.encrypt(
            message_with_signature,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Encrypted Message:", self.ciphertext)
        return self.ciphertext

    # def decrypt(self):
    #     """Decrypts the message using RSA private key"""
    #     if self.ciphertext is None:
    #         print("No message to decrypt!")
    #         return None

    #     plaintext = self.private_key.decrypt(
    #         self.ciphertext,
    #         padding.OAEP(
    #             mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #             algorithm=hashes.SHA256(),
    #             label=None
    #         )
    #     )
    #     print("Decrypted Message:", plaintext.decode())
    #     return plaintext
    
    def decrypt(self, encrypted_message):
        """Decrypts a message and verifies its signature"""
        plaintext = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Split message and signature
        message, signature = plaintext.rsplit(b'||', 1)

        # Verify the signature
        if self.verify_signature(message.decode(), signature):
            print("Decrypted and Verified Message:", message.decode())
            return message
        else:
            print("Message Integrity Compromised!")
            return None
    

    def hashing(self, message):
        input_hash = hashlib.sha256(message.encode()).hexdigest()
        print(f'input hash: {input_hash}')
        return (input_hash,message)
    
    def compare_hashing(self,stored_hash,message):
        input_hash = hashlib.sha256(message.encode()).hexdigest()
        if input_hash == stored_hash:
            print("Hash Match!")
            return True
        else:
            print("Wrong Hash!")
            return False


    def sign_message(self, message):
        signature = self.private_key.sign(
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, message, signature):
        try:
            self.public_key.verify(
                signature,
                message.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print("✅ Signature is valid!")
            return True
        except:
            print("❌ Signature is INVALID!")
            return False


def main():
    # **Testing**
    entity = Entity()  # Create entity with keys
    entity.key_generation()  # Generate and display keys

    actions = Actions(entity)  # Pass entity to actions
    cipher_text = actions.encrypt(b"Confidential message")  # Encrypt a message
    actions.decrypt()  # Decrypt the message


if __name__ == '__main__':
    main()