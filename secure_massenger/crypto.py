import hashlib
import os
import json
import logging
import secrets
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import HKDF
from typing import Tuple, Dict, List, Union
import base64

logger = logging.getLogger(__name__)


class PasswordHasher:
    SALT_SIZE = 16
    HASH_ITERATIONS = 150000

    @staticmethod
    def hash_password(password: str) -> Tuple[bytes, bytes]:
        salt = secrets.token_bytes(PasswordHasher.SALT_SIZE)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            PasswordHasher.HASH_ITERATIONS
        )
        return password_hash, salt

    @staticmethod
    def verify_password(password: str, password_hash: bytes, salt: bytes) -> bool:
        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            PasswordHasher.HASH_ITERATIONS
        )
        return secrets.compare_digest(new_hash, password_hash)


class RSAECCEncryptor:
    RSA_KEY_SIZE = 2048
    AES_KEY_SIZE = 32
    NONCE_SIZE = 12
    ECC_CURVE = 'secp256r1'

    def __init__(self):
        logger.info("Initialized RSAECCEncryptor with ECC support")

    def generate_keys(self) -> Tuple[Dict, Dict]:
        rsa_enc_key = RSA.generate(self.RSA_KEY_SIZE)
        rsa_sign_key = RSA.generate(self.RSA_KEY_SIZE)
        ecc_key = ECC.generate(curve=self.ECC_CURVE)

        return {
            "rsa_public": rsa_enc_key.publickey().export_key().decode('utf-8'),
            "rsa_sign_public": rsa_sign_key.publickey().export_key().decode('utf-8'),
            "ecc_public": ecc_key.public_key().export_key(format='PEM')
        }, {
            "rsa_private": rsa_enc_key.export_key().decode('utf-8'),
            "rsa_sign_private": rsa_sign_key.export_key().decode('utf-8'),
            "ecc_private": ecc_key.export_key(format='PEM')
        }

    def encrypt_message(self, message: str, recipient_public_key: Dict, sender_private_key: Dict, sender_public_key: Dict) -> Dict:
        """
        Шифрование сообщение, используется гибридный подход:
            - ECDH для обмена ключами
            - AES-GCM для шифрования
            - RSA-PSS для подписи
        """
        try:

            ephemeral_key = ECC.generate(curve=self.ECC_CURVE)
            recipient_ecc_key = ECC.import_key(recipient_public_key["ecc_public"])


            shared_secret = ephemeral_key.d * recipient_ecc_key.pointQ
            shared_secret_bytes = shared_secret.x.to_bytes(32, 'big')


            aes_key = HKDF(
                shared_secret_bytes,
                self.AES_KEY_SIZE,
                salt=None,
                hashmod=SHA256,
                num_keys=1
            )


            nonce = get_random_bytes(self.NONCE_SIZE)
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))


            signer = pkcs1_15.new(RSA.import_key(sender_private_key["rsa_sign_private"]))
            h = SHA256.new(aes_key)
            signature = signer.sign(h)

            return {
                "version": 4,
                "ephemeral_ecc_public": ephemeral_key.public_key().export_key(format='PEM'),
                "nonce": nonce.hex(),
                "ciphertext": ciphertext.hex(),
                "tag": tag.hex(),
                "signature": base64.b64encode(signature).decode('utf-8'),
                "sender_sign_public": sender_public_key["rsa_sign_public"]
            }

        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}", exc_info=True)
            raise

    def decrypt_message(self, encrypted_data: Dict, private_key: Dict) -> str:

        try:
            version = encrypted_data.get("version", 2)

            if version == 4:

                ephemeral_ecc_key = ECC.import_key(encrypted_data["ephemeral_ecc_public"])
                recipient_ecc_key = ECC.import_key(private_key["ecc_private"])


                shared_secret = recipient_ecc_key.d * ephemeral_ecc_key.pointQ
                shared_secret_bytes = shared_secret.x.to_bytes(32, 'big')


                aes_key = HKDF(
                    shared_secret_bytes,
                    self.AES_KEY_SIZE,
                    salt=None,
                    hashmod=SHA256,
                    num_keys=1
                )


                sender_sign_public = RSA.import_key(encrypted_data["sender_sign_public"])
                verifier = pkcs1_15.new(sender_sign_public)
                h = SHA256.new(aes_key)
                signature = base64.b64decode(encrypted_data["signature"])
                verifier.verify(h, signature)


                cipher = AES.new(
                    aes_key,
                    AES.MODE_GCM,
                    nonce=bytes.fromhex(encrypted_data["nonce"])
                )
                decrypted = cipher.decrypt_and_verify(
                    bytes.fromhex(encrypted_data["ciphertext"]),
                    bytes.fromhex(encrypted_data["tag"])
                )
                return decrypted.decode('utf-8')

            else:

                required_keys = ["encrypted_aes_key", "nonce", "ciphertext", "tag", "signature"]
                if not all(k in encrypted_data for k in required_keys):
                    raise ValueError("Invalid encrypted data format")


                rsa_key = RSA.import_key(private_key["rsa_private"])
                rsa_cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
                encrypted_aes_key = base64.b64decode(encrypted_data["encrypted_aes_key"])
                aes_key = rsa_cipher.decrypt(encrypted_aes_key)


                sender_sign_public = RSA.import_key(encrypted_data.get("sender_sign_public", private_key["rsa_sign_private"]))
                verifier = pkcs1_15.new(sender_sign_public)
                h = SHA256.new(aes_key)
                signature = base64.b64decode(encrypted_data["signature"])
                verifier.verify(h, signature)


                cipher = AES.new(
                    aes_key,
                    AES.MODE_GCM,
                    nonce=bytes.fromhex(encrypted_data["nonce"])
                )
                decrypted = cipher.decrypt_and_verify(
                    bytes.fromhex(encrypted_data["ciphertext"]),
                    bytes.fromhex(encrypted_data["tag"])
                )
                return decrypted.decode('utf-8')

        except Exception as e:
            logger.error(f"Decryption error: {str(e)}", exc_info=True)
            raise
