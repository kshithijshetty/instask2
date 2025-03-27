from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
from cryptography.hazmat.primitives.padding import PKCS7

class KeyMgmtSys:
    def __init__(self):
        self.sym_keys = {}
        self.asym_keys = {}

    def gen_aes_key(self, key_id):
        key = os.urandom(32)
        self.sym_keys[key_id] = key
        return base64.b64encode(key).decode()

    def gen_rsa_pair(self, user_id):
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_key = priv_key.public_key()
        self.asym_keys[user_id] = (priv_key, pub_key)
        return pub_key

    def aes_encrypt(self, key_id, text):
        key = self.sym_keys[key_id]
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(text.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()

    def aes_decrypt(self, key_id, enc_data):
        key = self.sym_keys[key_id]
        enc_data = base64.b64decode(enc_data)
        iv, ciphertext = enc_data[:16], enc_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        text = unpadder.update(decrypted_padded) + unpadder.finalize()
        return text.decode()

    def rsa_encrypt(self, user_id, text):
        _, pub_key = self.asym_keys[user_id]
        enc_data = pub_key.encrypt(text.encode(), padding.PKCS1v15())
        return base64.b64encode(enc_data).decode()

    def rsa_decrypt(self, user_id, enc_data):
        priv_key, _ = self.asym_keys[user_id]
        enc_data = base64.b64decode(enc_data)
        decrypted = priv_key.decrypt(enc_data, padding.PKCS1v15())
        return decrypted.decode()

    def dh_keygen(self):
        params = generate_parameters(generator=2, key_size=2048)
        priv_key = params.generate_private_key()
        pub_key = priv_key.public_key()
        return priv_key, pub_key

    def revoke_key(self, key_id):
        if key_id in self.sym_keys:
            del self.sym_keys[key_id]
        elif key_id in self.asym_keys:
            del self.asym_keys[key_id]
        return "Key Revoked"

kms = KeyMgmtSys()

aes_id = "user1"
kms.gen_aes_key(aes_id)
aes_enc = kms.aes_encrypt(aes_id, "SecretData")
aes_dec = kms.aes_decrypt(aes_id, aes_enc)
print("AES Decoded:", aes_dec)

rsa_user = "userRSA"
kms.gen_rsa_pair(rsa_user)
rsa_enc = kms.rsa_encrypt(rsa_user, "Confidential")
rsa_dec = kms.rsa_decrypt(rsa_user, rsa_enc)
print("RSA Decoded:", rsa_dec)

dh_priv, dh_pub = kms.dh_keygen()
print("DH Public Key:", dh_pub)

revocation_res = kms.revoke_key(aes_id)
print("Revocation Status:", revocation_res)

try:
    kms.aes_decrypt(aes_id, aes_enc)
except Exception as e:
    print("Expected Error:", e)
