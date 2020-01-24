from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import base64

__author__ = "Louis Aussedat"
__copyright__ = "Copyright (c) 2019 Louis Aussedat"
__license__ = "GPLv3"

def generate_keys(pub_key_file, priv_key_file):
    """generate two keys, public and private, and
    store them in files"""
    modulus_length = 2048
    key = RSA.generate(modulus_length)
    pub_key = key.publickey()

    f = open(priv_key_file, "w")
    f.write(key.exportKey().decode())
    f.close()

    f = open(pub_key_file, "w")
    f.write(pub_key.exportKey().decode())
    f.close()

def load_key(key_file):
    """load key from file"""
    f = open(key_file, "r")
    key = f.read()
    f.close()
    key = RSA.importKey(key.encode())
    return key

def encrypt_public_key(a_message, pub_key):
    """encrypt a message with public key"""
    encryptor = PKCS1_OAEP.new(pub_key)
    encrypted_msg = encryptor.encrypt(a_message)
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    return encoded_encrypted_msg

def decrypt_private_key(encoded_encrypted_msg, private_key):
    """decrypt encoded_encrypted_msg with private_key"""
    encryptor = PKCS1_OAEP.new(private_key)
    decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
    decoded_decrypted_msg = encryptor.decrypt(decoded_encrypted_msg)
    return decoded_decrypted_msg

def verify_sign(pub_key, signature, data):
    """Verifies with a public key from whom the data came that it was indeed
    signed by their private key"""
    signer = PKCS1_v1_5.new(pub_key)
    digest = SHA256.new()
    digest.update(data)
    if signer.verify(digest, signature):
        return True
    return False

def sign(priv_key, data):
    """Sign data with private key"""
    signer = PKCS1_v1_5.new(priv_key)
    digest = SHA256.new()
    digest.update(data)
    return signer.sign(digest)
