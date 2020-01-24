from ...common import rsa
import unittest
from os import path, remove
from Crypto.PublicKey import RSA

PUB_KEY_FILE = "/tmp/key_file.pub"
PRIV_KEY_FILE = "/tmp/key_file.priv"

class RsaTest(unittest.TestCase):

    def setUp(self):
        """Initiate keys."""
        rsa.generate_keys(PUB_KEY_FILE, PRIV_KEY_FILE)

    def test_pub_key_format(self):
        """verify public key format"""
        assert path.exists(PUB_KEY_FILE) == 1

        file = open(PUB_KEY_FILE, "r")
        lines = file.readlines()
        file.close()

        assert "-----BEGIN PUBLIC KEY-----" in lines[0]
        assert "-----END PUBLIC KEY-----" in lines[-1]

    def test_priv_key_format(self):
        """verify private key format"""
        assert path.exists(PRIV_KEY_FILE) == 1

        file = open(PRIV_KEY_FILE, "r")
        lines = file.readlines()
        file.close()

        assert "-----BEGIN RSA PRIVATE KEY-----" in lines[0]
        assert "-----END RSA PRIVATE KEY-----" in lines[-1]


    def test_load_public_key(self):
        """test load"""
        key = rsa.load_key(PUB_KEY_FILE)
        assert type(key) is RSA._RSAobj
        key = rsa.load_key(PRIV_KEY_FILE)
        assert type(key) is RSA._RSAobj

    def test_encrypt_decrypt(self):
        """test encryption and decryption"""
        pub_key = rsa.load_key(PUB_KEY_FILE)
        priv_key = rsa.load_key(PRIV_KEY_FILE)
        message = b"Hello this is a test"
        encrypted_message = rsa.encrypt_public_key(message, pub_key)
        decrypted_message = rsa.decrypt_private_key(encrypted_message, priv_key)
        assert decrypted_message == message

    def test_sign_verify(self):
        """test sign and verify_sign"""
        pub_key = rsa.load_key(PUB_KEY_FILE)
        priv_key = rsa.load_key(PRIV_KEY_FILE)
        message = b"Hello this is a test"
        signed_message = rsa.sign(priv_key, message)
        assert rsa.verify_sign(pub_key, signed_message, message)

    def setDown(self):
        """remove temporary files."""
        remove(PUB_KEY_FILE)
        remove(PRIV_KEY_FILE)
