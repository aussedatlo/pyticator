import unittest
from os import path
from pyticator.rsa_crypt import generate_keys, load_public_key
from Crypto.PublicKey import RSA

PUB_KEY_FILE = "/tmp/key_file.pub"
PRIV_KEY_FILE = "/tmp/key_file.priv"
EMPTY_FILE = "/tmp/key_file.empty"
FALSE_FILE = "/tmp/key_file.false"

class RsaWrapperTest(unittest.TestCase):

    def setUp(self):
        """Initiate keys."""
        generate_keys(PUB_KEY_FILE, PRIV_KEY_FILE)
        file = open(FALSE_FILE, "w")
        file.write("123")
        file.close()
        file = open(EMPTY_FILE, "w")
        file.close()

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
        self.assertRaises(IndexError, load_public_key, EMPTY_FILE)
        self.assertRaises(ValueError, load_public_key, FALSE_FILE)

        key = load_public_key(PUB_KEY_FILE)
        assert type(key) is RSA._RSAobj

