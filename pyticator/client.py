#!/usr/bin/env python3

from pathlib import Path
import logging
import socket
import argparse
import hashlib
import sys
import pyticator.rsa_crypt as rsa_crypt
import pyticator.exceptions as exceptions

__author__ = "Louis Aussedat"
__copyright__ = "Copyright (c) 2019 Louis Aussedat"
__license__ = "GPLv3"

def check_key(key_file):
    logging.debug(" checking key: %s" % key_file)
    key_file = Path(key_file)
    if not key_file.is_file():
        logging.error(" file not found")
        raise exceptions.KeyNotFound("key file %s not found" % key_file)

def main(argv):
    # parse arguments
    parser = argparse.ArgumentParser(argv)
    parser.add_argument("host", help="host")
    parser.add_argument("--priv", help="private key file", default="/etc/pyticator/id_rsa")
    parser.add_argument("--pub", help="public key file", default="/etc/pyticator/id_rsa.pub")
    parser.add_argument("-p", "--port", help="port", type=int, default="8852")
    parser.add_argument("-d", "--debug", help="debug mode",
        action="store_true")
    parser.add_argument("-g", "--generate", help="generate keys",
        action="store_true")
    args = parser.parse_args()

    # Logger mode
    if args.debug:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.INFO

    logging.basicConfig(level=logging_level,
        format="%(asctime)s:%(levelname)s:%(message)s",
        datefmt="%H:%M:%S")

    # generate keys
    if args.generate:
        rsa_crypt.generate_keys(pub_key_file=args.pub, priv_key_file=args.priv)
        sys.exit(0)

    # check if key exist and load them
    check_key(args.priv)
    check_key(args.pub)
    private = rsa_crypt.load_private_key(args.priv)

    # create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, args.port))
    sock.settimeout(10)

    # send hello message encrypted with public key
    message = rsa_crypt.sign(private, "Hello".encode())
    logging.debug(" sending sign hello message: %s" % message)
    # encoded = rsa_crypt.encrypt_private_key(message, public)
    sock.send(message)

    # wait for response
    response = sock.recv(2048)
    response_decrypt = rsa_crypt.decrypt_private_key(response, private)

    logging.info(" code is %s" % response_decrypt.decode())

def exec_command_line(argv):
	# Exit with correct return value
	if main(argv):
		exit(0)
	else:
		exit(255)

if __name__== "__main__":
    main(sys.argv)
