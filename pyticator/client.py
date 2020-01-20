#!/usr/bin/env python3

from pathlib import Path
import logging
import socket
import argparse
import hashlib
import sys
import pyticator.rsa_crypt as rsa_crypt
import pyticator.exceptions as exceptions
import pyticator.configReader as configReader

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
    parser.add_argument("--host", help="host")
    parser.add_argument("--priv_key_file", help="private key file")
    parser.add_argument("--pub_key_file", help="public key file")
    parser.add_argument("-p", "--port", help="port", type=int)
    parser.add_argument("-d", "--debug", help="debug mode",
        action="store_true")
    parser.add_argument("-g", "--generate", help="generate keys",
        action="store_true")
    args = parser.parse_args()

    args = configReader.get("/etc/pyticator/pyticator.conf", "client", args)

    # Logger mode
    if args.debug != "0" and args.debug != None:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(message)s", datefmt="%H:%M:%S")
        logging.info("args: %s" % args)
    else:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s:%(levelname)s:%(message)s", datefmt="%H:%M:%S")

    logging.basicConfig(level=logging_level,
        format="%(asctime)s:%(levelname)s:%(message)s",
        datefmt="%H:%M:%S")

    # generate keys
    if args.generate:
        rsa_crypt.generate_keys(pub_key_file=args.pub_key_file, priv_key_file=args.priv_key_file)
        sys.exit(0)

    # check if key exist and load them
    check_key(args.priv_key_file)
    check_key(args.pub_key_file)
    private = rsa_crypt.load_private_key(args.priv_key_file)

    # create socket
    logging.info("connectiong to %s:%s" % (args.host, args.port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, int(args.port)))
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
