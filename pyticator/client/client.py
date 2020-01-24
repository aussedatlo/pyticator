#!/usr/bin/env python3

from ..common import rsa, exceptions, config_reader, logger
from pathlib import Path
import socket
import argparse
import hashlib
import sys
import logging

__author__ = "Louis Aussedat"
__copyright__ = "Copyright (c) 2019 Louis Aussedat"
__license__ = "GPLv3"

log = logger.setup_logger(__name__, logging.INFO)

def check_key(key_file):
    key_file = Path(key_file)
    if not key_file.is_file():
        log.error("file %s not found" % key_file)
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

    args = config_reader.get("/etc/pyticator/pyticator.conf", "client", args)

    if args.debug != '0':
        log.setLevel(logging.DEBUG)

    # generate keys
    if args.generate:
        rsa.generate_keys(pub_key_file=args.pub_key_file, priv_key_file=args.priv_key_file)
        sys.exit(0)

    # check if key exist and load them
    check_key(args.priv_key_file)
    check_key(args.pub_key_file)
    private = rsa.load_key(args.priv_key_file)

    # create socket
    log.info("connecting to %s:%s" % (args.host, args.port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, int(args.port)))
    sock.settimeout(10)

    # send hello message encrypted with public key
    message = rsa.sign(private, "Hello".encode())
    log.debug("sending sign hello message: %s" % message.hex())
    # encoded = rsa.encrypt_private_key(message, public)
    sock.send(message)

    # wait for response
    response = sock.recv(2048)
    response_decrypt = rsa.decrypt_private_key(response, private)

    log.info("code is %s" % response_decrypt.decode())

def exec_command_line(argv):
	# Exit with correct return value
	if main(argv):
		exit(0)
	else:
		exit(255)

if __name__== "__main__":
    main(sys.argv)
