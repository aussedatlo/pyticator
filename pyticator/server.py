#!/usr/bin/env python3

import pyticator.rsa_crypt as rsa_crypt
import pyticator.generate_code as generate_code
import pyticator.exceptions as exceptions
from pathlib import Path
import logging
import socket
import argparse
import hashlib
import signal
import sys

__author__ = "Louis Aussedat"
__copyright__ = "Copyright (c) 2019 Louis Aussedat"
__license__ = "GPLv3"

class Server:
    def __init__(self, pub_key_file, port):
        """initialize the server class"""
        self.port = port
        self.array_keys = []

        self.thread_generate_code = generate_code.thread_generate_code()
        self.thread_generate_code.start()

        # Create socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(('', port))

        # Get pub key
        self.key = rsa_crypt.load_public_key(pub_key_file)

    def _send_message(self, client, message):
        try:
            client.send(message)
            logging.debug(" message sending ok")
        except:
            logging.error(" message sending error")

    def _check_message(self, message):
        logging.debug(" checking message ! : %s" % message.hex())
        verify = rsa_crypt.verify_sign(self.key, message, "Hello".encode())
        if not verify:
            logging.error(" error key not reconized")
        return verify

    def signal_handler(self, sig, frame):
        logging.info(" SIGINT reicive, closing...")
        self.thread_generate_code.stop_tread()
        self.sock.close()
        sys.exit(0)

    def start(self):
        while True:
            self.sock.listen(5)
            client, address = self.sock.accept()
            logging.debug(" connected by %s", address)

            message = client.recv(256)
            if message != "":
                if self._check_message(message):
                    logging.info(" accepted key for user %s", address)
                    code, validity = self.thread_generate_code.get_code()
                    response = str(code) + ":" + str(validity)
                    send = rsa_crypt.encrypt_public_key(response.encode(), self.key)
                    self._send_message(client, send)
                else:
                    logging.error(" refusing connexion for user %s", address)

def main(argv):
    # Parse arguments
    parser = argparse.ArgumentParser(argv)
    parser.add_argument("--pub", help="public key file", default="/etc/pyticator/id_rsa.pub")
    parser.add_argument("-p", "--port", help="port", type=int, default="8852")
    parser.add_argument("-d", "--debug", help="debug mode",
                    action="store_true")
    args = parser.parse_args()

    # Logger mode
    if args.debug:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.INFO

    logging.basicConfig(level=logging_level, format="%(asctime)s:%(levelname)s:%(message)s", datefmt="%H:%M:%S")

    server = Server(args.pub, args.port)
    # Handle SIGINT interrupt
    signal.signal(signal.SIGINT, server.signal_handler)
    server.start()

def exec_command_line(argv):
	# Exit with correct return value
	if main(argv):
		exit(0)
	else:
		exit(255)

if __name__== "__main__":
    main(sys.argv)
