#!/usr/bin/env python3

from . import code_generator
from ..common import rsa, config_reader, logger
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

log = logger.setup_logger(__name__, logging.INFO)

class Server:
    def __init__(self, pub_key_file, port):
        """initialize the server class"""
        self.port = port
        self.array_keys = []

        self.thread_code_generator = code_generator.thread_code_generator()
        self.thread_code_generator.start()

        # Create socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(('', port))

        # Get pub key
        self.key = rsa.load_key(pub_key_file)

    def _send_message(self, client, message):
        try:
            client.send(message)
            log.debug(" message sending ok")
        except:
            log.error(" message sending error")

    def _check_message(self, message):
        log.debug(" checking message: %s" % message.hex())
        verify = rsa.verify_sign(self.key, message, "Hello".encode())
        if not verify:
            log.error(" error key not reconized")
        return verify

    def _signal_handler(self, sig, frame):
        log.info(" SIGINT reicive, closing...")
        self.thread_code_generator.stop_tread()
        self.sock.close()
        sys.exit(0)

    def start(self):
        while True:
            self.sock.listen(5)
            client, address = self.sock.accept()
            log.debug(" connected by %s", address)

            message = client.recv(256)
            if message != "":
                if self._check_message(message):
                    log.info(" accepted key for user %s", address)
                    code, validity = self.thread_code_generator.get_code()
                    response = str(code) + ":" + str(validity)
                    send = rsa.encrypt_public_key(response.encode(), self.key)
                    self._send_message(client, send)
                else:
                    log.error(" refusing connexion for user %s", address)

def main(argv):
    # Parse arguments
    parser = argparse.ArgumentParser(argv)
    parser.add_argument("--pub_key_file", help="public key file")
    parser.add_argument("-p", "--port", help="port", type=int)
    parser.add_argument("-d", "--debug", help="debug mode",
                    action="store_true")
    args = parser.parse_args()
    args = config_reader.get("/etc/pyticator/pyticator.conf", "server", args)

    if args.debug != '0':
        log.setLevel(logging.DEBUG)

    server = Server(args.pub_key_file, int(args.port))
    # Handle SIGINT interrupt
    signal.signal(signal.SIGINT, server._signal_handler)
    server.start()

def exec_command_line(argv):
	# Exit with correct return value
	if main(argv):
		exit(0)
	else:
		exit(255)

if __name__== "__main__":
    main(sys.argv)
