
import threading
import random
import time

__author__ = "Louis Aussedat"
__copyright__ = "Copyright (c) 2019 Louis Aussedat"
__license__ = "GPLv3"

class thread_codeGenerator(threading.Thread):
    """Class thread that generate random code"""
    def __init__(self):
        threading.Thread.__init__(self)
        self.stop = False
        self.code = ""
        self.validity = 0

    def run(self):
        while not self.stop:
            if (self.validity == 0):
                # logging.debug(" generate new code...")
                self.code = int(random.uniform(0, 9999))
                self.validity = 20
            time.sleep(1)
            self.validity = self.validity - 1
        # logging.debug(" thread ended")

    def stop_tread(self):
        self.stop = True
        # logging.debug(" stopping thread")

    def get_code(self):
        return self.code, self.validity
