__author__ = "Louis Aussedat"
__copyright__ = "Copyright (c) 2019 Louis Aussedat"
__license__ = "GPLv3"

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class KeyNotFound(Error):
    """Exception raised for errors in the input."""

    def __init__(self, message):
        self.message = message

class ConfigFileNotFound(Error):
    """Exception raised when config file is not found."""

    def __init__(self, message):
        self.message = message
