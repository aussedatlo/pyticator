import configparser
from .exceptions import ConfigFileNotFound
from pathlib import Path

__author__ = "Louis Aussedat"
__copyright__ = "Copyright (c) 2019 Louis Aussedat"
__license__ = "GPLv3"

def get(file, section, args):
    """get config from file and replace them by args if they exist"""

    if not Path(file).is_file():
        raise ConfigFileNotFound("No such file %s" % file)

    configParser = configparser.RawConfigParser()
    configParser.read(file)

    for arg in vars(args):
        arg_cmd = getattr(args, arg)
        if arg_cmd == False or arg_cmd == None:
            try:
                setattr(args, arg, configParser.get(section, arg))
            except:
                setattr(args, arg, None)
    return args

