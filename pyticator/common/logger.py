import logging

def setup_logger(name, level):
    logging.basicConfig(level=logging.DEBUG,
        format='%(asctime)s %(name)-12s %(levelname)-6s %(message)s',
        datefmt='%H:%M:%S')
    if "." in name:
        name = "pyticator.%s" % name.rpartition(".")[-1]

    logging.getLogger(name).setLevel(level)
    return logging.getLogger(name)
