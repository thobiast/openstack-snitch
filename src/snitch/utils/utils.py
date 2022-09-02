# -*- coding: utf-8 -*-
"""Module with helper functions."""

import logging
import sys

import yaml

color_dic = {
    "blue": "\033[0;34m",
    "red": "\033[1;31m",
    "green": "\033[0;32m",
    "yellow": "\033[0;33m",
    "cyan": "\033[0;36m",
    "nocolor": "\033[0m",
}


def read_yaml_file(filename):
    """Read yaml file."""
    try:
        with open(filename, encoding="utf-8", mode="r") as file_fd:
            return yaml.safe_load(file_fd)
    except FileNotFoundError as error:
        print(str(error))
        sys.exit(1)
    except PermissionError as error:
        print(str(error))
        sys.exit(1)


def setup_logging(logfile=None, *, filemode="a", date_format=None, log_level="DEBUG"):
    """
    Configure logging.

    Arguments (opt):
        logfile     (str): log file to write the log messages
                               If not specified, it shows log messages
                               on screen (stderr)
    Keyword arguments (opt):
        filemode    (a/w): a - log messages are appended to the file (default)
                           w - log messages overwrite the file
        date_format (str): date format in strftime format
                           default is %m/%d/%Y %H:%M:%S
        log_level   (str): specifies the lowest-severity log message
                           DEBUG, INFO, WARNING, ERROR or CRITICAL
                           default is DEBUG
    """
    dict_level = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }

    if log_level not in dict_level:
        raise ValueError("Invalid log_level")
    if filemode not in ["a", "w"]:
        raise ValueError("Invalid filemode")

    if not date_format:
        date_format = "%m/%d/%Y %H:%M:%S"

    log_fmt = "%(asctime)s %(module)s %(funcName)s %(levelname)s %(message)s"

    logging.basicConfig(
        level=dict_level[log_level],
        format=log_fmt,
        datefmt=date_format,
        filemode=filemode,
        filename=logfile,
    )

    return logging.getLogger(__name__)


# vim: ts=4
