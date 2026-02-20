# -*- coding: utf-8 -*-
"""Module with helper functions."""

import logging
import sys

import yaml


def read_yaml_file(filename):
    """Read a YAML file and return the parsed structure.

    Exits the process with status 1 for common file errors.

    Args:
        filename: Path to the YAML file.

    Returns:
        object: Parsed YAML content (typically dict/list) returned by yaml.safe_load().
    """
    try:
        with open(filename, encoding="utf-8", mode="r") as file_fd:
            return yaml.safe_load(file_fd)
    except FileNotFoundError as error:
        print(str(error))
        sys.exit(1)
    except PermissionError as error:
        print(str(error))
        sys.exit(1)


def setup_logging(log_level=logging.INFO):
    """Configure root logger with a stdout handler and consistent formatting.

    This sets the root logger level and attaches a StreamHandler writing to
    standard output. Intended to be called once at program startup.

    Args:
        log_level: Logging level to apply to the root logger.
    """
    date_fmt = "%Y-%m-%d %H:%M:%S"
    msg_fmt = "%(asctime)s %(module)s - %(funcName)s [%(levelname)s] %(message)s"

    formatter = logging.Formatter(
        fmt=msg_fmt,
        datefmt=date_fmt,
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(handler)


# vim: ts=4
