# -*- coding: utf-8 -*-
"""Module to create notification class object."""

from . import influxdb, stdout


def create_notification(system, **kwargs):
    """Return notificationbase class object."""
    supported = {
        "influxdb": influxdb.InfluxdbClient,
        "stdout": stdout.Stdout,
    }

    return supported[system](**kwargs)


# vim: ts=4
