# -*- coding: utf-8 -*-
"""Module to handle notification to InfluxDB."""

import logging
import os

from influxdb import InfluxDBClient

from .notificationbase import NotificationBase

LOG = logging.getLogger(__name__)


def fmt_violation_payload(violation):
    """Format violation object to influxdb payload."""
    return [
        {
            "measurement": violation.resource_type,
            "tags": {
                "project_name": violation.project_name,
                "resource_name": violation.resource_name,
                "resource_id": violation.resource_id,
                "message": violation.message,
            },
            "fields": {
                "resource_created_at": violation.resource_created_at,
            },
        }
    ]


class InfluxdbClient(NotificationBase):
    """
    Class to send violations to influxdb.
    Args:
        violations  (list): List with Violation object
    """

    # pylint: disable=W0613
    def __init__(self, **conf):
        self.client = InfluxDBClient(
            host=self.get_env("INFLUX_HOST"),
            port=self.get_env("INFLUX_PORT"),
            username=self.get_env("INFLUX_USERNAME"),
            password=self.get_env("INFLUX_PASSWORD"),
            database=self.get_env("INFLUX_DATABASE"),
        )

    def send_violations(self, violations):
        """
        Write violations to InfluxDB.

        Args:
            violations  (list): List with Violation object
        """
        for v in violations:
            LOG.debug("Writing violations %s", v)
            payload = fmt_violation_payload(v)
            self.client.write_points(payload)

    @staticmethod
    def get_env(var):
        if not os.environ.get(var):
            raise ValueError(f"Error: You must export environment variable {var}")
        return os.environ.get(var)


# vim: ts=4
