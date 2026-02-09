# -*- coding: utf-8 -*-
"""Module to handle notification to stdout."""

import logging

from rich.console import Console
from rich.table import Table

from .notificationbase import NotificationBase

LOG = logging.getLogger(__name__)


class Stdout(NotificationBase):
    """
    Class to send violations to influxdb.

    Args:  **conf: kwargs with options for this class
    """

    def __init__(self, **conf):
        self.format = conf.get("stdout_fmt", "table")

    def send_violations(self, violations):
        """
        Write violations to stdout.

        Args:
            violations  (list): List with Violation object
        """
        if self.format == "table":
            self.table(violations)
        elif self.format == "dict":
            for v in violations:
                print(v.to_dict)
        else:
            for v in violations:
                print(v)

    def table(self, violations):
        table = Table(title="OpenStack Violations")
        table.add_column("Resource ID", style="cyan", no_wrap=True)
        table.add_column("Resource Name", style="magenta")
        table.add_column("Resource Type", justify="center", style="green")
        table.add_column("Resource Created at", justify="right", style="green")
        table.add_column("Violation", justify="left", style="green")

        for v in violations:
            table.add_row(
                v.resource_id,
                v.resource_name,
                v.resource_type,
                v.resource_created_at,
                v.message,
            )

        console = Console()
        console.print(table, justify="center")


# vim: ts=4
