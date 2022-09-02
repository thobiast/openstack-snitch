# -*- coding: utf-8 -*-
"""Module do handle server compliance checks."""

import logging

from ..violation.violation import Violation

LOG = logging.getLogger(__name__)

VIOLATION_TYPE = "Server"
SERVER_MISSING_METADATA = "Missing metadata key"
SERVER_MISSING_TAGS = "Missing tags"


class Server:
    """Security Group handler."""

    def __init__(self, project_name, os_server):
        """
        Class to handle Servers checks.

        Params:
            project_name: (str) Project name
            osg_sg: (openstack.compute.v2.server) instance

        """
        self.project_name = project_name
        self.os_server = os_server
        self.name = os_server.name
        self.id = os_server.id
        self.violations = []

    def check_server_tags(self, mandatory_tags):
        """Verify if server has all mandatory tags."""
        missing_tags = [i for i in mandatory_tags if i not in self.os_server.tags]
        if missing_tags:
            message = f"{SERVER_MISSING_TAGS} {', '.join(missing_tags)}"
            # pylint: disable=duplicate-code
            self.violations.append(
                Violation(
                    self.project_name,
                    VIOLATION_TYPE,
                    self.name,
                    self.id,
                    self.os_server.created_at,
                    message,
                )
            )
            LOG.debug(
                "Server id: %s - Violation of server tags: missing tags: %s",
                self.id,
                missing_tags,
            )

    def check_server_metadata(self, mandatory_metadata):
        """Verify if server has all mandatory metadata."""
        server_metadata = self.os_server.metadata.keys()
        missing_metadata = [i for i in mandatory_metadata if i not in server_metadata]
        if missing_metadata:
            message = f"{SERVER_MISSING_METADATA} {', '.join(missing_metadata)}"
            # pylint: disable=duplicate-code
            self.violations.append(
                Violation(
                    self.project_name,
                    VIOLATION_TYPE,
                    self.name,
                    self.id,
                    self.os_server.created_at,
                    message,
                )
            )
            LOG.debug(
                "Server id: %s - Violation of server metadata: missing metadata: %s",
                self.id,
                missing_metadata,
            )

    def return_violations(self):
        """Return list with all Violation instances for the server."""
        return list(set(self.violations))


# vim: ts=4
