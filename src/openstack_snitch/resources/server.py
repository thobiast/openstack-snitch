# -*- coding: utf-8 -*-
"""Module defining the base resource for all compliance checks"""

from ..violation.violation import ViolationCode
from .base_resource import BaseResource


class Server(BaseResource):
    """Compliance checker for Nova servers.

    This class evaluates a single server against the project policy.
    """

    def __init__(self, project_name, os_server):
        """Create a server compliance checker for one server.

        Args:
            project_name: Name of the OpenStack project being checked.
            os_server: OpenStack SDK server object.
        """
        super().__init__(project_name, os_server, "Server")

    def check_compliance(self, rules, *, context=None):
        """Run all configured server checks.

        Checks:
          - Mandatory tags.
          - Mandatory metadata keys (if configured).

        Args:
            project_server_rules: Server policy section loaded from compliance rules.
        """
        project_server_rules = rules
        self._check_mandatory_tags(
            project_server_rules.mandatory_tags, ViolationCode.SERVER_MISSING_TAG
        )

        # Check metadata
        if project_server_rules.mandatory_metadata:
            metadata = getattr(self.os_resource, "metadata", None) or {}
            missing = [
                m for m in project_server_rules.mandatory_metadata if m not in metadata
            ]
            if missing:
                self.add_violation(
                    ViolationCode.SERVER_MISSING_METADATA,
                    details={"metadata": f"{','.join(missing)}"},
                )


# vim: ts=4
