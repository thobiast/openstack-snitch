# -*- coding: utf-8 -*-
"""Module to handle compliance checks."""

from abc import ABC, abstractmethod

from ..violation.violation import Violation


class BaseResource(ABC):
    """Abstract base class for all OpenStack resources."""

    def __init__(self, project_name, os_resource, resource_type):
        """Initialize the resource wrapper.

        Args:
            project_name: Name of the OpenStack project being checked.
            os_resource: The OpenStack SDK resource object (server, sg, ...).
            resource_type: Human-friendly resource type label used in reporting.
        """
        self.project_name = project_name
        self.os_resource = os_resource
        self.resource_type = resource_type
        self.name = getattr(os_resource, "name", "")
        self.id = getattr(os_resource, "id", "")
        self._violations = []

    @abstractmethod
    def check_compliance(self, rules, *, context=None):
        """Run compliance checks for this resource.

        Subclasses must implement this method and call `add_violation()` for each
        failed check.

        Args:
            rules: Policy/rules object for this resource type.
            context: Optional per-run context (e.g., used SG IDs).
        """

    def add_violation(self, violationcode, details):
        """Record a compliance violation for this resource.

        Args:
            violationcode: A ViolationCode enum value describing the issue.
            details: Dict with extra information to help identify the issue.
        """
        self._violations.append(
            Violation(
                project_name=self.project_name,
                resource_type=self.resource_type,
                resource_name=self.name,
                resource_id=self.id,
                resource_created_at=self.os_resource.created_at,
                code=violationcode,
                details=details,
            )
        )

    def _check_mandatory_tags(self, mandatory_tags, violationcode):
        """Verify that the resource contains all mandatory tags.

        Args:
            mandatory_tags: List of tags that must exist on the resource.
            violationcode: ViolationCode to use if any tags are missing.
        """
        tags = getattr(self.os_resource, "tags", [])
        missing = [t for t in mandatory_tags if t not in tags]
        if missing:
            self.add_violation(violationcode, details={"tag": f"{', '.join(missing)}"})

    def get_violations(self):
        """Return all violations recorded for this resource.

        Returns:
            list: A copy of the internal list of Violation objects.
        """
        return list(self._violations)


# vim: ts=4
