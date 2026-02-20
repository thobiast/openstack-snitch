# -*- coding: utf-8 -*-
"""Module that defines Violation structure."""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict


class ViolationCode(str, Enum):
    """Stable identifiers for compliance violations.

    These codes are intended for reporting, alerting, and downstream processing.
    """

    # Security Group
    SG_NOT_USED = "sg_not_used"
    SG_MISSING_TAG = "sg_missing_tag"
    SG_TOO_MANY_RULES = "sg_too_many_rules"
    # Security Group Rule
    SG_RULE_DENY_PORTS_PER_CIDR = "sg_rule_deny_ports_per_cidr"
    SG_RULE_FORBIDDEN_CIDR = "sg_rule_forbidden_cidr"
    SG_RULE_NETMASK_TOO_BROAD = "sg_rule_netmask_too_broad"
    SG_RULE_ANY_PROTOCOL = "sg_rule_any_protocol"
    SG_RULE_ANY_PORTS = "sg_rule_any_ports"
    SG_RULE_TOO_MANY_PORTS = "sg_rule_too_many_ports"
    SG_RULE_FORBIDDEN_PORT = "sg_rule_forbidden_port"
    # Server
    SERVER_MISSING_TAG = "server_missing_tag"
    SERVER_MISSING_METADATA = "server_missing_metadata"


@dataclass(frozen=True)
class Violation:
    """Represents a single compliance finding for one OpenStack resource.

    A violation contains the resource identity, a machine-friendly code, and an
    optional details payload used to describe what triggered the violation.
    """

    project_name: str
    resource_type: str
    resource_name: str
    resource_id: str
    resource_created_at: str

    code: ViolationCode
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def as_dict(self):
        """Return this violation as a serializable dictionary."""
        return asdict(self)


# vim: ts=4
