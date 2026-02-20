# -*- coding: utf-8 -*-
# pylint: disable=missing-class-docstring,too-few-public-methods
"""
Schema and validation for os-snitch compliance rules.

This module defines the Pydantic models that validate the structure and values
of the `compliance_rules.yaml` file.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Dict, List, Optional

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyNetwork,
    RootModel,
    StringConstraints,
    model_validator,
)

# --- Reusable Types ---
# This defines a port as an int between 1 and 65535
Port = Annotated[int, Field(ge=1, le=65535)]
# Ensures strings are non-empty and stripped
NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
# Pydantic's IPvAnyNetwork handles the ipaddress logic automatically
Cidr = IPvAnyNetwork


class CidrMatch(str, Enum):
    exact = "exact"
    overlap = "overlap"


class ForbiddenCidrRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cidr: IPvAnyNetwork
    match: CidrMatch = CidrMatch.exact


class ForbidPorts(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tcp: List[Port] = Field(default_factory=list)
    udp: List[Port] = Field(default_factory=list)


class DenyPortsPerCidrRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cidr: IPvAnyNetwork
    match: CidrMatch = CidrMatch.exact

    tcp: List[Port] = Field(default_factory=list)
    udp: List[Port] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_some_ports(self):
        if not self.tcp and not self.udp:
            raise ValueError(
                "deny_ports_per_cidr item must define tcp and/or udp ports"
            )
        return self


class DirectionRules(BaseModel):
    model_config = ConfigDict(extra="forbid")

    forbid_cidrs: List[ForbiddenCidrRule] = Field(default_factory=list)

    deny_ports_per_cidr: List[DenyPortsPerCidrRule] = Field(default_factory=list)

    # Netmasks are 0-32 for IPv4, up to 128 for IPv6
    max_netmask_allowed: Optional[Annotated[int, Field(ge=0, le=128)]] = None

    forbid_protocols_any: bool = False
    forbid_ports_any: bool = False
    max_ports_per_rule: Optional[Annotated[int, Field(ge=1)]] = None

    forbid_ports: ForbidPorts = Field(default_factory=ForbidPorts)


class SecurityGroupPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mandatory_tags: List[NonEmptyStr] = Field(default_factory=list)
    alert_if_not_used: bool = False
    ignore_sg_ids: List[NonEmptyStr] = Field(default_factory=list)

    max_rules_per_sg: Optional[Annotated[int, Field(ge=1)]] = None

    ingress: DirectionRules = Field(default_factory=DirectionRules)
    egress: DirectionRules = Field(default_factory=DirectionRules)


class ServerPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mandatory_tags: List[NonEmptyStr] = Field(default_factory=list)
    mandatory_metadata: List[NonEmptyStr] = Field(default_factory=list)
    ignore_server_ids: List[NonEmptyStr] = Field(default_factory=list)


class ProjectPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sg: Optional[SecurityGroupPolicy] = None
    server: Optional[ServerPolicy] = None

    @model_validator(mode="after")
    def require_at_least_one(self) -> "ProjectPolicy":
        if self.sg is None and self.server is None:
            raise ValueError(
                "Project must define at least one policy: 'sg' or 'server'"
            )
        return self


class ComplianceRules(RootModel[Dict[str, ProjectPolicy]]):
    """
    Top-level: Represents the entire YAML file.
    RootModel allows us to validate a dict of projects at the root.
    """

    @classmethod
    def from_yaml_file(cls, path: str) -> "ComplianceRules":
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        if not isinstance(raw, dict) or not raw:
            raise ValueError(
                "Top-level YAML must be a non-empty mapping: <project_name>: { ... }"
            )

        return cls.model_validate(raw)
