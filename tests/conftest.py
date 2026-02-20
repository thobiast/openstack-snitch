# -*- coding: utf-8 -*-
"""pytest fixtures."""

from unittest.mock import MagicMock

import pytest

from openstack_snitch.utils.rules_schema import (
    DirectionRules,
    ForbiddenCidrRule,
    ForbidPorts,
    SecurityGroupPolicy,
    ServerPolicy,
)


@pytest.fixture(name="sg_policy")
def fixture_sg_policy():
    """Default SecurityGroupPolicy for tests (Pydantic model)."""
    return SecurityGroupPolicy(
        mandatory_tags=["Team", "Department"],
        alert_if_not_used=True,
        ignore_sg_ids=["ad8b5502-fef5-4cb4-9950-9bbbb701a7f7"],
        egress=DirectionRules(
            forbid_cidrs=[
                ForbiddenCidrRule(cidr="0.0.0.0/0", match="exact"),
            ],
        ),
        ingress=DirectionRules(
            forbid_ports_any=True,  # old: forbid_all_ports
            forbid_protocols_any=True,  # old: forbid_all_protocols
            forbid_cidrs=[
                ForbiddenCidrRule(cidr="0.0.0.0/0", match="exact"),
            ],
            max_netmask_allowed=16,
            max_ports_per_rule=2,  # old: max_number_port_per_rule
            forbid_ports=ForbidPorts(
                tcp=[22],  # old: forbid_tcp_port
                udp=[],  # old: forbid_udp_port
            ),
        ),
    )


@pytest.fixture
def sg_policy_tags(sg_policy, request):
    """Fixture to inject specific mandatory tags into SG policy."""
    sg_policy.mandatory_tags = request.param
    return sg_policy


@pytest.fixture(name="server_policy_tags")
def fixture_server_policy_tags(request):
    """Fixture to inject specific mandatory tags into Server policy."""
    return ServerPolicy(mandatory_tags=request.param)


@pytest.fixture(name="server_policy_metadata")
def fixture_server_policy_metadata(request):
    """Fixture to inject specific mandatory metadata into Server policy."""
    return ServerPolicy(mandatory_metadata=request.param)


@pytest.fixture
def os_sg():
    """Mock an OpenStack Security Group object."""
    os_sg_mock = MagicMock(name="os_sg_mock")
    os_sg_mock.name = "test-sg"
    os_sg_mock.id = "sg-12345"
    os_sg_mock.created_at = "2024-01-01T00:00:00Z"
    os_sg_mock.tags = ["Team"]
    os_sg_mock.security_group_rules = []
    return os_sg_mock


@pytest.fixture
def server_policy():
    return ServerPolicy()


@pytest.fixture
def os_server():
    """Mock an OpenStack Server object."""
    os_server_mock = MagicMock(name="os_server_mock")
    os_server_mock.name = "test-server"
    os_server_mock.id = "srv-12345"
    os_server_mock.created_at = "2024-01-01T00:00:00Z"
    os_server_mock.tags = ["Team"]
    os_server_mock.metadata = {"m1": "v1"}
    return os_server_mock
