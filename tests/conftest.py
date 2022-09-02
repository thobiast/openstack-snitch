# -*- coding: utf-8 -*-
"""pytest fixtures."""

from unittest.mock import MagicMock

import pytest


@pytest.fixture(name="sg_compliance_rules")
def fixture_sg_compliance_rules():
    sg_rules = {
        "mandatory_tags": ["Team", "Department"],
        "alert_if_not_used": True,
        "egress": {"forbid_cidrs": ["0.0.0.0/0"], "forbid_cidrs_match_subnets": False},
        "ingress": {
            "forbid_all_ports": True,
            "forbid_all_protocols": True,
            "forbid_cidrs": ["0.0.0.0/0"],
            "forbid_cidrs_match_subnets": False,
            "forbid_tcp_port": [],
            "forbid_udp_port": [],
            "max_netmask_allowed": 16,
            "max_number_port_per_rule": 2,
        },
        "ignore_sg_ids": [
            "ad8b5502-fef5-4cb4-9950-9bbbb701a7f7",
        ],
    }
    return sg_rules


@pytest.fixture
def sg_compliance_rules_tags(sg_compliance_rules, request):
    sg_compliance_rules["mandatory_tags"] = request.param
    return sg_compliance_rules


@pytest.fixture
def server_compliance_rules_tags(request):
    server_compliance_rules = {"mandatory_tags": request.param}
    return server_compliance_rules


@pytest.fixture
def server_compliance_rules_metadata(request):
    server_compliance_rules = {"mandatory_metadata": request.param}
    return server_compliance_rules


@pytest.fixture
def os_sg():
    os_sg_mock = MagicMock(name="os_name")
    os_sg_mock.id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    os_sg_mock.created_at = "2000-01-01T00:00:00Z"
    return os_sg_mock


@pytest.fixture
def os_server():
    os_server_mock = MagicMock(name="os_name")
    os_server_mock.id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    os_server_mock.created_at = "2000-01-01T00:00:00Z"
    return os_server_mock
