# -*- coding: utf-8 -*-
"""Test SecurityGroupRule class."""

import pytest

from snitch.resources.security_group import SecurityGroupRule


@pytest.mark.parametrize(
    "forbidden, remote_cidr, result",
    [
        (["0.0.0.0/0"], "0.0.0.0/0", "Forbidden cidr egress"),
        (["0.0.0.0/0"], "192.168.0.0/24", "Forbidden cidr egress"),
        (["0.0.0.0/0", "192.168.0.0/16"], "192.168.0.0/16", "Forbidden cidr egress"),
        (["192.168.0.0/16"], "192.168.0.0/16", "Forbidden cidr egress"),
        (["192.168.0.0/16"], "192.168.0.0/20", "Forbidden cidr egress"),
        (["192.168.0.0/16"], "192.168.50.0/24", "Forbidden cidr egress"),
        (["192.168.0.0/22"], "192.168.3.0/24", "Forbidden cidr egress"),
        (["192.168.0.0/22"], "192.168.4.0/24", ""),
        (["192.168.0.0/16"], "10.0.0.0/24", ""),
    ],
)
def test_check_cidr_exactly_match(forbidden, remote_cidr, result):
    """Check security grupo rule cidr (ingress and egress)."""
    rule = {"id": "01", "remote_ip_prefix": remote_cidr}
    sg_rule = SecurityGroupRule(rule)
    sg_rule.check_cidr(
        direction="egress", forbidden_cidrs=forbidden, match_subnets=True
    )
    result = [result] if result else []
    assert sg_rule.issues == result


@pytest.mark.parametrize(
    "forbidden, remote_cidr, result",
    [
        (["0.0.0.0/0"], "0.0.0.0/0", "Forbidden cidr egress"),
        (["0.0.0.0/0"], "192.168.0.0/24", ""),
        (["0.0.0.0/0", "192.168.0.0/16"], "192.168.0.0/16", "Forbidden cidr egress"),
        (
            ["0.0.0.0/0", "192.168.0.0/16", "10.0.4.0/24"],
            "10.0.4.0/24",
            "Forbidden cidr egress",
        ),
        (["192.168.0.0/16"], "192.168.0.0/16", "Forbidden cidr egress"),
        (["192.168.0.0/16"], "192.168.0.0/20", ""),
        (["192.168.0.0/16"], "192.168.50.0/24", ""),
        (["192.168.0.0/22"], "192.168.3.0/24", ""),
    ],
)
def test_check_cidr_exactly_match_false(forbidden, remote_cidr, result):
    """Check security grupo rule cidr (ingress and egress)."""
    rule = {"id": "01", "remote_ip_prefix": remote_cidr}
    sg_rule = SecurityGroupRule(rule)
    sg_rule.check_cidr(
        direction="egress", forbidden_cidrs=forbidden, match_subnets=False
    )
    result = [result] if result else []
    assert sg_rule.issues == result


@pytest.mark.parametrize(
    "max_netmask_allowed, remote_cidr, remote_group_id, result",
    [
        (16, None, None, "Violation of ingress max netmask"),
        (16, "10.0.0.0/8", None, "Violation of ingress max netmask"),
        (22, "10.0.0.0/20", None, "Violation of ingress max netmask"),
        (20, "10.0.0.0/19", None, "Violation of ingress max netmask"),
        (20, "10.0.0.0/23", None, ""),
        (20, "10.0.0.0/20", None, ""),
        (20, None, "another_sg_id", ""),
    ],
)
def test_check_ingress_max_netmask(
    max_netmask_allowed, remote_cidr, remote_group_id, result
):
    rule = {
        "id": "01",
        "remote_ip_prefix": remote_cidr,
        "remote_group_id": remote_group_id,
    }
    sg_rule = SecurityGroupRule(rule)
    sg_rule.check_ingress_max_netmask(max_netmask_allowed)
    result = [result] if result else []
    assert sg_rule.issues == result


@pytest.mark.parametrize(
    "max_number_port_per_rule, protocol, port_min, port_max, result",
    [
        (2, "tcp", 80, 85, "Violation of ingress max number port per rule"),
        (2, "udp", 80, 85, "Violation of ingress max number port per rule"),
        (2, "tcp", None, 85, "Violation of ingress max number port per rule"),
        (2, "tcp", 80, None, "Violation of ingress max number port per rule"),
        (2, "tcp", None, None, "Violation of ingress max number port per rule"),
        (2, "tcp", 80, 80, ""),
        (2, "tcp", 80, 81, ""),
        (2, "icmp", 80, 90, ""),
    ],
)
def test_check_ingress_max_number_port(
    max_number_port_per_rule, protocol, port_min, port_max, result
):
    rule = {
        "id": "01",
        "protocol": protocol,
        "port_range_min": port_min,
        "port_range_max": port_max,
    }
    sg_rule = SecurityGroupRule(rule)
    sg_rule.check_ingress_max_number_port(max_number_port_per_rule)
    result = [result] if result else []
    assert sg_rule.issues == result


@pytest.mark.parametrize(
    "forbidden_ports, protocol, port_min, port_max, result",
    [
        ([80], "tcp", 80, 85, "Violation of ingress forbidden port tcp"),
        ([80], "tcp", 80, 80, "Violation of ingress forbidden port tcp"),
        ([80], "tcp", 70, 90, "Violation of ingress forbidden port tcp"),
        ([23, 80], "tcp", 80, 80, "Violation of ingress forbidden port tcp"),
        ([20, 23, 80], "tcp", 23, 23, "Violation of ingress forbidden port tcp"),
        ([20, 23, 80], "tcp", 1, 21, "Violation of ingress forbidden port tcp"),
        ([80], "tcp", 443, 443, ""),
        ([80], "tcp", 81, 123, ""),
    ],
)
def test_check_ingress_port(forbidden_ports, protocol, port_min, port_max, result):
    rule = {
        "id": "01",
        "protocol": protocol,
        "port_range_min": port_min,
        "port_range_max": port_max,
    }
    sg_rule = SecurityGroupRule(rule)
    sg_rule.check_ingress_port(protocol, forbidden_ports)
    result = [result] if result else []
    assert sg_rule.issues == result


@pytest.mark.parametrize(
    "forbidden_ports, protocol, port_min, port_max",
    [
        ([80], "tcp", 80, 80),
        ([80], "tcp", 1, 1024),
    ],
)
def test_check_ingress_port_mismatch_protocol(
    forbidden_ports, protocol, port_min, port_max
):
    """check_ingress_port - check when sg rule does not match compliance protocol."""
    rule = {
        "id": "01",
        "protocol": protocol,
        "port_range_min": port_min,
        "port_range_max": port_max,
    }
    sg_rule = SecurityGroupRule(rule)
    sg_rule.check_ingress_port("udp", forbidden_ports)
    assert not sg_rule.issues


@pytest.mark.parametrize(
    "forbid_all_protocols, protocol, result",
    [
        (True, "tcp", ""),
        (True, "udp", ""),
        (True, None, "Violation of ingress all protocols"),
        (False, None, ""),
    ],
)
def test_check_ingress_all_protocols(forbid_all_protocols, protocol, result):
    rule = {"id": "01", "protocol": protocol}
    sg_rule = SecurityGroupRule(rule)
    sg_rule.check_ingress_all_protocols(forbid_all_protocols)
    result = [result] if result else []
    assert sg_rule.issues == result


@pytest.mark.parametrize(
    "forbid_all_ports, protocol, port_min, result",
    [
        (True, "tcp", 443, ""),
        (True, "tcp", None, "Violation of ingress all ports"),
        (True, "udp", None, "Violation of ingress all ports"),
        (True, "icmp", None, ""),
        (False, "tcp", None, ""),
        (False, "udp", None, ""),
    ],
)
def test_check_ingress_all_ports(forbid_all_ports, protocol, port_min, result):
    rule = {"id": "01", "protocol": protocol, "port_range_min": port_min}
    sg_rule = SecurityGroupRule(rule)
    sg_rule.check_ingress_all_ports(forbid_all_ports)
    result = [result] if result else []
    assert sg_rule.issues == result


# vim: ts=4
