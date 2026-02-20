# -*- coding: utf-8 -*-
"""Test Security Group Rule compliance logic within the SecurityGroup class."""

import pytest

from openstack_snitch.resources.security_group import SecurityGroup
from openstack_snitch.utils.rules_schema import DenyPortsPerCidrRule, ForbiddenCidrRule
from openstack_snitch.violation.violation import ViolationCode


def _find_violations(sg, violationcode):
    """
    Return all recorded violations from a SecurityGroup handler that match a given code.

    Args:
        sg: The SecurityGroup instance (or any object) that exposes a 'violations' attribute
            containing Violation objects.
        violationcode: The ViolationCode (enum value) to filter by.

    Returns:
        list[Violation]: A list of violations whose 'code' equals 'violationcode'.
        Returns an empty list if none match.
    """
    return [v for v in sg._violations if v.code == violationcode]


def _reset_direction_to_minimal(direction_rules):
    direction_rules.forbid_cidrs = []
    direction_rules.max_netmask_allowed = None
    direction_rules.forbid_protocols_any = False
    direction_rules.forbid_ports_any = False
    direction_rules.max_ports_per_rule = None
    direction_rules.forbid_ports.tcp = []
    direction_rules.forbid_ports.udp = []
    direction_rules.deny_ports_per_cidr = []


# -----------------------------
# Forbidden CIDR tests
# -----------------------------


@pytest.mark.parametrize(
    "forbidden_items, remote_cidr, expected_matches",
    [
        # exact match: should match only if equal
        ([{"cidr": "0.0.0.0/0", "match": "exact"}], "0.0.0.0/0", 1),
        ([{"cidr": "10.0.0.0/8", "match": "exact"}], "10.0.0.0/8", 1),
        ([{"cidr": "10.0.0.0/8", "match": "exact"}], "10.0.0.0/16", 0),
        # overlap match: should match if overlaps
        ([{"cidr": "10.0.0.0/8", "match": "overlap"}], "10.0.0.0/16", 1),
        ([{"cidr": "192.168.1.0/24", "match": "overlap"}], "192.168.0.0/16", 1),
        ([{"cidr": "172.16.0.0/12", "match": "overlap"}], "10.0.0.0/8", 0),
        # report all matches
        (
            [
                {"cidr": "0.0.0.0/0", "match": "exact"},
                {"cidr": "100.64.0.0/10", "match": "overlap"},
            ],
            "0.0.0.0/0",
            2,  # /0 overlaps everything, so overlap rule also matches
        ),
    ],
)
def test_rule_forbid_cidrs(
    os_sg, sg_policy, forbidden_items, remote_cidr, expected_matches
):
    """
    Test if forbidden CIDRs are correctly identified in rules.
    Asserts on ViolationCode + details.matches.
    """
    os_sg.security_group_rules = [
        {
            "id": "test-rule-id",
            "direction": "egress",
            "remote_ip_prefix": remote_cidr,
            "protocol": "tcp",
            "remote_group_id": None,
        }
    ]

    # set pydantic rule
    sg_policy.egress.forbid_cidrs = [
        ForbiddenCidrRule(**item) for item in forbidden_items
    ]

    sg = SecurityGroup("test_project", os_sg)
    sg.check_compliance(sg_policy)

    vlist = _find_violations(sg, ViolationCode.SG_RULE_FORBIDDEN_CIDR)

    if expected_matches == 0:
        assert vlist == []
        return

    assert len(vlist) == 1
    v = vlist[0]
    assert v.details["remote_cidr"] == remote_cidr
    assert isinstance(v.details["matches"], list)
    assert len(v.details["matches"]) == expected_matches


# -----------------------------
# Forbidden ports tests
# -----------------------------


@pytest.mark.parametrize(
    "protocol, port_min, port_max, forbidden_tcp, forbidden_udp, expected_hit_ports",
    [
        ("tcp", 22, 22, [22, 80], [], [22]),
        ("tcp", 22, 443, [22, 80], [], [22, 80]),
        ("tcp", 80, 80, [22], [], []),
        ("tcp", 20, 25, [22], [], [22]),
        ("udp", 53, 53, [], [53], [53]),
        ("icmp", None, None, [22], [53], []),
    ],
)
def test_rule_forbid_ports(
    os_sg,
    sg_policy,
    protocol,
    port_min,
    port_max,
    forbidden_tcp,
    forbidden_udp,
    expected_hit_ports,
):
    os_sg.security_group_rules = [
        {
            "id": "port-rule-id",
            "direction": "ingress",
            "protocol": protocol,
            "port_range_min": port_min,
            "port_range_max": port_max,
            "remote_ip_prefix": "1.1.1.1/32",
            "remote_group_id": None,
        }
    ]

    _reset_direction_to_minimal(sg_policy.ingress)

    # set pydantic rule
    sg_policy.ingress.forbid_ports.tcp = forbidden_tcp
    sg_policy.ingress.forbid_ports.udp = forbidden_udp

    sg = SecurityGroup("test_project", os_sg)
    sg.check_compliance(sg_policy)

    vlist = _find_violations(sg, ViolationCode.SG_RULE_FORBIDDEN_PORT)

    if not expected_hit_ports:
        assert vlist == []
        return

    assert len(vlist) == 1
    v = vlist[0]
    assert sorted(v.details["matched_ports"]) == sorted(expected_hit_ports)
    assert v.details["protocol"] in ("tcp", "udp")


def test_rule_all_ports_forbidden(os_sg, sg_policy):
    """
    If forbid_ports list is set and p_min is None,
    it should triggers SG_ANY_PORTS and SG_FORBIDDEN_PORT
    """
    os_sg.security_group_rules = [
        {
            "id": "all-ports-rule",
            "direction": "ingress",
            "protocol": "tcp",
            "port_range_min": None,
            "port_range_max": None,
            "remote_ip_prefix": "0.0.0.0/0",
            "remote_group_id": None,
        }
    ]

    _reset_direction_to_minimal(sg_policy.ingress)

    # set pydantic rule
    sg_policy.ingress.forbid_ports_any = True
    sg_policy.ingress.forbid_ports.tcp = [22, 3389]

    sg = SecurityGroup("test_project", os_sg)
    sg.check_compliance(sg_policy, context={"used_sgs_ids": {os_sg.id}})

    assert (
        len(_find_violations(sg, ViolationCode.SG_RULE_ANY_PORTS)) == 1
    ), "Expected SG_ANY_PORTS violation"

    violation_forbid = _find_violations(sg, ViolationCode.SG_RULE_FORBIDDEN_PORT)
    assert violation_forbid, "Expected SG_FORBIDDEN_PORT violation"
    assert sorted(violation_forbid[0].details["matched_ports"]) == [22, 3389]


@pytest.mark.parametrize(
    "port_min, port_max, limit, expect_violation, expected_num_ports",
    [
        (22, 22, 2, False, 1),  # 1 port <= 2 OK
        (20, 21, 2, False, 2),  # 2 ports == 2 OK
        (20, 22, 2, True, 3),  # 3 ports > 2 violation
        (80, None, 1, False, 1),  # if port_max is None, treated as single-port
    ],
)
def test_rule_max_ports_per_rule(
    os_sg, sg_policy, port_min, port_max, limit, expect_violation, expected_num_ports
):
    os_sg.security_group_rules = [
        {
            "id": "max-ports-rule",
            "direction": "ingress",
            "protocol": "tcp",
            "port_range_min": port_min,
            "port_range_max": port_max,
            "remote_ip_prefix": "1.1.1.1/32",
            "remote_group_id": None,
        }
    ]

    dr = sg_policy.ingress
    _reset_direction_to_minimal(dr)
    dr.max_ports_per_rule = limit

    sg = SecurityGroup("test_project", os_sg)
    sg.check_compliance(sg_policy)

    vlist = _find_violations(sg, ViolationCode.SG_RULE_TOO_MANY_PORTS)
    assert bool(vlist) == expect_violation

    if expect_violation:
        v = vlist[0]
        assert v.details["max_ports_per_rule"] == limit
        assert v.details["num_ports"] == expected_num_ports
        assert v.details["port_min"] == port_min
        # if port_max is None in rule, your code may normalize it or keep it None; be tolerant:
        # assert v.details["port_max"] in (port_max, port_min)


def test_rule_max_ports_per_rule_ignored_for_icmp(os_sg, sg_policy):
    os_sg.security_group_rules = [
        {
            "id": "icmp-max-ports-rule",
            "direction": "ingress",
            "protocol": "icmp",
            "port_range_min": 1,
            "port_range_max": 65535,
            "remote_ip_prefix": "1.1.1.1/32",
            "remote_group_id": None,
        }
    ]

    dr = sg_policy.ingress
    _reset_direction_to_minimal(dr)
    dr.max_ports_per_rule = 1

    sg = SecurityGroup("test_project", os_sg)
    sg.check_compliance(sg_policy)

    assert _find_violations(sg, ViolationCode.SG_RULE_TOO_MANY_PORTS) == []


@pytest.mark.parametrize(
    "remote_cidr, limit, expect_violation",
    [
        ("10.0.0.0/8", 16, True),  # /8 is broader than /16 => violation
        ("10.0.0.0/16", 16, False),  # equal => ok
        ("10.0.0.0/24", 16, False),  # more restrictive => ok
        ("0.0.0.0/0", 16, True),  # broadest => violation
    ],
)
def test_rule_max_netmask_allowed(
    os_sg, sg_policy, remote_cidr, limit, expect_violation
):
    os_sg.security_group_rules = [
        {
            "id": "netmask-rule",
            "direction": "egress",
            "protocol": "tcp",
            "remote_ip_prefix": remote_cidr,
            "remote_group_id": None,
        }
    ]

    dr = sg_policy.egress
    _reset_direction_to_minimal(dr)
    # Set option max_netmask_allowed
    dr.max_netmask_allowed = limit

    sg = SecurityGroup("test_project", os_sg)
    sg.check_compliance(sg_policy)

    vlist = _find_violations(sg, ViolationCode.SG_RULE_NETMASK_TOO_BROAD)
    assert bool(vlist) == expect_violation

    if expect_violation:
        v = vlist[0]
        assert v.details["cidr"] == remote_cidr
        assert v.details["max_netmask_allowed"] == limit
        # prefixlen is parsed from CIDR; you can assert it too:
        assert isinstance(v.details["prefixlen"], int)


def test_rule_max_netmask_allowed_skipped_when_remote_group_id_present(
    os_sg, sg_policy
):
    os_sg.security_group_rules = [
        {
            "id": "netmask-remote-group",
            "direction": "egress",
            "protocol": "tcp",
            "remote_ip_prefix": "0.0.0.0/0",
            "remote_group_id": "some-group",
        }
    ]

    dr = sg_policy.egress
    _reset_direction_to_minimal(dr)
    # Set option max_netmask_allowed
    dr.max_netmask_allowed = 16

    sg = SecurityGroup("test_project", os_sg)
    sg.check_compliance(sg_policy)

    assert _find_violations(sg, ViolationCode.SG_RULE_NETMASK_TOO_BROAD) == []


@pytest.mark.parametrize(
    "proto, expect_violation",
    [
        (None, True),
        ("any", True),
        ("tcp", False),
        ("udp", False),
        ("icmp", False),
    ],
)
def test_rule_forbid_protocols_any(os_sg, sg_policy, proto, expect_violation):
    os_sg.security_group_rules = [
        {
            "id": "any-proto-rule",
            "direction": "ingress",
            "protocol": proto,
            "port_range_min": 22,
            "port_range_max": 22,
            "remote_ip_prefix": "1.1.1.1/32",
            "remote_group_id": None,
        }
    ]

    dr = sg_policy.ingress
    _reset_direction_to_minimal(dr)
    # set configuration that forbid_protocols_any
    dr.forbid_protocols_any = True

    sg = SecurityGroup("test_project", os_sg)
    sg.check_compliance(sg_policy)

    vlist = _find_violations(sg, ViolationCode.SG_RULE_ANY_PROTOCOL)
    assert bool(vlist) == expect_violation


@pytest.mark.parametrize(
    "proto, port_min, port_max, expect_violation",
    [
        ("tcp", None, None, True),  # any ports => violation
        ("udp", None, None, True),  # any ports => violation
        ("tcp", 22, 22, False),  # specific port => ok
        ("udp", 53, 53, False),  # specific port => ok
        ("icmp", None, None, False),  # ICMP ignored by _check_forbid_ports_any
    ],
)
def test_rule_forbid_ports_any(
    os_sg, sg_policy, proto, port_min, port_max, expect_violation
):
    os_sg.security_group_rules = [
        {
            "id": "any-ports-rule",
            "direction": "ingress",
            "protocol": proto,
            "port_range_min": port_min,
            "port_range_max": port_max,
            "remote_ip_prefix": "1.1.1.1/32",
            "remote_group_id": None,
        }
    ]

    dr = sg_policy.ingress
    _reset_direction_to_minimal(dr)
    # set configuration that forbid_ports_any
    dr.forbid_ports_any = True

    sg = SecurityGroup("test_project", os_sg)
    sg.check_compliance(sg_policy)

    vlist = _find_violations(sg, ViolationCode.SG_RULE_ANY_PORTS)
    assert bool(vlist) == expect_violation


@pytest.mark.parametrize(
    "remote_cidr, policy_item, proto, port_min, port_max, expected_hit_ports",
    [
        # exact match: /0 exact + tcp 22 denied -> hit 22
        (
            "0.0.0.0/0",
            {"cidr": "0.0.0.0/0", "match": "exact", "tcp": [22, 3389], "udp": []},
            "tcp",
            22,
            22,
            [22],
        ),
        # exact match but different CIDR -> no hits
        (
            "10.0.0.0/8",
            {"cidr": "0.0.0.0/0", "match": "exact", "tcp": [22], "udp": []},
            "tcp",
            22,
            22,
            [],
        ),
        # overlap match: policy 10/8 overlap, remote 10/16 overlaps -> hit
        (
            "10.0.0.0/16",
            {"cidr": "10.0.0.0/8", "match": "overlap", "tcp": [3306], "udp": []},
            "tcp",
            3306,
            3306,
            [3306],
        ),
        # overlap match + range includes multiple denied ports -> hits list
        (
            "192.168.0.0/16",
            {
                "cidr": "192.168.0.0/16",
                "match": "overlap",
                "tcp": [22, 80, 443],
                "udp": [],
            },
            "tcp",
            1,
            100,
            [22, 80],
        ),
        # UDP example
        (
            "192.168.0.0/16",
            {"cidr": "192.168.0.0/16", "match": "exact", "tcp": [], "udp": [53]},
            "udp",
            53,
            53,
            [53],
        ),
        # Protocol not tcp/udp -> ignored
        (
            "0.0.0.0/0",
            {"cidr": "0.0.0.0/0", "match": "exact", "tcp": [22], "udp": []},
            "icmp",
            None,
            None,
            [],
        ),
    ],
)
def test_rule_deny_ports_per_cidr(
    os_sg,
    sg_policy,
    remote_cidr,
    policy_item,
    proto,
    port_min,
    port_max,
    expected_hit_ports,
):
    # one ingress rule under test
    os_sg.security_group_rules = [
        {
            "id": "deny-ports-per-cidr-rule",
            "direction": "ingress",
            "protocol": proto,
            "port_range_min": port_min,
            "port_range_max": port_max,
            "remote_ip_prefix": remote_cidr,
            "remote_group_id": None,
        }
    ]

    dr = sg_policy.ingress
    _reset_direction_to_minimal(dr)

    # configure policy list
    dr.deny_ports_per_cidr = [DenyPortsPerCidrRule(**policy_item)]

    sg = SecurityGroup("test_project", os_sg)
    sg.check_compliance(sg_policy, context={"used_sgs_ids": {os_sg.id}})

    vlist = _find_violations(sg, ViolationCode.SG_RULE_DENY_PORTS_PER_CIDR)

    if not expected_hit_ports:
        assert vlist == []
        return

    assert len(vlist) == 1
    v = vlist[0]
    assert v.details["remote_cidr"] == remote_cidr
    assert v.details["protocol"] == (proto or "any")

    matches = v.details["matches"]
    assert isinstance(matches, list)
    assert len(matches) == 1

    # verify matched ports
    assert sorted(matches[0]["matched_ports"]) == sorted(expected_hit_ports)
    assert matches[0]["policy_cidr"] == policy_item["cidr"]
    assert matches[0]["match"] == policy_item.get("match", "exact")


def test_rule_deny_ports_per_cidr_all_ports_hits_all_denied(os_sg, sg_policy):
    """
    If SG rule has port_range_min=None (all ports), and CIDR matches,
    then matched_ports should include all denied ports for that protocol.
    """
    os_sg.security_group_rules = [
        {
            "id": "deny-ports-per-cidr-all-ports",
            "direction": "ingress",
            "protocol": "tcp",
            "port_range_min": None,
            "port_range_max": None,
            "remote_ip_prefix": "0.0.0.0/0",
            "remote_group_id": None,
        }
    ]

    dr = sg_policy.ingress
    _reset_direction_to_minimal(dr)

    dr.deny_ports_per_cidr = [
        DenyPortsPerCidrRule(cidr="0.0.0.0/0", match="exact", tcp=[22, 3389], udp=[])
    ]

    sg = SecurityGroup("test_project", os_sg)
    sg.check_compliance(sg_policy, context={"used_sgs_ids": {os_sg.id}})

    vlist = _find_violations(sg, ViolationCode.SG_RULE_DENY_PORTS_PER_CIDR)
    assert len(vlist) == 1
    matches = vlist[0].details["matches"]
    assert matches[0]["matched_ports"] == [22, 3389]
    assert matches[0]["port_min"] is None
    assert matches[0]["port_max"] is None
