# -*- coding: utf-8 -*-
"""Test SecurityGroup class."""

import pytest

from openstack_snitch.resources.security_group import SecurityGroup
from openstack_snitch.violation.violation import ViolationCode


def _find_violations(sg, code):
    """Return all violations from a SecurityGroup instance matching a given ViolationCode."""
    return [v for v in sg._violations if v.code == code]


@pytest.mark.parametrize(
    "sg_policy_tags", [["tag1"], ["tag2"], ["tag3", "tag4"]], indirect=True
)
def test_check_sg_tags(sg_policy_tags, os_sg):
    """
    Verifies SG mandatory tag policy:
    - If tags are missing, expect SG_MISSING_TAG violation with details["tag"]
      containing a comma-separated string of missing tags.
    - If no tags are missing, expect no SG_MISSING_TAG violation.
    """
    os_sg.tags = ["tag1"]
    os_sg.security_group_rules = []

    sg = SecurityGroup("my_project", os_sg)
    sg.check_compliance(sg_policy_tags, context={"used_sg_ids": {os_sg.id}})

    missing = [t for t in sg_policy_tags.mandatory_tags if t not in os_sg.tags]
    vlist = _find_violations(sg, ViolationCode.SG_MISSING_TAG)

    if not missing:
        assert vlist == []
        return

    assert len(vlist) == 1
    v = vlist[0]

    assert "tag" in v.details
    got_missing = [t.strip() for t in v.details["tag"].split(",") if t.strip()]
    assert sorted(got_missing) == sorted(missing)


def test_sg_not_used_alert(os_sg, sg_policy):
    """
    Verifies SG not-used policy:
    - If SG is not in used_sg_ids and alert_if_not_used=True, expect SG_NOT_USED.
    """
    os_sg.security_group_rules = []
    sg = SecurityGroup("my_project", os_sg)

    # Ensure alert_if_not_used policy is enabled
    sg_policy.alert_if_not_used = True

    # Case: SG is NOT used
    sg.check_compliance(sg_policy, context={"used_sg_ids": {"other-id"}})

    assert _find_violations(
        sg, ViolationCode.SG_NOT_USED
    ), "Expected SG_NOT_USED violation"


def test_sg_is_used(os_sg, sg_policy):
    """
    Verifies SG not-used policy:
    - If SG is in used_sg_ids, should NOT emit SG_NOT_USED.
    """
    os_sg.security_group_rules = []
    sg = SecurityGroup("my_project", os_sg)

    sg_policy.alert_if_not_used = True

    # Case: SG IS used
    sg.check_compliance(sg_policy, context={"used_sg_ids": {os_sg.id}})

    assert _find_violations(sg, ViolationCode.SG_NOT_USED) == []
