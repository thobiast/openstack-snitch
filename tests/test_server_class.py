# -*- coding: utf-8 -*-
"""Test Server class."""

import pytest

from openstack_snitch.resources.server import Server
from openstack_snitch.violation.violation import ViolationCode


def _find_violations(obj, code):
    return [v for v in obj._violations if v.code == code]


@pytest.mark.parametrize(
    "server_policy_tags",
    [["tag1"], ["tag2"], ["tag3", "tag4"]],
    indirect=True,
)
def test_check_server_tags(server_policy_tags, os_server):
    os_server.tags = ["tag1"]
    server = Server("my_project", os_server)

    server.check_compliance(server_policy_tags)

    missing = [t for t in server_policy_tags.mandatory_tags if t not in os_server.tags]
    vlist = _find_violations(server, ViolationCode.SERVER_MISSING_TAG)

    if not missing:
        assert vlist == []
        return

    assert len(vlist) == 1
    v = vlist[0]
    assert "tag" in v.details
    got_missing = [t.strip() for t in v.details["tag"].split(",") if t.strip()]
    assert sorted(got_missing) == sorted(missing)


@pytest.mark.parametrize(
    "required_keys, metadata, expect_missing",
    [
        (["m1"], {"m1": "xxxx"}, False),
        (["m2"], {"m1": "xxxx"}, True),
        (["m3", "m4"], {"m1": "xxxx"}, True),
    ],
)
def test_check_server_metadata_keys(
    server_policy, os_server, required_keys, metadata, expect_missing
):
    os_server.metadata = metadata
    server_policy.mandatory_metadata = required_keys

    server = Server("my_project", os_server)
    server.check_compliance(server_policy)

    vlist = _find_violations(server, ViolationCode.SERVER_MISSING_METADATA)
    assert bool(vlist) == expect_missing

    if expect_missing:
        # Adjust this key to match your implementation for metadata checks:
        # e.g. details={"metadata": "m2"} or {"metadata_key": "..."} etc.
        missing = [k for k in required_keys if k not in metadata]
        got = [k.strip() for k in vlist[0].details["metadata"].split(",") if k.strip()]
        assert sorted(got) == sorted(missing)
