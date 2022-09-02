# -*- coding: utf-8 -*-
"""Test Server class."""

import pytest

from snitch.resources.server import Server
from snitch.violation.violation import Violation


@pytest.mark.parametrize(
    "server_compliance_rules_tags",
    [["tag1"], ["tag2"], ["tag3", "tag4"]],
    indirect=True,
)
def test_check_server_tags(server_compliance_rules_tags, os_server):
    tags_that_exists_on_server = ["tag1"]
    os_server.tags = tags_that_exists_on_server

    server = Server("my_project", os_server)
    server.check_server_tags(server_compliance_rules_tags)

    missing_tags = [i for i in server_compliance_rules_tags if i not in os_server.tags]
    if missing_tags:
        result = [
            Violation(
                project_name="my_project",
                resource_type="Server",
                resource_name=server.name,
                resource_id=server.id,
                resource_created_at=os_server.created_at,
                message=f"Missing tags {', '.join(missing_tags)}",
            )
        ]
    else:
        result = []

    assert server.violations == result


@pytest.mark.parametrize(
    "server_compliance_rules_metadata", [["m1"], ["m2"], ["m3", "m4"]], indirect=True
)
def test_check_server_metadata_keys(server_compliance_rules_metadata, os_server):
    metadata_that_exists_on_server = {"m1": "xxxx"}
    os_server.metadata = metadata_that_exists_on_server

    server = Server("my_project", os_server)
    server.check_server_metadata(server_compliance_rules_metadata)

    missing_metadata = [
        i
        for i in server_compliance_rules_metadata
        if i not in os_server.metadata.keys()
    ]
    if missing_metadata:
        result = [
            Violation(
                project_name="my_project",
                resource_type="Server",
                resource_id=server.id,
                resource_name=server.name,
                resource_created_at=os_server.created_at,
                message=f"Missing metadata key {', '.join(missing_metadata)}",
            )
        ]
    else:
        result = []

    assert server.violations == result


# vim: ts=4
