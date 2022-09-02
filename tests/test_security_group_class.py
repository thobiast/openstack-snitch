# -*- coding: utf-8 -*-
"""Test SecurityGroup class."""

import pytest

from snitch.resources.security_group import SecurityGroup
from snitch.violation.violation import Violation


@pytest.mark.parametrize(
    "sg_compliance_rules_tags", [["tag1"], ["tag2"], ["tag3", "tag4"]], indirect=True
)
def test_check_sg_tags(sg_compliance_rules_tags, os_sg):
    tags_that_exists_on_sg = ["tag1"]
    os_sg.tags = tags_that_exists_on_sg

    sg = SecurityGroup("my_project", os_sg)
    sg.check_sg_tags(sg_compliance_rules_tags)

    missing_tags = [i for i in sg_compliance_rules_tags if i not in os_sg.tags]

    if missing_tags:
        result = [
            Violation(
                project_name="my_project",
                resource_type="SG",
                resource_name=sg.name,
                resource_id=sg.id,
                resource_created_at=os_sg.created_at,
                message=f"Missing tags {', '.join(missing_tags)}",
            )
        ]
    else:
        result = []

    assert sg.violations == result


def test_in_use_check_sg_not_used(os_sg):
    sg = SecurityGroup("my_project", os_sg)
    sg.check_sg_not_used(all_used_sgs_ids=[os_sg.id])

    assert not sg.violations


def test_not_in_use_check_sg_not_used(os_sg):
    sg = SecurityGroup("my_project", os_sg)
    all_used_sgs_ids = ["yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"]
    sg.check_sg_not_used(all_used_sgs_ids=all_used_sgs_ids)

    assert sg.violations == [
        Violation(
            project_name="my_project",
            resource_type="SG",
            resource_name=sg.name,
            resource_id=sg.id,
            resource_created_at=os_sg.created_at,
            message="Security group not used",
        )
    ]


# vim: ts=4
