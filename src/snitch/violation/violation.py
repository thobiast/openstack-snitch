# -*- coding: utf-8 -*-
"""Module that defines Violation structure."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Violation:
    """Violation structure."""

    project_name: str
    resource_type: str
    resource_name: str
    resource_id: str
    resource_created_at: str
    message: str

    @property
    def to_dict(self):
        return asdict(self)


# vim: ts=4
