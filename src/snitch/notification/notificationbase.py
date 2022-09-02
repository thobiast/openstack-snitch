# -*- coding: utf-8 -*-
"""Define abtract notification base class."""

from abc import ABC, abstractmethod


# pylint: disable=R0903
class NotificationBase(ABC):
    """Notification abstract class."""

    @abstractmethod
    def send_violations(self, violations):
        """
        Write violations to backend.

        Args:
            violations  (list): List with Violation object
        """
        raise NotImplementedError()


# vim: ts=4
