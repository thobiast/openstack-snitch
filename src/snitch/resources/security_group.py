# -*- coding: utf-8 -*-
"""Module do handle security group compliance checks."""

import ipaddress
import logging

from ..utils.utils import color_dic
from ..violation.violation import Violation

LOG = logging.getLogger(__name__)

VIOLATION_TYPE = "SG"
SG_MISSING_TAGS = "Missing tags"
SG_NOT_USED = "Security group not used"
SG_RULE_FORBIDDEN_CIDR = "Forbidden cidr"
SG_INGRESS_MAX_NETMASK = "Violation of ingress max netmask"
SG_INGRESS_MAX_NUM_PORT_PER_RULE = "Violation of ingress max number port per rule"
SG_INGRESS_FORBIDDEN_PORT = "Violation of ingress forbidden port"
SG_INGRESS_FORBIDDEN_ALL_PORTS_RULE = "Violation of ingress all ports"
SG_INGRESS_FORBIDDEN_ALL_PROTOCOLS_RULE = "Violation of ingress all protocols"


class SecurityGroupRule:
    """
    Class to check Security groups rules compliance.

    Params:
        sg_rule: (dict) security group rules
    """

    def __init__(self, sg_rule):
        """SecurityGroupRule."""
        self.rule = sg_rule
        self.rule_id = sg_rule["id"]
        self.issues = []

    def __str__(self):
        """Return rule details."""
        return f"{self.rule}"

    def check_cidr(self, *, direction, forbidden_cidrs, match_subnets):
        """
        Check rule CIDR.

        Params:
            direction              (str): ingress / egress
            forbidden_cidrs       (list): list with forbidden cidrs
            match_subnets   (True/False): False - alarm match exactly cidr only, i.e.,
                                                  string comparation
                                          True  - alarm match if rule uses a subnet of
                                                  forbidden cidr
        """
        remote_ip_prefix = (
            self.rule["remote_ip_prefix"]
            if self.rule["remote_ip_prefix"]
            else "0.0.0.0/0"
        )

        if match_subnets:
            remote_network = ipaddress.ip_network(remote_ip_prefix)
            for cidr in forbidden_cidrs:
                cidr_network = ipaddress.ip_network(cidr)
                if cidr_network.overlaps(remote_network):
                    LOG.debug(
                        "Violation of %s cidr. SG rule cidr - %s",
                        direction,
                        remote_ip_prefix,
                    )
                    self.issues.append(f"{SG_RULE_FORBIDDEN_CIDR} {direction}")
                    return
        else:
            if remote_ip_prefix in forbidden_cidrs:
                LOG.debug(
                    "Violation of %s cidr. SG rule cidr - %s",
                    direction,
                    remote_ip_prefix,
                )
                self.issues.append(f"{SG_RULE_FORBIDDEN_CIDR} {direction}")
                return

        LOG.debug("cidr %s ok: %s", direction, remote_ip_prefix)

    def check_ingress_max_netmask(self, max_netmask):
        remote_ip_prefix = (
            self.rule["remote_ip_prefix"]
            if self.rule["remote_ip_prefix"]
            else "0.0.0.0/0"
        )

        # pass if SG permit access for a remote_group_id
        if not self.rule["remote_ip_prefix"] and self.rule["remote_group_id"]:
            LOG.debug("netmask ok: remote_ip_prefix None but remote_group_id defined")
            return

        netmask = remote_ip_prefix.split("/")[-1]

        if int(netmask) < max_netmask:
            LOG.debug("Violation of ingress max netmask: /%s", netmask)
            self.issues.append(SG_INGRESS_MAX_NETMASK)
        else:
            LOG.debug("netmask ok: /%s", netmask)

    def check_ingress_max_number_port(self, max_number_port_per_rule):
        if self.rule["protocol"] == "icmp":
            LOG.debug("max_number_port_per_rule ok: icmp protocol")
            return

        port_range_min = self.rule["port_range_min"]
        port_range_max = self.rule["port_range_max"]

        if not port_range_min or not port_range_max:
            LOG.debug(
                "Violation of ingress max number port per rule: port_min %s port_max %s",
                port_range_min,
                port_range_max,
            )
            self.issues.append(SG_INGRESS_MAX_NUM_PORT_PER_RULE)
        else:
            num_ports = (port_range_max + 1) - port_range_min
            if num_ports > max_number_port_per_rule:
                LOG.debug(
                    "Violation of ingress max number port per rule: %s", num_ports
                )
                self.issues.append(SG_INGRESS_MAX_NUM_PORT_PER_RULE)
            else:
                LOG.debug("max_number_port_per_rule ok: %s", num_ports)

    def check_ingress_port(self, protocol, forbidden_ports):
        if self.rule["protocol"] != protocol:
            LOG.debug("Not %s protocol rule: %s", protocol, self.rule["protocol"])
            return

        if not forbidden_ports:
            LOG.debug("No port forbidden for protocol %s", protocol)
            return

        port_range_min = self.rule["port_range_min"]
        port_range_max = self.rule["port_range_max"]

        if not port_range_min:
            self.issues.append(f"{SG_INGRESS_FORBIDDEN_PORT} {protocol}")
            LOG.debug(
                "Violation of ingress %s port: %s - %s",
                protocol,
                port_range_min,
                port_range_max,
            )
        else:
            for port in range(port_range_min, port_range_max + 1, 1):
                if port in forbidden_ports:
                    self.issues.append(f"{SG_INGRESS_FORBIDDEN_PORT} {protocol}")
                    LOG.debug(
                        "Violation of ingress %s port: %s - %s",
                        protocol,
                        port_range_min,
                        port_range_max,
                    )
                else:
                    LOG.debug(
                        "%s port ok: %s - %s", protocol, port_range_min, port_range_max
                    )

    def check_ingress_all_protocols(self, check_all_protocols):
        if not check_all_protocols:
            LOG.debug("Check disabled")
            return

        protocol = self.rule["protocol"]
        if protocol:
            LOG.debug("Protocol ok: %s", protocol)
        else:
            self.issues.append(SG_INGRESS_FORBIDDEN_ALL_PROTOCOLS_RULE)
            LOG.debug("Violation of ingress all_protocols: %s", protocol)

    def check_ingress_all_ports(self, check_all_ports):
        if not check_all_ports:
            LOG.debug("Check disabled")
            return
        if self.rule["protocol"] == "icmp":
            LOG.debug("Not check. Protocol: %s", self.rule["protocol"])
            return

        ports = self.rule["port_range_min"]
        if ports:
            LOG.debug("Ports ok: %s", ports)
        else:
            self.issues.append(SG_INGRESS_FORBIDDEN_ALL_PORTS_RULE)
            LOG.debug("Violation of ingress all ports: %s", ports)


class SecurityGroup:
    """Security Group compliance checker."""

    def __init__(self, project_name, os_sg):
        """
        Class to handle Security groups configuration.

        Params:
            project_name: (str) Project name
            osg_sg: (openstack.network.v2.security_group.SecurityGroup) instance

        Attribute violations is a list of Violation class instance
        with findings for the SG
        """
        self.project_name = project_name
        self.os_sg = os_sg
        self.name = os_sg.name
        self.id = os_sg.id
        self.rules = [
            SecurityGroupRule(rule) for rule in self.os_sg.security_group_rules
        ]
        self.violations = []

    def check_egress_rules(self, egress):
        """
        Verify all egress rules.

        Params:  egress (dict): Dictionary with egress compliance rules.
        """
        LOG.debug(
            "%s #### Checking egress rules %s", color_dic["cyan"], color_dic["nocolor"]
        )
        for rule in self.rules:
            if rule.rule["direction"] == "egress":
                LOG.debug("#### Checking egress rules - rule id: %s", rule.rule_id)
                rule.check_cidr(
                    direction=rule.rule["direction"],
                    forbidden_cidrs=egress["forbid_cidrs"],
                    match_subnets=egress["forbid_cidrs_match_subnets"],
                )

    def check_ingress_rules(self, ingress):
        """
        Verify all ingress rules.

        Params:  ingress (dict): Dictionary with ingress compliance rules.
        """
        LOG.debug(
            "%s #### Checking ingress rules %s", color_dic["cyan"], color_dic["nocolor"]
        )
        for rule in self.rules:
            if rule.rule["direction"] == "ingress":
                LOG.debug("#### Checking ingress rules - rule id: %s", rule.rule_id)
                rule.check_cidr(
                    direction=rule.rule["direction"],
                    forbidden_cidrs=ingress["forbid_cidrs"],
                    match_subnets=ingress["forbid_cidrs_match_subnets"],
                )
                rule.check_ingress_max_netmask(ingress["max_netmask_allowed"])
                rule.check_ingress_max_number_port(ingress["max_number_port_per_rule"])
                rule.check_ingress_port("tcp", ingress["forbid_tcp_port"])
                rule.check_ingress_port("udp", ingress["forbid_udp_port"])
                rule.check_ingress_all_protocols(ingress["forbid_all_protocols"])
                rule.check_ingress_all_ports(ingress["forbid_all_ports"])

    def check_sg_tags(self, mandatory_tags):
        """Verify if security group has all mandatory tags."""
        sg_tags = self.os_sg.tags
        missing_sg_tags = [i for i in mandatory_tags if i not in sg_tags]

        if missing_sg_tags:
            message = f"{SG_MISSING_TAGS} {', '.join(missing_sg_tags)}"
            self.violations.append(
                Violation(
                    self.project_name,
                    VIOLATION_TYPE,
                    self.name,
                    self.id,
                    self.os_sg.created_at,
                    message,
                )
            )
            LOG.debug("SG id: %s - Violation of sg tags: %s", self.id, message)

    def check_sg_not_used(self, all_used_sgs_ids):
        """Verify if security group is in use."""
        if self.id not in all_used_sgs_ids:
            self.violations.append(
                # pylint: disable=duplicate-code
                Violation(
                    self.project_name,
                    VIOLATION_TYPE,
                    self.name,
                    self.id,
                    self.os_sg.created_at,
                    SG_NOT_USED,
                )
            )
            LOG.debug("SG id: %s - Violation SG not used", self.id)

    def compute_rules_violations(self):
        """Append all security group rules violations."""
        for rule in self.rules:
            if rule.issues:
                message = f"rule id {rule.rule_id} - {', '.join(rule.issues)}"
                violation = Violation(
                    self.project_name,
                    VIOLATION_TYPE,
                    self.name,
                    self.id,
                    self.os_sg.created_at,
                    message,
                )
                if violation not in self.violations:
                    self.violations.append(violation)

    def return_violations(self):
        """Return list with all Violation instances for the security group."""
        self.compute_rules_violations()
        return list(set(self.violations))


# vim: ts=4
