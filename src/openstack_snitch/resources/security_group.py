# -*- coding: utf-8 -*-
"""Module to handle security group compliance checks."""

import ipaddress
import logging

from ..violation.violation import ViolationCode
from .base_resource import BaseResource


class SecurityGroup(BaseResource):
    """Compliance checker for Neutron security groups.

    Evaluates the security group object itself (e.g., tags and usage) as well as
    its individual rules (e.g., CIDR and port restrictions).
    """

    def __init__(self, project_name, os_sg):
        """Create a security group compliance checker for one security group.

        Args:
            project_name: Name of the OpenStack project being checked.
            os_sg: OpenStack SDK security group object.
        """
        super().__init__(project_name, os_sg, "SG")

    def check_compliance(self, rules, *, context=None):
        """Run all configured security group checks.

        High-level checks:
          - Mandatory tags.
          - Optional "not used" alert based on used security group IDs.
          - Maximum rules per security group.
          - Per-rule validation for ingress/egress based on the direction policy.

        Args:
            rules: Security group policy section loaded from compliance rules.
            context: Optional dict containing extra information for checks.
                Expected keys:
                  - used_sg_ids: Set of security group IDs referenced by ports.
        """
        policy_sg = rules
        # Default context to an empty dict
        context = context or {}
        used_sg_ids = context.get("used_sg_ids", set())

        logging.info("Checking SG: %s", self.id)

        # SG tag policy
        self._check_mandatory_tags(
            policy_sg.mandatory_tags, ViolationCode.SG_MISSING_TAG
        )

        # SG not used policy
        if policy_sg.alert_if_not_used and self.id not in used_sg_ids:
            self.add_violation(ViolationCode.SG_NOT_USED, details={})

        sg_rules = self.os_resource.security_group_rules or []

        # SG max rules
        total_rules = len(sg_rules)
        logging.debug("SG %s has %s rules", self.id, total_rules)
        if policy_sg.max_rules_per_sg and total_rules > policy_sg.max_rules_per_sg:
            self.add_violation(
                ViolationCode.SG_TOO_MANY_RULES,
                details={
                    "num_rules": total_rules,
                    "max_rules_per_sg": policy_sg.max_rules_per_sg,
                },
            )

        # Per rule check
        for sg_rule in sg_rules:
            direction = sg_rule.get("direction")

            dir_policy = getattr(policy_sg, direction, None)
            if dir_policy:
                self._validate_single_rule(sg_rule, dir_policy, direction=direction)
            else:
                logging.debug("No rules for %s", direction)

    def _validate_single_rule(self, sg_rule, dir_policy, direction):
        """Validate an individual security group rule against direction policy.

        Evaluates this rule against the direction policy and records violations
        for each constraint that is triggered.

        Rules referencing a remote_group_id skip CIDR and netmask checks since the
        address scope is defined by the remote group instead of a CIDR.

        Args:
            sg_rule: The OpenStack SDK rule object (or dictionary).
            dir_policy: Direction-specific policy (ingress/egress) from the rules file.
            direction: The traffic direction string ("ingress" or "egress").
        """
        rule_id = sg_rule.get("id", "<unknown>")
        proto = sg_rule.get("protocol")
        logging.debug("Processing rule %s (%s %s)", rule_id, proto, direction)

        common = {
            "rule_id": rule_id,
            "direction": direction,
            "protocol": proto or "any",
        }

        checks = []

        # CIDR and netmask size checks
        if sg_rule.get("remote_group_id"):
            # pass if SG permit access for a remote_group_id
            logging.debug(
                "Rule %s: skipping CIDR/netmask checks (remote_group_id present)",
                rule_id,
            )
        else:
            # pylint: disable=W0511
            # TODO: If remote_address_group_id is defined, it needs to check the address in address
            # group
            remote_ip_prefix = sg_rule.get("remote_ip_prefix") or "0.0.0.0/0"
            # pylint: disable=E1121
            checks += [
                # check forbid_cidrs
                (
                    ViolationCode.SG_RULE_FORBIDDEN_CIDR,
                    self._check_forbidden_cidr(sg_rule, dir_policy, remote_ip_prefix),
                ),
                # check max_netmask_allowed
                (
                    ViolationCode.SG_RULE_NETMASK_TOO_BROAD,
                    self._check_max_netmask_allowed(
                        sg_rule, dir_policy, remote_ip_prefix
                    ),
                ),
                # check deny ports per cidr
                (
                    ViolationCode.SG_RULE_DENY_PORTS_PER_CIDR,
                    self._check_deny_ports_per_cidr(
                        sg_rule, dir_policy, remote_ip_prefix
                    ),
                ),
            ]

        # pylint: disable=E1121
        checks += [
            # check forbid_protocols_any
            (
                ViolationCode.SG_RULE_ANY_PROTOCOL,
                self._check_forbid_protocols_any(sg_rule, dir_policy),
            ),
            # check forbid_ports_any
            (
                ViolationCode.SG_RULE_ANY_PORTS,
                self._check_forbid_ports_any(sg_rule, dir_policy),
            ),
            # check forbid_ports
            (
                ViolationCode.SG_RULE_FORBIDDEN_PORT,
                self._check_forbid_ports(sg_rule, dir_policy),
            ),
            # check max_ports_per_rule
            (
                ViolationCode.SG_RULE_TOO_MANY_PORTS,
                self._check_max_ports_per_rule(sg_rule, dir_policy),
            ),
        ]

        for code, hit in checks:
            self._add_if_hit(code, common, hit)

    def _check_forbid_ports(self, sg_rule, dir_policy):
        """Check whether the rule allows any explicitly forbidden ports.

        Applies only to TCP/UDP rules. If the rule covers any port in the forbidden
        list for the relevant protocol, returns details describing the overlap.

        Args:
            sg_rule: Security group rule dict.
            dir_policy: Direction policy with forbid_ports configuration.

        Returns:
            dict or None: Details when forbidden ports are matched, otherwise None.
        """
        proto = sg_rule.get("protocol")
        if proto not in ("tcp", "udp"):
            return None

        forbidden = (
            dir_policy.forbid_ports.tcp
            if proto == "tcp"
            else dir_policy.forbid_ports.udp
        )
        if not forbidden:
            return None

        p_min, p_max = self._get_port_range(sg_rule)

        # If p_min is None, it's an 'all ports' rule, which is handled by _any check
        # However, for this specific method, an 'all ports' rule implies it contains forbidden ports
        if p_min is None:
            hits = forbidden
        else:
            hits = sorted([f_port for f_port in forbidden if p_min <= f_port <= p_max])

        if hits:
            return {
                "port_min": p_min,
                "port_max": p_max,
                "matched_ports": hits,
            }

        return None

    def _check_forbid_ports_any(self, sg_rule, dir_policy):
        """Check whether the rule allows any ports when the policy forbids it.

        If forbid_ports_any is enabled, a TCP/UDP rule with no port_range_min/max is
        considered an "any ports" rule. ICMP rules are ignored for this check.

        Args:
            sg_rule: Security group rule dict.
            dir_policy: Direction policy with forbid_ports_any flag.

        Returns:
            dict or None: Details when the rule is "any ports", otherwise None.
        """
        if sg_rule.get("protocol") == "icmp":
            return None

        if not dir_policy.forbid_ports_any:
            return None

        p_min, p_max = self._get_port_range(sg_rule)
        if p_min is None:
            return {"port_min": p_min, "port_max": p_max, "any_ports": True}

        return None

    def _check_forbid_protocols_any(self, sg_rule, dir_policy):
        """Check whether the rule allows any protocol when the policy forbids it.

        If forbid_protocols_any is enabled, a rule with protocol unset (or "any")
        is considered an "any protocol" rule.

        Args:
            sg_rule: Security group rule dict.
            dir_policy: Direction policy with forbid_protocols_any flag.

        Returns:
            dict or None: Details when the rule is "any protocol", otherwise None.
        """
        if not dir_policy.forbid_protocols_any:
            return None

        proto = sg_rule.get("protocol")
        if proto in (None, "any"):
            return {"any_protocol": True}

        return None

    def _check_max_ports_per_rule(self, sg_rule, dir_policy):
        """Check whether the rule spans too many ports.

        Applies to non-ICMP rules when max_ports_per_rule is configured. Rules that
        allow all ports (no port_range_min) are treated as spanning an unknown count
        and will be reported with num_ports=None.

        Args:
            sg_rule: Security group rule dict.
            dir_policy: Direction policy with max_ports_per_rule limit.

        Returns:
            dict or None: Details when the rule exceeds the limit, otherwise None.
        """
        if dir_policy.max_ports_per_rule is None:
            return None

        if sg_rule.get("protocol") == "icmp":
            return None

        port_min, port_max = self._get_port_range(sg_rule)
        if port_min is None:
            return {
                "port_min": port_min,
                "port_max": port_max,
                "num_ports": None,
                "max_ports_per_rule": dir_policy.max_ports_per_rule,
            }

        num_ports = (port_max + 1) - port_min
        if num_ports > dir_policy.max_ports_per_rule:
            return {
                "port_min": port_min,
                "port_max": port_max,
                "num_ports": num_ports,
                "max_ports_per_rule": dir_policy.max_ports_per_rule,
            }

        return None

    def _check_max_netmask_allowed(self, dir_policy, remote_ip_prefix):
        """Check whether a rule's remote CIDR is broader than allowed.

        When max_netmask_allowed is set, the rule's remote CIDR must not be broader
        (smaller prefix length) than the configured limit.

        Args:
            dir_policy: Direction policy with max_netmask_allowed.
            remote_ip_prefix: Rule remote_ip_prefix string or a default.

        Returns:
            dict or None: Details when the CIDR is too broad, otherwise None.
        """
        limit = dir_policy.max_netmask_allowed
        if limit is None:
            return None

        net = ipaddress.ip_network(remote_ip_prefix, strict=False)

        # Adjust limit for IPv4 sanity check
        effective_limit = 32 if (net.version == 4 and limit > 32) else limit

        if net.prefixlen < effective_limit:
            return {
                "cidr": str(net),
                "prefixlen": int(net.prefixlen),
                "max_netmask_allowed": effective_limit,
            }

        return None

    def _check_forbidden_cidr(self, dir_policy, remote_ip_prefix):
        """Check whether a rule's remote CIDR matches any forbidden CIDR policy entry.

        Matching behavior depends on the policy entry mode (exact vs overlap).

        Args:
            dir_policy: Direction policy containing forbid_cidrs entries.
            remote_ip_prefix: Rule remote_ip_prefix string.

        Returns:
            dict or None: Details when forbidden CIDRs match, otherwise None.
        """
        if not dir_policy.forbid_cidrs:
            return None

        remote_net = ipaddress.ip_network(remote_ip_prefix, strict=False)
        hits = []

        for f_cidr_item in dir_policy.forbid_cidrs:
            forbidden_net = f_cidr_item.cidr  # IPvAnyNetwork
            mode = f_cidr_item.match.value

            if self._network_matches(remote_net, forbidden_net, mode):
                hits.append(
                    {
                        "forbidden_cidr": str(forbidden_net),
                        "match": mode,
                    }
                )

        if hits:
            return {
                "remote_cidr": str(remote_net),
                "matches": hits,
            }

        return None

    def _check_deny_ports_per_cidr(self, sg_rule, dir_policy, remote_ip_prefix):
        """Check deny_ports_per_cidr policy for TCP/UDP rules.

        For each policy entry (CIDR + match mode + TCP/UDP port lists):
          - If the rule's remote CIDR matches the policy CIDR (exact/overlap), and
          - The rule's port range intersects the denied ports for the rule protocol,
        then this check returns details describing the matched policy entry and ports.

        "All ports" rules (no port_range_min) are treated as matching all denied ports.

        Args:
            sg_rule: Security group rule dict.
            dir_policy: Direction policy containing deny_ports_per_cidr entries.
            remote_ip_prefix: Rule remote_ip_prefix string.

        Returns:
            dict or None: Details when denied ports match, otherwise None.
        """
        policy = getattr(dir_policy, "deny_ports_per_cidr", None)
        if not policy:
            return None

        proto = sg_rule.get("protocol")
        if proto not in ("tcp", "udp"):
            return None

        remote_net = ipaddress.ip_network(remote_ip_prefix, strict=False)

        # Determine rule port range
        p_min, p_max = self._get_port_range(sg_rule)

        matches = []

        for item in policy:
            forbidden_net = item.cidr
            mode = item.match.value  # "exact" or "overlap"

            if not self._network_matches(remote_net, forbidden_net, mode):
                continue

            # Get denied ports for this protocol
            denied_ports = item.tcp if proto == "tcp" else item.udp
            if not denied_ports:
                continue

            # If SG rule is "all ports" (port_min is None), it reports all denied ports
            if p_min is None:
                hits = sorted(denied_ports)
            else:
                hits = sorted(p for p in denied_ports if p_min <= int(p) <= p_max)

            if hits:
                matches.append(
                    {
                        "policy_cidr": str(forbidden_net),
                        "match": mode,
                        "matched_ports": hits,
                        "port_min": p_min,
                        "port_max": p_max,
                    }
                )

        if matches:
            return {
                "remote_cidr": str(remote_net),
                "matches": matches,
            }

        return None

    def _get_port_range(self, sg_rule):
        """Normalize OpenStack port range fields into a consistent tuple.

        Args:
            sg_rule: Security group rule dict.

        Returns:
            tuple: (port_min, port_max) as integers when defined.
                   Returns (None, None) when the rule represents "all ports".
        """
        p_min = sg_rule.get("port_range_min")
        p_max = sg_rule.get("port_range_max")

        if p_min is None:
            return None, None

        return int(p_min), int(p_max or p_min)

    def _network_matches(self, network_a, network_b, mode):
        """Evaluate CIDR match according to policy mode.

        Args:
            network_a: ipaddress network derived from the rule CIDR.
            network_b: ipaddress network derived from the policy CIDR.
            mode: Matching mode string ("exact" or "overlap").

        Returns:
            bool: True when the networks match according to the mode, else False.
        """
        if mode == "overlap":
            return network_a.overlaps(network_b)
        return network_a == network_b

    def _add_if_hit(self, code, common, hit):
        """Add a violation when a check reports a match.

        This helper normalizes the "hit" contract used by rule checks:

          - hit is None: the check did not match -> no violation is added.
          - hit is a dict (including {}): the check matched -> a violation is added.
            The violation details are built from `common` plus any keys in `hit`.

        Args:
            code: ViolationCode to record when the check matches.
            common: Dict with fields shared across rule violations (e.g. rule_id,
                direction, protocol).
            hit: None for "no match", or a dict describing the match. An empty dict
                means "matched, but no extra details".

        Returns:
            bool: True if a violation was recorded, otherwise False.
        """
        if hit is None:
            return False

        self.add_violation(violationcode=code, details={**common, **hit})
        return True


# vim: ts=4
