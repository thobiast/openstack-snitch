# -*- coding: utf-8 -*-
"""os-snitch - OpenStack compliance rules checker."""

import argparse
import logging
import os
import pprint
import sys
from dataclasses import dataclass
from typing import Any

import openstack
from pydantic import ValidationError

from .notification.notification import create_notification
from .resources.security_group import SecurityGroup
from .resources.server import Server
from .utils.rules_schema import ComplianceRules, ProjectPolicy
from .utils.utils import setup_logging


@dataclass(frozen=True)
class RunContext:
    """
    Execution context shared across checks.

    Holds the selected project policy, an OpenStack connection, and
    parsed command-line arguments.
    """

    project_policy: ProjectPolicy
    os_conn: Any
    args: argparse.Namespace


###########################################################################
# Add command line arguments to argparse
###########################################################################
def parse_args():
    epilog = """
    Example of use:
        %(prog)s --help
        %(prog)s --resource server
        %(prog)s --resource server --compliance-file ./myrules/compliance_rules.yaml
        %(prog)s --resource server sg
        %(prog)s --resource server sg --sendto influxdb
        %(prog)s --resource server --sendto stdout influxdb
    """

    parser = argparse.ArgumentParser(
        description="os-snitch",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
    )
    parser.add_argument("--debug", action="store_true", dest="debug", help="debug flag")
    parser.add_argument(
        "--os-cloud",
        help=(
            "Name of the cloud to load from clouds.yaml. "
            "(Default '%(default)s', which uses OS_* env vars)"
        ),
        type=str,
        default="envvars",
        required=False,
    )
    parser.add_argument(
        "--compliance-file",
        dest="compliance_file",
        default=os.path.dirname(os.path.abspath(__file__)) + "/compliance_rules.yaml",
        help="Yaml file with the compliance rules (default: %(default)s)",
    )
    parser.add_argument(
        "--resource",
        nargs="+",
        required=True,
        choices=["sg", "server"],
        help="Check compliance rules for which OpenStack resource",
    )
    parser.add_argument(
        "--sendto",
        nargs="*",
        default=["stdout"],
        choices=["influxdb", "stdout"],
        help="Send violations found to",
    )
    parser.add_argument(
        "--stdout-fmt",
        nargs="?",
        default="table",
        choices=("table", "dict"),
        help="Format to show violation on stdout",
    )

    return parser.parse_args()


##############################################################################
# Return a list with all security groups ids used
##############################################################################
def get_used_security_group_ids(ctx):
    """Return security group IDs currently in use by the project.

    Args:
        ctx: RunContext

    Returns:
        list: Unique security group IDs used by at least one port in the project.
    """
    logging.debug("Getting all security groups in use")

    all_used_sgs_ids = set()
    for port in ctx.os_conn.network.ports(project_id=ctx.os_conn.current_project.id):
        if port.security_group_ids:
            all_used_sgs_ids.update(port.security_group_ids)

    return list(all_used_sgs_ids)


#############################################################################
# Check all security group rules
#############################################################################
def check_sg_compliance(ctx):
    """Validate security groups in the project against the configured policy.

    For each security group in the project:
      - Skips ignored security group IDs.
      - Validates mandatory tags.
      - Optionally flags unused security groups (alert_if_not_used).
      - Validates rule-level constraints

    Args:
        ctx: RunContext

    Returns:
        list: A flat list of Violation objects describing all issues found.
    """
    project_sg_rules = ctx.project_policy.sg
    if project_sg_rules is None:
        logging.warning(
            "Skipping sg: no policy defined for project %s",
            ctx.os_conn.current_project.name,
        )
        return []

    logging.info(
        "Starting Security Group compliance for project: %s",
        ctx.os_conn.current_project.name,
    )
    logging.debug("Policy: %s", project_sg_rules.model_dump())

    # If alert_if_not_used option is enabled, get a list with all used sgs
    used_sg_ids = (
        set(get_used_security_group_ids(ctx))
        if project_sg_rules.alert_if_not_used
        else set()
    )

    all_violations = []
    for os_sg in ctx.os_conn.network.security_groups(
        project_id=ctx.os_conn.current_project.id
    ):
        if os_sg.id in project_sg_rules.ignore_sg_ids:
            logging.debug("--- Skipping SG (ignored ID): %s (%s)", os_sg.name, os_sg.id)
            continue

        logging.info("--- Validating Security Group: %s (%s)", os_sg.name, os_sg.id)

        securitygroup = SecurityGroup(ctx.os_conn.current_project.name, os_sg)
        # Pass data via the specific resource context
        securitygroup.check_compliance(
            project_sg_rules, context={"used_sg_ids": used_sg_ids}
        )

        violations = securitygroup.get_violations()
        all_violations.extend(violations)

        if violations:
            logging.debug("SG %s: found %d violations", os_sg.name, len(violations))
        else:
            logging.debug("SG %s: compliant", os_sg.name)

    logging.info(
        "Security Groups compliance check complete. Total violations found: %d",
        len(all_violations),
    )
    return all_violations


#############################################################################
# Check all servers rules
#############################################################################
def check_servers_compliance(ctx):
    """Validate servers in the project against the configured policy.

    For each server in the project:
      - Skips ignored server IDs.
      - Validates mandatory tags.
      - Validates mandatory metadata keys, if configured.

    Args:
        ctx: RunContext

    Returns:
        list: A flat list of Violation objects describing all issues found.
    """
    project_server_rules = ctx.project_policy.server
    if project_server_rules is None:
        logging.warning(
            "Skipping server: no policy defined for project %s",
            ctx.os_conn.current_project.name,
        )
        return []

    logging.info(
        "Starting server compliance for project: %s", ctx.os_conn.current_project.name
    )
    logging.debug("Policy: %s", project_server_rules.model_dump())

    all_violations = []
    for os_server in ctx.os_conn.compute.servers(
        project_id=ctx.os_conn.current_project.id
    ):

        if os_server.id in project_server_rules.ignore_server_ids:
            logging.debug(
                "--- Skipping server (ignored ID): %s (%s)",
                os_server.name,
                os_server.id,
            )
            continue

        logging.info("--- Validating Server:: %s (%s)", os_server.name, os_server.id)

        server = Server(ctx.os_conn.current_project.name, os_server)
        server.check_compliance(project_server_rules)

        violations = server.get_violations()
        all_violations.extend(violations)

        if violations:
            logging.debug(
                "Server %s: found %d violations", os_server.name, len(violations)
            )
        else:
            logging.debug("Server %s: compliant", os_server.name)

    logging.info(
        "Server compliance check complete. Total violations found: %d",
        len(all_violations),
    )
    return all_violations


##############################################################################
# Send violations
##############################################################################
def send_violations(ctx, violations):
    """Send violations to configured notification backends.

    Notification backends are selected via CLI.

    Args:
        ctx: RunContext
        violations: List of Violation objects to be sent.
    """
    if not ctx.args.sendto:
        logging.debug("Notification system not specified.")
        return

    conf = {"stdout_fmt": ctx.args.stdout_fmt}

    for i in ctx.args.sendto:
        logging.debug("Sending violations to %s", i)
        notification = create_notification(i, **conf)
        notification.send_violations(violations)


##############################################################################
# Main
##############################################################################
def main():
    """
    Main entry point for the script.
    """

    args = parse_args()
    setup_logging(log_level=logging.DEBUG if args.debug else logging.INFO)
    logging.debug("CMD line args: %s", args)

    # Load and validate rules
    try:
        rules = ComplianceRules.from_yaml_file(args.compliance_file)
    except ValidationError as e:
        logging.error("Invalid compliance rules:\n%s", e)
        sys.exit(2)
    # pylint: disable=broad-exception-caught
    except Exception as e:
        logging.error("Failed to load compliance rules: %s", e)
        sys.exit(2)

    # Connect to OpenStack
    openstack.enable_logging(debug=False)
    logging.debug("Create openstack connect to cloud: '%s'", args.os_cloud)
    try:
        os_conn = openstack.connect(cloud=args.os_cloud)
        project_name = os_conn.current_project.name
    except Exception as exc:
        logging.debug("Openstack connection configuration failed:", exc_info=True)
        raise RuntimeError(f"Failed to connect to OpenStack: {exc}") from exc

    # Check if there is policy defined for the project
    if project_name not in rules.root:
        logging.warning("No policy defined for project: %s", project_name)
        return

    ctx = RunContext(
        os_conn=os_conn, args=args, project_policy=rules.root[project_name]
    )
    logging.debug(
        "project_policy for project %s: %s",
        project_name,
        pprint.pformat(ctx.project_policy),
    )

    # Execute checks
    violations = []
    if "sg" in args.resource:
        violations.extend(check_sg_compliance(ctx))
    if "server" in args.resource:
        violations.extend(check_servers_compliance(ctx))

    send_violations(ctx, violations)


##############################################################################
# Run from command line
##############################################################################
if __name__ == "__main__":
    main()

# vim: ts=4
