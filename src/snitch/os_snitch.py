# -*- coding: utf-8 -*-
"""os-snitch - OpenStack compliance rules checker."""

import argparse
import logging
import os
import pprint

import openstack

from .notification.notification import create_notification
from .resources.security_group import SecurityGroup
from .resources.server import Server
from .utils.utils import color_dic, read_yaml_file, setup_logging

LOG = setup_logging()


###########################################################################
# Add command line arguments to argparse
###########################################################################
def cli_argparse():
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

    return parser


##############################################################################
# Return a list with all security groups ids used
##############################################################################
def return_all_used_sgs(os_conn):
    all_used_sgs_ids = set()
    for port in os_conn.network.ports(project_id=os_conn.current_project.id):
        if port.security_group_ids:
            all_used_sgs_ids.update(port.security_group_ids)

    return list(all_used_sgs_ids)


#############################################################################
# Check all security group rules
#############################################################################
def check_sg_compliance(os_conn, compliance_rules):
    LOG.debug("%s", pprint.pformat(compliance_rules))

    # If alert_if_not_used option is enabled, get a list with all used sgs
    all_used_sgs_ids = (
        return_all_used_sgs(os_conn) if compliance_rules["alert_if_not_used"] else []
    )

    sgs = []
    for os_sg in os_conn.network.security_groups(project_id=os_conn.current_project.id):
        LOG.debug(
            "%s #########################################################%s",
            color_dic["blue"],
            color_dic["nocolor"],
        )
        if os_sg.id in compliance_rules["ignore_sg_ids"]:
            LOG.debug("Ignoring sg: %s - %s", os_sg.id, os_sg.name)
            continue
        LOG.debug(
            "%s #### Checking rules for sg: %s - %s%s",
            color_dic["blue"],
            os_sg.id,
            os_sg.name,
            color_dic["nocolor"],
        )
        LOG.debug(
            "%s #########################################################%s",
            color_dic["blue"],
            color_dic["nocolor"],
        )

        securitygroup = SecurityGroup(os_conn.current_project.name, os_sg)
        if compliance_rules["alert_if_not_used"]:
            securitygroup.check_sg_not_used(all_used_sgs_ids)
        securitygroup.check_sg_tags(compliance_rules["mandatory_tags"])
        securitygroup.check_egress_rules(compliance_rules["egress"])
        securitygroup.check_ingress_rules(compliance_rules["ingress"])
        sgs.append(securitygroup)

        LOG.debug(
            "%s#### Violation for %s %s%s",
            color_dic["red"],
            os_sg.name,
            securitygroup.return_violations(),
            color_dic["nocolor"],
        )

    return sgs


#############################################################################
# Check all servers rules
#############################################################################
def check_servers_compliance(os_conn, compliance_rules):

    servers = []
    for os_server in os_conn.compute.servers(project_id=os_conn.current_project.id):
        LOG.debug(
            "%s #########################################################%s",
            color_dic["blue"],
            color_dic["nocolor"],
        )
        if os_server.id in compliance_rules["ignore_server_ids"]:
            LOG.debug("Ignoring sg: %s - %s", os_server.id, os_server.name)
            continue
        LOG.debug(
            "%s #### Checking rules for server: %s - %s%s",
            color_dic["blue"],
            os_server.id,
            os_server.name,
            color_dic["nocolor"],
        )
        server = Server(os_conn.current_project.name, os_server)
        server.check_server_tags(compliance_rules["mandatory_tags"])
        server.check_server_metadata(compliance_rules["mandatory_metadata"])
        servers.append(server)

    return servers


##############################################################################
# Send violations
##############################################################################
def send_violations(cmd_options_parsed, violations):
    if not cmd_options_parsed.sendto:
        LOG.debug("Notification system not specified.")
        return

    conf = {"stdout_fmt": cmd_options_parsed.stdout_fmt}

    for i in cmd_options_parsed.sendto:
        LOG.debug("Sending violations to %s", i)
        notification = create_notification(i, **conf)
        notification.send_violations(violations)


##############################################################################
# Main
##############################################################################
def main():

    # disable openstacksdk logs
    openstack.enable_logging(debug=False)

    cmd_options = cli_argparse()
    # openstacksdk parser
    os_conn = openstack.connect(options=cmd_options)

    # parser arguments
    cmd_options_parsed = cmd_options.parse_args()

    if not cmd_options_parsed.debug:
        logging.getLogger("snitch").setLevel(logging.CRITICAL)

    # load compliance rules
    compliance_rules = read_yaml_file(cmd_options_parsed.compliance_file)[
        os_conn.current_project.name
    ]
    LOG.debug("compliance_rules: %s", pprint.pformat(compliance_rules))

    sgs = (
        check_sg_compliance(os_conn, compliance_rules["sg"])
        if "sg" in cmd_options_parsed.resource
        else []
    )
    servers = (
        check_servers_compliance(os_conn, compliance_rules["server"])
        if "server" in cmd_options_parsed.resource
        else []
    )

    # compute all violations into a list
    violations_by_resource = [v.return_violations() for v in sgs + servers]
    violations = [item for elem in violations_by_resource for item in elem]

    send_violations(cmd_options_parsed, violations)


##############################################################################
# Run from command line
##############################################################################
if __name__ == "__main__":
    main()

# vim: ts=4
