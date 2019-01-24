#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
spacewalk_channel_freeze.py - a tool for freezing patches and errata for systems managed
with Spacewalk and Uyuni

2019 By Christian Stankowic
<info at cstan dot io>
https://github.com/stdevel/spacewalk_channel_freeze
"""

import os
import stat
import getpass
from fnmatch import fnmatch
import logging
import sys
import argparse
import datetime
try:
    # Python 3
    # noinspection PyCompatibility
    from xmlrpc.server import SimpleXMLRPCServer as Server
    # noinspection PyCompatibility
    from xmlrpc.client import Fault
except ImportError:
    # Python 2
    # noinspection PyCompatibility
    import xmlrpclib

# define global variables
__version__ = "0.1.0"
LOGGER = logging.getLogger('spacewalk_channel_freeze')
SYSTEMS = []
CHANNELS = {}
SUPPORTED_API_LEVEL = 12.0


class APILevelNotSupportedException(Exception):
    """
    Class for unsupported API versions
    """
    pass


def check_if_api_is_supported(client):
    """"
    Check whether API is supported

    :param client: Spacewalk client
    :type client: XMLRPC object
    """
    api_level = client.api.getVersion()
    if float(api_level) < SUPPORTED_API_LEVEL:
        raise APILevelNotSupportedException(
            "Your API version ({0}) does not support the required calls. "
            "You'll need API version 12 or higher!".format(api_level)
        )
    else:
        LOGGER.info("Supported API version (%s) found.", api_level)


def get_credentials(cred_type, input_file=None):
    """
    Retrieve credentials from authfile, environment variable or input

    :param cred_type: authentication type (Spacewalk, etc.)
    :type cred_type: str
    :param input_file: authentication file path
    :type input_file: str
    :return: authentication credentials
    """
    # raw_input() was replaced by input() in Python 3
    try:
        input = raw_input
    except NameError:
        pass
    if input_file:
        LOGGER.debug("Using authfile")
        try:
            # check filemode and read file
            filemode = oct(stat.S_IMODE(os.lstat(input_file).st_mode))
            if filemode == "0400":
                LOGGER.debug("File permission matches 0400")
                with open(input_file, "r") as auth_file:
                    s_username = auth_file.readline().replace("\n", "")
                    s_password = auth_file.readline().replace("\n", "")
                return s_username, s_password
            else:
                LOGGER.warning("File permissions (%s) not matching 0400!", filemode)
        except OSError:
            LOGGER.warning("File non-existent or permissions not 0400!")
            LOGGER.debug("Prompting for login credentials as we have a faulty file")
            s_username = input(cred_type + " Username: ")
            s_password = getpass.getpass(cred_type + " Password: ")
            return s_username, s_password
    elif cred_type.upper() + "_LOGIN" in os.environ and \
            cred_type.upper() + "_PASSWORD" in os.environ:
        # shell variables
        LOGGER.debug("Checking shell variables")
        return os.environ[cred_type.upper() + "_LOGIN"], os.environ[cred_type.upper() + "_PASSWORD"]
    else:
        # prompt user
        LOGGER.debug("Prompting for login credentials")
        s_username = input(cred_type + " Username: ")
        s_password = getpass.getpass(cred_type + " Password: ")
        return s_username, s_password


def is_blacklisted(name, target_list):
    """
    Check whether system is blacklisted

    :param name: system name
    :type name: str
    :param target_list: element list
    :type target_list: list
    :return: bool
    """
    for entry in target_list:
        LOGGER.debug("Checking whether %s is blacklisted by *%s*", name, entry)
        if fnmatch(name.lower(), "*{seek}*".format(seek=entry.lower())):
            return True
    return False


def get_channels(client, key):
    """
    Gets all the host

    :param client: Spacewalk client
    :type client: XMLRPC client
    :param key: Spacewalk client authentication
    :type key: Spacewalk client key
    :return: list
    """
    sat_groups = []
    global CHANNELS
    global SYSTEMS

    for item in client.systemgroup.listAllGroups(key):
        sat_groups.append(item["name"])
    LOGGER.debug("This Satellite server's groups: '%s'", sat_groups)
    temp_hosts = []
    for host in options.targetSystems:
        if client.system.getId(key, host):
            temp_hosts.append(host)
        else:
            LOGGER.error("System '%s' appears not to be a valid host", host)
    for group in options.targetGroups:
        if group in sat_groups:
            group_hosts = client.systemgroup.listSystems(key, group)
            for host in group_hosts:
                temp_hosts.append(host["profile_name"])
                LOGGER.debug("Adding system '%s'", host["profile_name"])
        else:
            LOGGER.error("Group '%s' appears not to be a valid group", group)
    # removing blacklisted or hosts without base channel
    for host in temp_hosts:
        host_id = client.system.getId(key, host)
        if is_blacklisted(host, options.exclude):
            LOGGER.debug("System '%s' is blacklisted", host)
        elif not client.system.getSubscribedBaseChannel(key, host_id[0]["id"]):
            LOGGER.error("System '%s' has no base channel", host)
        else:
            LOGGER.debug("Adding valid system '%s'", host)
            SYSTEMS.append(host)
    # list hosts or die in a fire
    if not SYSTEMS:
        LOGGER.info("Nothing to do, giving up!")
        sys.exit(1)
    LOGGER.debug("Validated hosts:")
    for host in SYSTEMS:
        LOGGER.debug(host)

    # get _all_ the software channels
    for host in SYSTEMS:
        # adding base-channel
        LOGGER.debug("Check base-channel for system '%s'", host)
        host_id = client.system.getId(key, host)
        try:
            LOGGER.debug("This system's profile ID: %s", host_id)
            base_channel = client.system.getSubscribedBaseChannel(key, host_id[0]["id"])
            clean_base = base_channel["label"]
            if "." in clean_base:
                clean_base = clean_base[clean_base.find(".") + 1:]
            if clean_base not in CHANNELS:
                # channel non-present
                LOGGER.debug("Adding channel '%s'", clean_base)
                CHANNELS[clean_base] = []
                # adding child channels
                child_channels = client.system.listSubscribedChildChannels(key, host_id[0]["id"])
                for channel in child_channels:
                    clean_child = channel["label"]
                    if "." in clean_child:
                        clean_child = clean_child[clean_child.find(".") + 1:]
                    if clean_child not in CHANNELS[clean_base]:
                        LOGGER.debug("Adding child-channel '%s'", clean_child)
                        CHANNELS[clean_base].append(clean_child)
                # also list non-subscribed channels if wanted
                if options.allSubchannels:
                    child_channels = client.system.listSubscribableChildChannels(
                        key, host_id[0]["id"]
                    )
                    for channel in child_channels:
                        if clean_child not in CHANNELS[clean_base]:
                            LOGGER.debug("Adding non-subscribed child-channel '%s'", clean_child)
                            CHANNELS[clean_base].append(clean_child)
        except IndexError:
            LOGGER.error(
                "Unable to scan system '%s', check hostname, profile name "
                "and whether a base channel was set!",
                host
            )
    # print channel information
    LOGGER.debug("Software channel tree: %s", str(CHANNELS))


def clone_channels(client, key, date, label, unfreeze=False):
    """
    Clone channels

    :param client: Spacewalk client
    :type client: XMLRPC client
    :param key: Spacewalk client authentication
    :type key: Spacewalk client key
    :param date: date prefix
    :type date: str
    :param label: label prefix
    :type label: str
    :param unfreeze: flag whether channels should be cloned/removed
    :type unfreeze: bool
    :return: bool
    """
    if unfreeze:
        # remove clones
        for channel in CHANNELS:
            # remove child-channels
            for child in CHANNELS[channel]:
                if options.dryrun:
                    LOGGER.info(
                        "I'd like to remove cloned child-channel '%s'",
                        label + "-" + date + "." + child
                    )
                else:
                    try:
                        LOGGER.info(
                            "Deleting child-channel '%s'",
                            label + "-" + date + "." + child
                        )
                        client.channel.software.delete(
                            key, label + "-" + date + "." + child
                        )
                    except xmlrpclib.Fault as err:
                        LOGGER.error(
                            "Unable to remove child-channel '%s': '%s'",
                            label + "-" + date + "." + child, err.faultString
                        )
                    except xmlrpclib.ProtocolError as err:
                        LOGGER.error(
                            "Unable to remove child-channel '%s': '%s'",
                            label + "-" + date + "." + child, err.errmsg
                        )
        # remove base-channel
        if options.dryrun:
            LOGGER.info(
                "I'd like to remove cloned base-channel '%s'",
                label + "-" + date + "." + channel
            )
        else:
            try:
                LOGGER.info(
                    "Deleting base-channel '%s'",
                    label + "-" + date + "." + channel
                )
                client.channel.software.delete(
                    key, label + "-" + date + "." + channel
                )
            except xmlrpclib.Fault as err:
                LOGGER.error(
                    "Unable to remove base-channel '%s': '%s'",
                    label + "-" + date + "." + channel, err.faultString
                )
            except xmlrpclib.ProtocolError as err:
                LOGGER.error(
                    "Unable to remove base-channel '%s': '%s'",
                    label + "-" + date + "." + channel, err.errmsg
                )
        return True

    # clone channels
    for channel in CHANNELS:
        # clone base-channels
        my_args = {"name": "Cloned " + channel + " from " + date + " (" + label + ")",
                   "label": label + "-" + date + "." + channel,
                   "summary": "Software channel cloned by satprep"}
        if options.dryrun:
            LOGGER.info(
                "I'd like to clone base-channel '%s' as '%s'",
                channel, label + "-" + date + "." + channel
            )
        else:
            LOGGER.info(
                "Cloning base-channel '%s' as '%s'",
                channel, label + "-" + date + "." + channel
            )
            try:
                result = client.channel.software.clone(key, channel, my_args, False)
                if result != 0:
                    LOGGER.debug("Cloned base-channel")
            except xmlrpclib.Fault as err:
                LOGGER.error("Unable to clone base-channel: %s", err.faultString)
            except xmlrpclib.ProtocolError as err:
                LOGGER.error("Unable to clone base-channel: %s", err.errmsg)

        # clone child-channels
        for child in CHANNELS[channel]:
            my_args = {
                "name": "Cloned " + child + " from " + date,
                "label": label + "-" + date + "." + child,
                "summary": "Software channel cloned by satprep",
                "parent_label": label + "-" + date + "." + channel
            }
            if options.dryrun:
                LOGGER.info(
                    "I'd like to clone child-channel '%s' as '%s'",
                    child, label + "-" + date + "." + child
                )
            else:
                LOGGER.info(
                    "Cloning child-channel '%s' as '%s'",
                    child, label + "-" + date + "." + child
                )
                try:
                    result = client.channel.software.clone(key, child, my_args, False)
                    if result != 0:
                        LOGGER.debug("Cloned child-channel")
                except xmlrpclib.Fault as err:
                    LOGGER.error("Unable to clone base-channel: %s", err.faultString)
                except xmlrpclib.ProtocolError as err:
                    LOGGER.error("Unable to clone base-channel: %s", err.errmsg)


def remap_systems(client, key, unfreeze=False):
    """
    Remap systems

    :param client: Spacewalk client
    :type client: XMLRPC client
    :param key: Spacewalk client authentication
    :type key: Spacewalk client key
    :param unfreeze: flag whether original channels should be used
    :type unfreeze: bool
    """
    if options.noRemap:
        LOGGER.info("Not remapping system's channels")
    else:
        for system in SYSTEMS:
            # remap base-channel
            host_id = client.system.getId(key, system)
            my_base = client.system.getSubscribedBaseChannel(key, host_id[0]["id"])
            if unfreeze:
                my_new_base = my_base["label"]
                my_new_base = my_new_base[my_new_base.find(".") + 1:]
            else:
                my_new_base = options.targetLabel + "-" + options.targetDate + "." + my_base["label"]

            if options.dryrun:
                LOGGER.info(
                    "I'd like to remap %s's base-channel from %s to %s",
                    system, my_base["label"], my_new_base
                )
            else:
                try:
                    LOGGER.debug(
                        "Remapping %s's base-channel from %s to %s",
                        system, my_base["label"], my_new_base
                    )
                    result = client.system.setBaseChannel(key, host_id[0]["id"], my_new_base)
                    if result == 1:
                        LOGGER.debug("Remapped system")
                except xmlrpclib.Fault as err:
                    LOGGER.error(
                        "Unable to change base-channel for system '%s' - '%s - %s'",
                        system, err.faultCode, err.faultString
                    )
                except xmlrpclib.ProtocolError as err:
                    LOGGER.error(
                        "Unable to change base-channel for system '%s' - '%s - %s'",
                        system, err.faultCode, err.faultString
                    )

            # remap child-channels
            child_channels = client.system.listSubscribedChildChannels(key, host_id[0]["id"])
            tmp_channels = []
            for channel in child_channels:
                my_new_channel = channel["label"]
                if unfreeze:
                    # switch back to non-cloned
                    my_new_channel = my_new_channel[my_new_channel.find(".") + 1:]
                else:
                    # switch to cloned
                    my_new_channel = options.targetLabel + "-" + options.targetDate + "." + channel["label"]
                tmp_channels.append(my_new_channel)
            if options.dryrun:
                LOGGER.info(
                    "I'd like to set the following child-channels for %s: %s",
                    system, str(tmp_channels)
                )
            else:
                try:
                    LOGGER.debug(
                        "Setting child-channels for %s: %s",
                        system, str(tmp_channels)
                    )
                    client.system.setChildChannels(key, host_id[0]["id"], tmp_channels)
                except xmlrpclib.Fault:
                    # ignore xmlrpclib.Fault as it works like a charm
                    pass
                except xmlrpclib.ProtocolError as err:
                    LOGGER.error(
                        "Unable to set child-channels (%s) for system '%s' - '%s' - '%s'",
                        str(tmp_channels), system, err.faultCode, err.faultString
                    )
            del tmp_channels


def main(this_options):
    """
    Check/set some necessary information
    :param this_options: program options
    :type this_options: Namespace
    """
    # check/set some necessary information
    if not this_options.targetSystems and not this_options.targetGroups:
        LOGGER.error("You need to specify at least one system or system group!")
        exit(1)
    if this_options.targetDate == "wingardiumleviosa":
        # set current date
        now = datetime.datetime.now()
        this_options.targetDate = now.strftime("%Y-%m-%d")
        LOGGER.debug("Flicked date to: %s", now.strftime("%Y-%m-%d"))
    # split label, systems and groups
    this_options.targetLabel = ''.join(this_options.targetLabel.split()).strip("-").lower()
    if "sp" not in this_options.targetLabel:
        this_options.targetLabel = "sp-" + this_options.targetLabel
    if len(this_options.targetSystems) == 1:
        this_options.targetSystems = str(this_options.targetSystems).strip("[]'").split(",")
    if len(this_options.targetGroups) == 1:
        this_options.targetGroups = str(this_options.targetGroups).strip("[]'").split(",")
    if len(this_options.exclude) == 1:
        this_options.exclude = str(this_options.exclude).strip("[]'").split(",")

    LOGGER.debug("Options: %s", this_options)

    # authenticate against Satellite and check whether supported API found
    (username, password) = get_credentials("Satellite", this_options.authfile)
    satellite_url = "http://{0}/rpc/api".format(this_options.server)
    client = xmlrpclib.Server(satellite_url, verbose=this_options.debug)
    key = client.auth.login(username, password)
    check_if_api_is_supported(client)

    # get channels
    get_channels(client, key)
    if this_options.unfreeze:
        remap_systems(client, key, True)
        clone_channels(client, key, this_options.targetDate, this_options.targetLabel, True)
    else:
        clone_channels(client, key, this_options.targetDate, this_options.targetLabel)
        remap_systems(client, key)


def parse_options():
    """
    Parses options

    :return: list
    """
    # define description, version and load parser
    desc = '''spacewalk_channel_freeze is used to clone software channels managed with Uyuni,
 Spacewalk, Red Hat Satellite 5.x and SUSE Manager to freeze system updates. It automatically
 clones appropriate software channels for particular systems or system groups and also remaps
 software channels to affected hosts. Login credentials are assigned using the following
 shell variables:

SATELLITE_LOGIN  username
SATELLITE_PASSWORD  password

It is also possible to create an authfile (permissions 0400) for usage with this script. The
 first line needs to contain the username, the second line should consist of the appropriate
 password.
 If you're not defining variables or an authfile you will be prompted to enter your login
 information.'''
    epilog = '''Checkout the GitHub page for updates:
 https://github.com/stdevel/spacewalk_channel_freeze'''
    parser = argparse.ArgumentParser(description=desc, epilog=epilog)
    parser.add_argument('--version', action='version', version=__version__)

    # define option groups
    gen_opts = parser.add_argument_group("Generic Options")
    srv_opts = parser.add_argument_group("Server Options")
    sys_opts = parser.add_argument_group("System Options")
    chn_opts = parser.add_argument_group("Channel Options")

    # GENERIC OPTIONS
    # -d / --debug
    gen_opts.add_argument(
        "-d", "--debug", dest="debug", default=False,
        action="store_true", help="enable debugging outputs (default: no)"
    )
    # -n / --dry-run
    gen_opts.add_argument(
        "-n", "--dry-run", action="store_true", dest="dryrun", default=False,
        help="only simulates what would be done (default: no)"
    )
    # -u / --unfreeze
    gen_opts.add_argument(
        "-u", "--unfreeze", action="store_true", dest="unfreeze", default=False,
        help="removes clones and remaps systems (default: no)"
    )

    # SERVER OPTIONS
    # -a / --authfile
    srv_opts.add_argument(
        "-a", "--authfile", dest="authfile", metavar="FILE", default="",
        help="defines an auth file to use instead of shell variables"
    )
    # -s / --server
    srv_opts.add_argument(
        "-s", "--server", dest="server", metavar="SERVER", default="localhost",
        help="defines the server to use (default: localhost)"
    )

    # SYSTEM OPTIONS
    # -S / --system
    sys_opts.add_argument(
        "-S", "--system", action="append", dest="targetSystems", metavar="SYSTEM",
        default=[], help="specifies a system to use for freezing patches"
    )
    # -g / --group
    sys_opts.add_argument(
        "-g", "--group", action="append", dest="targetGroups", metavar="GROUP",
        default=[], help="specifies a system group to use for freezing patches"
    )
    # -e / --exclude
    sys_opts.add_argument(
        "-e", "--exclude", action="append", dest="exclude", metavar="SYSTEM",
        default=[], help="defines hosts that should be excluded for freezing patches"
    )
    # -i / --no-remap
    sys_opts.add_argument(
        "-i", "--no-remap", action="store_true", dest="noRemap", default=False,
        help="disables remapping affected systems to cloned channels (default: no)"
    )

    # CHANNEL OPTIONS
    # -A / --all-subchannels
    chn_opts.add_argument(
        "-A", "--all-subchannels", action="store_true", dest="allSubchannels", default=False,
        help="clones all sub-channels instead of only required ones (default: no)"
    )
    # -l / --label
    chn_opts.add_argument(
        "-l", "--label", action="store", dest="targetLabel", metavar="LABEL", default="sp",
        help="defines a label for the cloned channel (e.g. application name)"
    )
    # -D / --date
    chn_opts.add_argument(
        "-D", "--date", action="store", dest="targetDate", metavar="DATE",
        default="wingardiumleviosa",
        help="defines the date patches should be freezed (default: current date)"
    )

    this_options = parser.parse_args()
    return this_options


if __name__ == "__main__":
    options = parse_options()

    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
        LOGGER.setLevel(logging.DEBUG)
    else:
        logging.basicConfig()
        LOGGER.setLevel(logging.INFO)

    main(options)
