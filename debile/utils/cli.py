# Copyright (c) 2012-2013 Paul Tagliamonte <paultag@debian.org>
# Copyright (c) 2014      Jon Severinsson <jon@severinsson.net>
# Copyright (c) 2015      Lucas Kanashiro <kanashiro.duarte@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

from debile.utils.config import get_config
from debile.utils.xmlrpc import get_proxy
import sys


def _create_slave(proxy, name, pgp, ssl):
    """
        Create a slave:
            debile-remote create-slave <name> <pgp-key> <ssl-cert>
    """

    try:
        pgp = open(pgp, 'r').read()
    except IOError as e:
        print("Error whilst opening OpenPGP public key.")
        print("   %s when trying to open %s" % (str(e), pgp))
        raise

    try:
        ssl = open(ssl, 'r').read()
    except IOError as e:
        print("Error whilst opening SSL client certificate.")
        print("   %s when trying to open %s" % (str(e), ssl))
        raise

    print(proxy.create_builder(name, pgp, ssl, None))


def _create_slave_ip(proxy, name, pgp, ip):
    """
        Create a slave using simple authentication:
            debile-remote create-slave-ip <name> <pgp-key> <ip address>
    """

    try:
        pgp = open(pgp, 'r').read()
    except IOError as e:
        print("Error whilst opening OpenPGP public key.")
        print("   %s when trying to open %s" % (str(e), pgp))
        raise

    print(proxy.create_builder(name, pgp, None, ip))


def _update_slave_keys(proxy, name, pgp, ssl):
    """
        Replace the pgp public key and ssl certificate of a slave:
            debile-remote update-slave-keys <name> <pgp-key> <ssl-cert>
    """

    try:
        pgp = open(pgp, 'r').read()
    except IOError as e:
        print("Error whilst opening OpenPGP public key.")
        print("   %s when trying to open %s" % (str(e), pgp))
        raise

    try:
        ssl = open(ssl, 'r').read()
    except IOError as e:
        print("Error whilst opening SSL client certificate.")
        print("   %s when trying to open %s" % (str(e), ssl))
        raise

    print(proxy.update_builder_keys(name, pgp, ssl))


def _disable_slave(proxy, name):
    """
        Prevent a slave from being able to authenticate with the master:
            debile-remote disable-slave <name>
    """

    print(proxy.disable_builder(name))


def _create_user(proxy, name, email, pgp, ssl):
    """
    Create a user:
        debile-remote create-user <name> <email> <pgp-key> <ssl-cert>
    """

    try:
        pgp = open(pgp, 'r').read()
    except IOError as e:
        print("Error whilst opening OpenPGP public key.")
        print("   %s when trying to open %s" % (str(e), pgp))
        raise

    try:
        ssl = open(ssl, 'r').read()
    except IOError as e:
        print("Error whilst opening SSL client certificate.")
        print("   %s when trying to open %s" % (str(e), ssl))
        raise

    print(proxy.create_user(name, email, pgp, ssl, None))


def _create_user_ip(proxy, name, email, pgp, ip):
    """
    Create a user with simple authentication:
        debile-remote create-user-ip <name> <email> <pgp-key> <ip-address>
    """

    try:
        pgp = open(pgp, 'r').read()
    except IOError as e:
        print("Error whilst opening OpenPGP public key.")
        print("   %s when trying to open %s" % (str(e), pgp))
        raise

    print(proxy.create_user(name, email, pgp, None, ip))


def _update_user_keys(proxy, email, pgp, ssl):
    """
        Replace the pgp public key and ssl certificate of a user:
            debile-remote update-user-keys <email> <pgp-key> <ssl-cert>
    """

    try:
        pgp = open(pgp, 'r').read()
    except IOError as e:
        print("Error whilst opening OpenPGP public key.")
        print("   %s when trying to open %s" % (str(e), pgp))
        raise

    try:
        ssl = open(ssl, 'r').read()
    except IOError as e:
        print("Error whilst opening SSL client certificate.")
        print("   %s when trying to open %s" % (str(e), ssl))
        raise

    print(proxy.update_user_keys(email, pgp, ssl))


def _disable_user(proxy, email):
    """
        Prevent a user from being able to authenticate with the master:
            debile-remote disable-user <email>
    """

    print(proxy.disable_user(email))


def _rerun_job(proxy, job_id):
    """
    Re-runs a specified job:
        debile-remote rerun-job <job-id>
    """

    print(proxy.rerun_job(job_id))


def _rerun_check(proxy, name):
    """
    Re-runs all jobs for a specified check:
        debile-remote rerun-check <check-name>
    """

    print(proxy.rerun_check(name))


def _retry_failed(proxy):
    """
    Re-tries all failed build jobs:
        debile-remote retry-failed
    """

    print(proxy.retry_failed())


def _set_check(proxy, check, *args):
    """
    Add a check to the database or configure an existing one:
        debile-remote set-check <check-name> [source] [binary] [build]
    """
    print(proxy.set_check(check, *args))


def _enable_check(proxy, check, group, suite):
    """
    Enable a check for a given group/suite
        debile-remote enable-check <check> <group> <suite>
    """
    print(proxy.enable_check(check, group, suite))


def _list_checks(proxy, *args):
    """
    List checks
        debile-remote list-checks
    """
    print(proxy.list_checks(*args))


def _help():
    print("Commands:")
    for command in COMMANDS:
        print("  %s - %s" % (command, COMMANDS[command].__doc__))


COMMANDS = {
    "create-slave": _create_slave,
    "create-slave-ip": _create_slave_ip,
    "update-slave-keys": _update_slave_keys,
    "disable-slave": _disable_slave,
    "create-user": _create_user,
    "create-user-ip": _create_user_ip,
    "update-user-keys": _update_user_keys,
    "disable-user": _disable_user,
    "rerun-job": _rerun_job,
    "rerun-check": _rerun_check,
    "retry-failed": _retry_failed,
    "enable-check": _enable_check,
    "list-checks": _list_checks,
    "set-check": _set_check,

}


def main():
    args = list(sys.argv[1:])
    command = args.pop(0)
    try:
        run = COMMANDS[command]
    except KeyError:
        return _help()

    config = get_config("user.yaml")
    xml = config.get('xmlrpc')
    auth_method = 'ssl'
    if xml is not None:
        auth_method = xml.get('auth_method', 'ssl')

    proxy = get_proxy(config, auth_method)

    return run(proxy, *args)
