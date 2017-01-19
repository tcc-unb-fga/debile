# Copyright (c) 2013 Paul Tagliamonte <paultag@debian.org>
# Copyright (c) 2013-2014 Sylvestre Ledru <sylvestre@debian.org>
# Copyright (c) 2014 Clement Schreiner <clement@mux.me>
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


# This isn't perfect, but it'll do.

from debian import deb822

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

import datetime as dt
import email.utils
import hashlib
import time
import os
from contextlib import contextmanager
import tempfile

from debile.utils.commands import run_command
from debile.slave.utils import cd, tdir


class MissingChangesFieldException(Exception):
    """ Some field is missing in the DSC file """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return 'Missing {0} field.'.format(self.value)


@contextmanager
def tmpfile():
    lolwut, fd = tempfile.mkstemp()
    try:
        yield fd
    finally:
        os.unlink(fd)


def pool_path(source):
    pfix = ''
    if source.startswith('lib'):
        pfix += source[:4]
    else:
        pfix += source[0]
    pfix += "/" + source
    return pfix


def run(cmd):
    out, err, ret = run_command(cmd)
    if ret != 0:
        print(out, err)
        raise Exception("Command " + ' '.join(cmd) + " failed")
    return out, err


def fetch_and_upload(dist, source, version, **kwargs):
    from . import DEFAULT_MIRROR
    confFile = "/etc/debile-rebuild.ini"
    config = configparser.ConfigParser({'mirror': DEFAULT_MIRROR})
    if not os.path.isfile(confFile):
        raise Exception("Could not find " + confFile)
    config.read([confFile])
    gpg = config.get('config', 'signing-key')
    target = config.get('config', 'dput-target')
    mirror = config.get('config', 'mirror')

    eversion = version
    if ":" in eversion:
        _, eversion = version.rsplit(":", 1)

    if "incoming.debian.org" == mirror:
        DSC_URL = (
            "http://{mirror}/{source}_{version}.dsc".format(
                source=source,
                version=eversion,
                mirror=mirror,
            ))
    else:
        path = pool_path(source)
        DSC_URL = (
            "http://{mirror}/debian/pool/main/"
            "{path}/{source}_{version}.dsc".format(
                path=path,
                source=source,
                version=eversion,
                mirror=mirror,
            ))

    with tdir() as pth:
        with cd(pth):
            _, err, ret = run_command(['dget', '-u', DSC_URL])
            if ret == 0:
                dsc = os.path.basename(DSC_URL)
                try:
                    changes = write_changes(dsc, dist, **kwargs)
                    out, err = run(['debsign', '-k%s' % gpg, dsc])
                    out, err = run(['dput', target, changes])
                except MissingChangesFieldException as e:
                    print('Could not issue rebuild. Missing Changes')
            else:
                print('Could not download %s' % DSC_URL)


def file_info(path):
    for algo, name in [
        ('md5', 'Files'),
        ('sha1', 'Checksums-Sha1'),
        ('sha256', 'Checksums-Sha256')
    ]:
        m = getattr(hashlib, algo)()
        buf = open(path, 'rb').read()
        m.update(buf)
        hhash = m.hexdigest()
        fsize = len(buf)
        yield (algo, name, hhash, fsize, path)


def write_changes(fname, dist, **kwargs):
    changes = forge_changes_file(fname, dist, **kwargs)

    version = changes['Version']
    eversion = version
    if ":" in eversion:
        _, eversion = version.rsplit(":", 1)

    path = '/tmp/{source}_{version}_source.changes'.format(
        source=changes['Source'],
        version=eversion,
    )
    changes.dump(fd=open(path, 'wb'))
    return path


def forge_changes_file(fname, dist, **kwargs):
    dsc = deb822.Dsc(open(fname, 'r'))

    changes = deb822.Changes()
    changes['Format'] = '1.8'
    changes['Date'] = email.utils.formatdate(
        time.mktime(dt.datetime.utcnow().timetuple()), usegmt=True
    )

    for key in [
        'Source', 'Version', 'Maintainer',
        'Checksums-Sha1', 'Checksums-Sha256', 'Files'
    ]:
        if key not in dsc:
            raise MissingChangesFieldException(key)

        changes[key] = dsc[key]

    for algo, key, h, s, f in file_info(fname):
        if algo == 'md5':
            algo = 'md5sum'

        entry = deb822.Deb822Dict()
        entry[algo] = h
        entry['size'] = s
        entry['name'] = f

        changes[key].append(entry)

    for entry in changes['Files']:
        entry['section'] = 'not-implemented'
        entry['priority'] = 'not-implemented'

    changes['Distribution'] = dist
    changes['Urgency'] = 'low'
    changes['Changed-By'] = 'Archive Rebuilder <paultag@debian.org>'
    changes['Architecture'] = 'source'
    changes['Binary'] = 'not implemented either'
    changes['Description'] = """This feature is not implemented.
 This is a pretty damn hard to deal with right now. I might write this
 later."""
    changes['Changes'] = """
 {source} ({version}) {dist}; urgency={urgency}
 .
   * This is a fake ChangeLog entry used by debile to force a rebuild
     on debile.debian.net.""".format(
        source=changes['Source'],
        version=changes['Version'],
        urgency=changes['Urgency'],
        dist=dist,
    )

    for k, v in kwargs.items():
        changes[k] = v

    return changes
