# Copyright (c) 2012-2013 Paul Tagliamonte <paultag@debian.org>
# Copyright (c) 2013 Leo Cavaille <leo@cavaille.net>
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

from firehose.model import Issue, Message, File, Location, Point
import lxml.etree

# We require:
# cppcheck --enable=all . --xml 1>/dev/null  ( stderr )


def parse_cppcheck(payload):
    tree = lxml.etree.fromstring(payload.encode('utf-16'))

    locations = tree.xpath("//results/errors/error/location")
    locations_index = 0
    for result in tree.xpath("//results/errors/error"):
        if 'file' not in locations[locations_index].attrib:
            continue

        path = locations[locations_index].attrib['file']
        line = locations[locations_index].attrib['line']
        severity = result.attrib['severity']
        message = result.attrib['msg']
        testid = result.attrib['id']
        if 'cwe' in result.attrib:
            cwe = int(result.attrib['cwe'])
        else:
            cwe = None

        locations_index += 1

        yield Issue(cwe=cwe,
                    testid=testid,
                    location=Location(
                        file=File(path, None),
                        function=None,
                        point=Point(int(line), 0) if line else None),
                    severity=severity,
                    message=Message(text=message),
                    notes=None,
                    trace=None)
