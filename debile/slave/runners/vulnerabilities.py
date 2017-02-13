# Copyright (c) 2017 David Carlos <ddavidcarlos1392@gmail.com>
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

from debile.utils.commands import run_command
from firehose.model import Message, Info
from debile.slave.utils import cd
import tempfile
import subprocess
import os
import shutil


total_modules = 0

def vulnerabilities(dsc, analysis):
    sloc_data_dir = tempfile.mkdtemp()
    source_dir = tempfile.mkdtemp()
    with cd(source_dir):
        run_command(["dpkg-source", "-x", dsc, 'source-vulnerabilities'])
    run_command(['sloccount', '--datadir', sloc_data_dir, '--filecount', source_dir + '/source-vulnerabilities'])
    count_modules(sloc_data_dir)

    failed = False
    cwe457_info = Info(infoid='cwe457', location=None, message=Message(text=str(cwe457_model())), customfields=None)
    cwe476_info = Info(infoid='cwe476', location=None, message=Message(text=str(cwe476_model())), customfields=None)
    analysis.results.append(cwe476_info)
    analysis.results.append(cwe457_info)

    shutil.rmtree(source_dir)
    return (analysis, '', failed, None, None)


def count_modules(path):
    for root, dirs, files in os.walk(path):
        for _file in files:
            is_ansic(_file, root)


def is_ansic(file_name, root):
    if file_name == 'ansic_list.dat':
        file_path = root + '/' + file_name
        wc_result = subprocess.check_output("wc -l %s" % file_path, shell=True)
        modules = int(wc_result.split(' ')[0])
        global total_modules
        total_modules += modules


def cwe457_model():
    return (-6.466983*10**(-16))*total_modules**3 + (5.603787*10**(-11))*total_modules**2 - (1.639652*10**(-6))*total_modules + (0.02287291)

def cwe476_model():
    return (1.911224*10**(-15))*total_modules**3 - (1.72028*10**(-10))*total_modules**2 + (4.85747*10**(-6))*total_modules - (0.03460173)

def version():
    out, _, ret = run_command(['sloccount', '--version'])
    if ret != 0:
        raise Exception("sloccount is not installed")
    return ('sloccount', out)
