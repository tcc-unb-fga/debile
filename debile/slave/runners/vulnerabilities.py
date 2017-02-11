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
from debile.slave.utils import cd
import tempfile
import subprocess
import os


total_modules = 0

def vulnerabilities(dsc, analysis):
    sloc_data_dir = tempfile.mkdtemp()
    source_dir = tempfile.mkdtemp()
    run_command(["dpkg-source", "-x", dsc, source_dir])
    run_command(['sloccount', '--datadir', sloc_data_dir, '--filecount', source_dir])
    print count_modules(sloc_data_dir)
    print(total_modules)

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


if __name__ == '__main__':
    vulnerabilities()

