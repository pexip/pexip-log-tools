#!/usr/bin/env python3

# Copyright 2023 Pexip AS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# pexsnap: process Pexip snapshots.
#
# usage: pexsnap.py [-h] [-s] [dir]
#
# optional arguments:
#   -h, --help              show this help message and exit
#   -s, --skip              skip confhistory and logreader processing
#   dir                     directory to extract the snapshot
#
# Disable "Invalid constant name"                       pylint: disable=C0103
# Disable "Line too long"                               pylint: disable=C0301
# Disable "Too many lines in module"                    pylint: disable=C0302
# Disable "Missing docstring"                           pylint: disable=C0111
# Disable "Too many branches"                           pylint: disable=R0912
# Disable "Too many statements"                         pylint: disable=R0915
# Disable "Unnecessary parens"                          pylint: disable=C0325

import argparse
from datetime import datetime
import fileinput
import glob
import json
import os
try:
    import pexdesk
    autokey = True
except:
    autokey = False
    pass
import re
import subprocess
import sys
import tarfile
from getpass import getpass
from os.path import expanduser, isfile, join
sys.path.append(expanduser('~/pexscripts'))
script_location=expanduser('~/pexscripts')

# Extract snapshot to pre-defined directory - will be used if 'dir' argument is passed
parsed_snaps = expanduser('~/Downloads/snapshots')

# setup variables
develop = 'unified_developer.log'
support = 'unified_support.log'
usyslog = 'unified_syslog.log'

irregularpulsetext = 'pex_health_irregular_pulse.log'
irregularpingstext = 'pex_health_irregular_ping.log'
rectorstallingtext = 'pex_health_reactor_stalling.log'
numaconfigurattext = 'pex_health_numa_nodes.log'
e1adapteresetstext = 'pex_health_adapter_resets.log'

actuallogdir = '/var/log/'
parsedlogdir = '/var/log/parsed/'

atom_path = '/Applications/Atom.app/Contents/MacOS/Atom'
code_path = '/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code'
subl_path = '/Applications/Sublime Text.app/Contents/SharedSupport/bin/subl'

external_scripts = {
    'conference_history': {
        'logfile':'pex_report_confhistory.log',
        'script':script_location+'/confhistory.py'
    },
    'connectivity': {
        'logfile':'pex_health_connectivity_report.log',
        'script':script_location+'/connectivity.py'
    },
    'dbsummary': {
        'logfile':'pex_report_dbreport.log',
        'script':script_location+'/dbsummary.py'
    },
    'dual_int_summary': {
        'logfile':'pex_report_dual_int_summary.log',
        'script':script_location+'/staticroutes.py'
    },
    'hitcounter': {
        'logfile':'pex_report_hitcounter.log',
        'script':script_location+'/pexhitcounter.py'
    },
    'logreader': {
        'logfile':'pex_report_logreader.log',
        'script':script_location+'/logreader.py'
    },
    'mjx_summary': {
        'logfile':'pex_report_mjxsummary.log',
        'script':script_location+'/mjxsummary.py'
    },
    'vmotion': {
        'logfile':'pex_health_vmotionreport.log',
        'script':script_location+'/vmotion.py'
    },
    'webapps': {
        'logfile':'pex_report_webapps.log',
        'script':script_location+'/pexwebapps.py'
    }
}

config_file = expanduser('~/pexscripts')+'/pexsnap.json'

if isfile(config_file):
    try:
        load_config = json.load(open(config_file))
    except:
        print('Error loading configuration file, please manually remove '+config_file+' and try again.')
        sys.exit(2)
else:
    while True:
        open_in_editor = input('Open the parsed files in an editor once complete? ([y]es or [n]o):').lower().strip()
        if open_in_editor[0] == 'y':
            select_editor = input('Please select an editor ([a]tom/vs[c]ode/[s]ublime:').lower().strip()
            if select_editor[0] == 'a':
                save_config = {'open_in_atom' : True, 'open_in_code' : False, 'open_in_subl' : False}
                break
            elif select_editor[0] == 'c':
                save_config = {'open_in_atom' : False, 'open_in_code' : True, 'open_in_subl' : False}
                break
            elif select_editor[0] == 's':
                save_config = {'open_in_atom' : False, 'open_in_code' : False, 'open_in_subl' : True}
                break
        elif open_in_editor[0] == 'n':
                save_config = {'open_in_atom' : False, 'open_in_code' : False, 'open_in_subl' : False}
                break
        else:
            print("Please enter [y]es or [n]o")
    json.dump(save_config, open(config_file, 'w'))
    load_config = json.load(open(config_file))

open_in_atom = load_config.get('open_in_atom', False) # open parsed files in Atom when script completes
open_in_code = load_config.get('open_in_code', False) # open parsed files in VSCode Text when script completes
open_in_subl = load_config.get('open_in_subl', False) # open parsed files in Sublime Text when script completes

# start
def parse_args(args=None):
    parser = argparse.ArgumentParser(description='Python variant of the Pexip Log Tools')
    parser.add_argument('dir', nargs='?', help='directory to extract the snapshot')
    parser.add_argument('-s', '--skip', action='store_true', help='skip confhistory and logreader processing')
    parser.add_argument('-o', '--old', action='store_true', help='use older decryption method')
    return parser.parse_args(args=args)

def decrypt(in_file, out_file, decrypt_method, key):
    password = ''
    if not key:
        password = getpass()
    else:
        password = key
    try:
        if decrypt_method:
            decrypted_file = subprocess.call(['openssl', 'aes-256-cbc', '-d', '-out', out_file, '-in', in_file, '-md', 'md5', '-pass', 'pass:{}'.format(password)])
        else:
            decrypted_file = subprocess.call(['openssl', 'aes-256-cbc', '-d', '-salt', '-pbkdf2', '-out', out_file, '-in', in_file, '-md', 'sha256', '-pass', 'pass:{}'.format(password)])
        if decrypted_file < 0:
            print('Child was terminated by signal', -decrypted_file)
            sys.exit(2)
        elif decrypted_file == 1:
            print('Wrong password')
            sys.exit(2)
    except OSError as e:
        print('Execution failed:', e)
        sys.exit(2)

def get_ordered_list_of_snaps(snapshot_path):
    ordered_snaps = {}
    order_id = 0
    num_files = -1
    found = 0
    for file_name in os.listdir(snapshot_path):
        if isfile(join(snapshot_path, file_name)):
            if 'diagnostic_snapshot_' in file_name and '.tgz' in file_name:
                found = 1
                size = str(os.stat(snapshot_path + '/' + file_name).st_size / 1048576)
                ordered_snaps[order_id] = os.path.join(snapshot_path, file_name), size
                if order_id > num_files:
                    num_files = order_id
                    order_id += 1
    if not found:
        return ()
    return (ordered_snaps, num_files)

def select_snap(snapshot_path):
    snaps = get_ordered_list_of_snaps(snapshot_path)
    if not snaps:
        print('No snapshots found in {}'.format(snapshot_path))
        print(len('No snapshots found in {}'.format(snapshot_path)) * "=")
        sys.exit(2)
    else:
        if len(snaps[0].items()) == 1:
            for key, value in snaps[0].items(): # return the only snapshot found
                return value[0]
        snap_count = 0
        print(len('Number  Size    Filename') * "=")
        print('Number\tSize\tFilename')
        for a, b in snaps[0].values():
            print ('{}\t{:.2f}MB\t{}'.format(snap_count, float(b), os.path.split(a)[1]))
            snap_count += 1

        snap_count -= 1
        try:
            snap_select = int(input('Select a number: '))
            while snap_select < 0 or snap_select > snaps[1]:
                print('Not an appropriate choice.')
                snap_select = int(input('Select a number: '))
        except ValueError:
            print('That\'s not an option!')
            sys.exit(2)
        for key, value in snaps[0].items(): # return selected snapshot
            if key == snap_select:
                return value[0]

def extract_snap(snapshot_output, snapshot_input, decrypt_method, dir): # extract snapshot
    now = datetime.now()
    if os.path.exists(snapshot_output):
        os.rename(snapshot_output, snapshot_output+'_old_'+now.strftime("%H%M%S_%d%m%Y"))
    if not os.path.exists(snapshot_output):
        os.makedirs(snapshot_output)
    snapshot_purge = snapshot_input
    try:
        with tarfile.open(snapshot_input) as tar: # check for encryption
            enc = False
    except:
        enc = True
    if enc:
        key_to_use = ''
        try:
            key = pexdesk.get_keys(dir)
        except:
            key = None
            pass
        if autokey and key != None:
            for keys in key.values():
                if snapshot_input.endswith(keys['filename']):
                    key_to_use = keys['key']
            decrypt(snapshot_input, snapshot_input.replace(".tgz", "-decrypted.tgz"), decrypt_method, key_to_use) # decrypt
        else:
            decrypt(snapshot_input, snapshot_input.replace(".tgz", "-decrypted.tgz"), decrypt_method, key_to_use) # decrypt
        snapshot_input = (snapshot_input.replace(".tgz", "-decrypted.tgz"))
    if not snapshot_input.endswith('.tgz'):
        print('Error: incorrect file format, expected .tgz got ' + os.path.split(snapshot_input)[1][-4:])
        sys.exit(2)
    print('Decompressing snapshot')
    try:
        with tarfile.open(snapshot_input) as tar:
            tar.extractall(path=snapshot_output)
            print()
    except Exception as e:
        print('Extraction failed:', e)
        sys.exit(2)
    os.rename(snapshot_input, (snapshot_output + '/' + os.path.split(snapshot_input)[1]))
    if os.path.exists(snapshot_purge):
        os.remove(snapshot_purge)
    return (snapshot_output)

def run_lr(path, snapshot_output, script_path, script_output):
    try:
        path = path.replace(" ", "\\ ")
        subprocess.Popen(("{} {}* > {}").format(script_path, path, (snapshot_output + parsedlogdir + script_output)), shell=True).wait()
    except subprocess.CalledProcessError as e:
        print(e.output)

def run_script(snapshot_output, script_path, report_output):
    try:
        snapshot_output = snapshot_output.replace(" ", "\\ ")
        subprocess.Popen(("{} {} > {}").format(script_path, snapshot_output, (snapshot_output + parsedlogdir + report_output)), shell=True).wait()
    except subprocess.CalledProcessError as e:
        print(e.output)

# run
def main():
    worker = False
    cwd = os.getcwd()
    args = parse_args()
    snapshot_input = select_snap(cwd) # select a snapshot from current working directory
    if args.old:
        decrypt_method = True
    else:
        decrypt_method = False
    if not args.dir:
        snapshot_output = (os.getcwd() + "/" + snapshot_input.replace(".tgz", "").split('/')[-1])
    else:
        snapshot_output = (parsed_snaps + "/" + args.dir)
    try:
        extract_snap(snapshot_output, snapshot_input, decrypt_method, args.dir) # extract snapshot to folder

        if not os.path.exists(snapshot_output + parsedlogdir): # create parsed log directory
            os.makedirs(snapshot_output + parsedlogdir)

        dev_files_array = sorted(glob.glob(os.path.join(snapshot_output, 'var/log/unified_developer.log*')), key=os.path.getmtime, reverse=True)
        sup_files_array = sorted(glob.glob(os.path.join(snapshot_output, 'var/log/unified_support.log*')), key=os.path.getmtime, reverse=True)
        sys_files_array = sorted(glob.glob(os.path.join(snapshot_output, 'var/log/unified_syslog.log*')), key=os.path.getmtime, reverse=True)
        if not dev_files_array and not sup_files_array and not sys_files_array:
            worker = True

        if worker == False:
            print(' -- Checking for stability issues')
            if dev_files_array:
                for line in fileinput.input(dev_files_array):
                    matchip = re.compile(r'Irregular ping detected.+\(\d[1-9]+\.\d[0-9].+sec\)')
                    if matchip.findall(line):
                        with open(snapshot_output + parsedlogdir + irregularpingstext, 'a') as output_file:
                            output_file.write(("{}:{}").format(fileinput.filename().split('/')[-1], line))
                    if 'Reactor stalling' in line:
                        with open(snapshot_output + parsedlogdir + rectorstallingtext, 'a') as output_file:
                            output_file.write(("{}:{}").format(fileinput.filename().split('/')[-1], line))
                    if 'Multiple numa nodes detected during sampling' in line:
                        with open(snapshot_output + parsedlogdir + numaconfigurattext, 'a') as output_file:
                            output_file.write(("{}:{}").format(fileinput.filename().split('/')[-1], line))
            if sup_files_array:
                for line in fileinput.input(sup_files_array):
                    if 'Irregular pulse duration detected' in line:
                        with open(snapshot_output + parsedlogdir + irregularpulsetext, 'a') as output_file:
                            output_file.write(("{}:{}").format(fileinput.filename().split('/')[-1], line))
            if sys_files_array:
                for line in fileinput.input(sys_files_array):
                    match = re.compile(r'e1000.*Reset adapter')
                    if match.findall(line):
                        with open(snapshot_output + parsedlogdir + e1adapteresetstext, 'a') as output_file:
                            output_file.write(("{}:{}").format(fileinput.filename().split('/')[-1], line))

            for script, values in external_scripts.items(): # run external scripts
                if os.path.isfile(values['script']):
                    if script == 'logreader' and args.skip:
                        continue
                    elif script == 'conference_history' and args.skip:
                        continue
                    elif script == 'logreader':
                        print(' -- Creating ' + script + ' output')
                        run_lr((snapshot_output + actuallogdir + support), snapshot_output, values['script'], values['logfile'])
                    else:
                        print(' -- Creating ' + script + ' output')
                        run_script(snapshot_output, values['script'], values['logfile'])

            print(len('Parsed file location: {}'.format(snapshot_output + parsedlogdir)) * "=")
            print('Parsed file location: {}'.format(snapshot_output + parsedlogdir))
        else: # do not process log files from a worker node
            print(len('File location: {}'.format(snapshot_output)) * "=")
            print('File location: {}'.format(snapshot_output))

        # open the file location in the selected editor if configured to do so.
        if open_in_atom:
            subprocess.Popen([atom_path, snapshot_output])
        if open_in_code:
            subprocess.Popen([code_path, snapshot_output])
        if open_in_subl:
            subprocess.Popen([subl_path, snapshot_output])

    except OSError as err:
        print(err)
        sys.exit(2)

if __name__ == "__main__":
    try:
        main()
    except (IOError, KeyboardInterrupt):
        pass
