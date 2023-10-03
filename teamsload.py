#!/usr/bin/env python3
# teamsload.py: parse snapshot database for teams connector load history (v25+)
# dependencies:
# pip3 install pandas
# pip3 install numpy
# v1.1 # port to python3 and fixup incorrect output
# v1.0
#
# Disable "Invalid constant name"                       pylint: disable=C0103
# Disable "Line too long"                               pylint: disable=C0301
# Disable "Too many lines in module"                    pylint: disable=C0302
# Disable "Missing docstring"                           pylint: disable=C0111
# Disable "Too many branches"                           pylint: disable=R0912
# Disable "Too many statements"                         pylint: disable=R0915
# Disable "Unnecessary parens"                          pylint: disable=C0325
# Disable "Wrong Import Position"                       pylint: disable=C0413
# Disable "Access to a protected member"                pylint: disable=W0212

import argparse
from datetime import datetime
import json
import os
import sqlite3
import sys
import pandas as pd
import numpy as np
pd.set_option('display.max_rows', None)

def parse_args(args=None):
    parser = argparse.ArgumentParser(description='Teams Connector concurrent call history')
    parser.add_argument('dir', nargs='?', help='base directory of the snapshot files')
    parser.add_argument('number', type=int, nargs='?', help='number of previous days to search (default=14)')
    parser.add_argument('-s', action='store_true', help='save the output to a file in the same dir')
    return parser.parse_args(args=args)

def char_len(x, fixed_n):
    '''set string x to fixed_n character, prepend with 'xxx' if short'''
    if len(x) > fixed_n:
        return x[:fixed_n] + '...'
    elif len(x) < fixed_n:
        return 'x' * (fixed_n - len(x)) + x
    return x + '...'

def builddict(db, table, fields, key, days):
    resp = {}
    cur = db.cursor()
    if days == None:
        cur.execute("select * from %s" % table)
    else:
        cur.execute("select * from %s WHERE start_time BETWEEN datetime('now', '-%s days') AND datetime('now', 'localtime')" % (table, days))
    for row in cur:
        data = {}
        for field in fields:
            data[field] = row[field] if field in row.keys() else ''
        resp[row[key]] = data
    return resp

def check_version(snapshot_path):
    version_file = os.path.join(snapshot_path, "opt", "pexip", "lib", "python2.7", "site-packages", "si", "web", "management", "conf", "static", "version.json")
    with open(version_file, "r") as fh:
        version_json = fh.read()
    version_info = json.loads(version_json)
    return version_info["major"]

def main():
    now = datetime.now()
    args = parse_args()
    if not args.dir:
        rootdir = os.getcwd()
    else:
        rootdir = args.dir
    if args.number:
        display_days = args.number
    else:
        display_days = 14
    if args.s:
        output_file = rootdir+'/teamsload_output_'+now.strftime("%H%M%S_%d%m%Y")+'.log'
    try:
        conferencing_history = sqlite3.connect(os.path.join(rootdir, 'opt/pexip/share/history/conferencing_history.db'))
        conferencing_history.row_factory = sqlite3.Row
        platform_history = sqlite3.connect(os.path.join(rootdir, 'opt/pexip/share/history/platform_history.db'))
        platform_history.row_factory = sqlite3.Row
    except:
        print("FATAL: Unable to open database files, run this from the snapshot directory")
        print("Usage: %s <snapshot folder>" % (os.path.basename(__file__)))
        sys.exit(2)
    version = check_version(rootdir)
    if version < 25:
        print("FATAL: Requires Pexip Infinity version 25 or higher")
        sys.exit(2)
    conferencinghistory_teamscall = builddict(conferencing_history, 'conferencinghistory_teamscall', ('teamsnode_id', 'source', 'destination', 'start_time', 'end_time', 'duration'), 'id', display_days)
    platformhistory_teamsnode = builddict(platform_history, 'platformhistory_teamsnode', ('id', 'node_id', 'name', 'scaleset_id', 'ip_address', 'start_time', 'end_time', 'max_calls', 'duration'), 'id', None)

    # get scalesets in use and remove any duplicates
    scalesets = set()
    try:
        for scaleset_root in sorted(platformhistory_teamsnode.keys(), key=lambda k: platformhistory_teamsnode.keys()):
            scalesets.add((platformhistory_teamsnode[scaleset_root]['node_id'], platformhistory_teamsnode[scaleset_root]['max_calls']))
    except:
        pass

    # process data
    if not conferencinghistory_teamscall:
        print("No data found, try specifying the number of previous days to search (default=14)")
        sys.exit(2)
    if scalesets:
        for instance, max_calls in sorted(scalesets):
            if args.s:
                with open(output_file, 'a') as output_f:
                    output_f.write('\n')
                    output_f.write(instance +' '+str(display_days)+' day call history\n')
                    output_f.write('\n')
            else:
                print()
                print(instance +' '+str(display_days)+' day call history')
                print()
            # create DataFrame
            df_dict = {}
            for k, v in conferencinghistory_teamscall.items():
                if v['teamsnode_id'] == instance:
                    df_dict.update({k: v})
            df = pd.DataFrame.from_dict(df_dict, orient='index', columns=['source', 'destination', 'start_time', 'end_time', 'duration'])
            if df.empty:
                if args.s:
                    with open(output_file, 'a') as output_f:
                        output_f.write("No data found for this instance")
                        output_f.write('\n')
                else:
                    print("No data found for this instance")
                pass
            else:
                # sort df by start_time
                df = df.sort_values(by='start_time', ascending=True)
                # count total calls in df
                total_calls = (df.shape[0])
                # create array of overlaps based on start and end time call data
                count_overlaps = pd.IntervalIndex.from_arrays(df.start_time.values, df.end_time.values, closed='both', dtype='interval[datetime64[ns]]')
                # count the total of overlaps per row
                total_overlaps = [count_overlaps.overlaps(x)for x in count_overlaps]
                # create a second DataFrame for the total count of overlaps
                arr = np.array(total_overlaps)
                df2 = pd.DataFrame(data=arr)
                # rename columns in original DataFrame
                df.columns = ['Source', 'Destination', 'Start Time', 'End Time', 'Duration']
                # limit destination string to 15 characters
                df['Destination'] = df['Destination'].apply(lambda x: char_len(x, 13))
                # add total concurrent call data to original DataFrame
                df['Concurrent Calls'] = df2.sum(1).values
                # output DataFrame results
                if args.s:
                    with open(output_file, 'a') as output_f:
                        output_f.write(df.to_string(header=True, index=False))
                        output_f.write('\n')
                        output_f.write('Total calls: ' +str(total_calls)+'\n')
                        output_f.write('Maximum concurrent calls: '+str(max_calls)+'\n\n')
                else:
                    print(df.to_string(header=True, index=False))
                    print('Total calls: ' +str(total_calls))
                    print('Maximum concurrent calls: '+str(max_calls))
        if args.s:
            print()
            print('Output saved in file: ' + output_file)
            print()
    else:
        print('No data found')
        sys.exit(2)

if __name__ == "__main__":
    try:
        main()
    except (IOError, KeyboardInterrupt):
        pass