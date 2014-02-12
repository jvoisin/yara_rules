#!/usr/bin/env python
# encoding: utf-8
#
# Tested on Linux (Ubuntu), Windows XP/7, and Mac OS X
#
'''
untitled.py

Created by Matthew Richard on 2010-03-12.
Ported to py3 by Julien (jvoisin) Voisin on feb2014
Copyright (c) 2010. All rights reserved.
'''

import os
import re
import argparse
import collections


def main():
    parser = argparse.ArgumentParser(description='PEiD to yara rules converter')
    parser.add_argument('-n', '--no-ep', dest='no_ep', action='store_true',
        default=False, help='no entrypoint restriction')
    parser.add_argument('files', metavar='files', type=str, nargs='+',
        help='scanned filenames')
    parser.add_argument('-o', '--output-file', action='store', dest='outfile',
        help='output filename')

    opts = parser.parse_args()

    if opts.outfile is None:
        parser.error('You must specify an output filename!\n')
    elif opts.files is None:
        parser.error('You must supply at least one filename!\n')
    else:
        for fin in opts.files:
            if not os.path.isfile(fin):
                parser.error('%s does not exist' % fin)

    # yara rule template from which rules will be created
    yara_rule = '''
rule %s
{
strings:
    %s
condition:
    %s
}

    '''
    rules = collections.defaultdict(lambda: set(), {})

    #  read the PEiD signature files
    data = ' '.join([open(f, 'r').read() for f in opts.files])

    #  every signature takes the form of
    #  [signature_name]
    #  signature = hex signature
    #  ep_only = (true|false)
    signature = re.compile(r'''
        \[\d*
        ([^(?:\->)\n]{1,128})               # This is the rule name
        (?:\->)?[^\]]*\]\s*\n               # We don't care about content after a "->"
        signature\ =\ (?:\?.\ )*            # Signature pattern can't start with ??
        ((?:[0-9A-Fa-f?]{2}\ )*             # Only match hex pairs
        [0-9A-Fa-f?]{2})\s*\n               # Get the terminal pair
        ep_only\ =\ (true|false)\s*\n
        ''', re.MULTILINE | re.VERBOSE)

    # rule name has the same constraints as a C variable name 
    rules_cpt = 0
    double_cpt = 0
    name_filter = re.compile(r'(\W)')
    for match in signature.finditer(data):
        name = name_filter.sub('_', match.group(1)).rstrip('_')
        if (match.group(2), match.group(3)) in rules[name]:
            double_cpt +=1
        rules[name].add((match.group(2), match.group(3)))
        rules_cpt += 1
    print('[+] Found %d signatures (%d duplicates) in PEiD input file' %
            (rules_cpt, double_cpt))

    output = ''
    for rule in list(rules.keys()):
        detects = ''
        conds = '\t'
        counter = 0
        for (detect, use_ep) in rules[rule]:
            # create each new rule using a unique numeric value
            # to allow for multiple criteria and no collisions
            detects += '\t$a%d = { %s }\n' % (counter, detect)

            if counter > 0:
                conds += ' or '

            # if the rule specifies it should be at EP we add
            # the yara specifier 'at entrypoint'
            conds += '$a%d' % counter
            if use_ep == 'true' and opts.no_ep is False:
                conds += ' at entrypoint'
            counter += 1

        # add the rule to the output
        output += yara_rule % (rule, detects, conds)

    # could be written to an output file
    with open(opts.outfile, 'w') as fout:
        fout.write(output)

    print('[+] Wrote %d rules to %s' % (len(rules), opts.outfile))

if __name__ == '__main__':
    main()
