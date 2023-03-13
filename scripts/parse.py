#!/usr/bin/env python3
import argparse, re 

def parse(trace): 
    stmts = []
    for l in trace:
        l = l.strip()
        if l.startswith('#'): # can also use regular expression
            tokens = l.split(' ')
            loc = tokens[-1].split('/')[-1]
            if ':' not in loc:
                continue
            func = tokens[3]
            stmts.append(func + ',' + loc)
    stmts.reverse()
    print(stmts)
    return stmts

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--trace', type=str, required=True, help="Specify target trace to analyze.")
    parser.add_argument('-o', '--out', type=str, required=False, help="Specify output file.")
    args = parser.parse_args()
    with open(args.trace, 'r', encoding='utf-8', errors='ignore') as fp:
        trace = fp.readlines()
    stmts = parse(trace)
    if args.out:
        outfile = args.out
    else:
        outfile = 'temp-out.txt'
    with open(outfile, 'w') as fp:
        fp.write('\n'.join(stmts))
