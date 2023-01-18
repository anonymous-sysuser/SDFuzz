#!/usr/bin/env python3
import argparse
import collections
import functools
import networkx as nx

if __name__ == '__main__':
  parser = argparse.ArgumentParser ()
  parser.add_argument ('-d', '--dot', type=str, required=True, help="Path to dot-file representing the graph.")
  parser.add_argument ('-f', '--target_functions', type=str, required=False, help="Path to file specifying Target nodes.")
  parser.add_argument ('-o', '--out', type=str, required=True, help="Path to output file containing distance for each node.")
  parser.add_argument ('-c', '--cg_distance', type=str, help="Path to file containing call graph distance.")
  args = parser.parse_args ()

  print ("\nParsing %s .." % args.dot)
  G = nx.DiGraph(nx.drawing.nx_pydot.read_dot(args.dot))
  print (nx.info(G))
  target_functions = []
  with open(args.target_functions, 'r') as f:
    for line in f.readlines ():
      line = line.strip ()
      target_functions.append(line)

  cg_distances = []
  with open(args.cg_distance, 'r') as f:
    new_CG = nx.DiGraph()
    CG = {}
    for l in f.readlines():
      s = l.strip().split(",")
      if s[0] not in CG.keys():
        CG[s[0]] = {}
      if s[1] not in CG[s[0]].keys():
        CG[s[0]][s[1]] = []
      CG[s[0]][s[1]].append(float(s[2]))
    for k1, v1 in CG.items():
      for k2, v2 in v1.items():
        temp_dis = 1/sum([1/i for i in v2])
        new_CG.add_edge(k1, k2, weight=temp_dis)
    all_functions = set()
    for e in G.edges():
      fro = G.nodes[e[0]]["label"].strip("\"\}\{\':")
      to = G.nodes[e[1]]["label"].strip("\"\}\{\':")
      all_functions.add(fro)
      all_functions.add(to)
      if not new_CG.has_edge(fro, to):
          print("add edge %s -> %s" % (fro, to))
          new_CG.add_edge(fro, to, weight=1)

    for func in all_functions:
      d = 0
      i = 0
      for tfunc in target_functions:
        try:
          shortest = nx.shortest_path_length(new_CG, func, tfunc, weight="weight")
          d += 1.0 / (1.0 + shortest)
          i += 1
        except nx.NetworkXNoPath:
          pass
      if d != 0:
        cg_distances.append("%s,%f" % (func, i/d))
  with open(args.out, 'w') as f:
    f.write("\n".join(cg_distances))

