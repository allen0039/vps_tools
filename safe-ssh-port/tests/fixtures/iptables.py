"""Minimal stateful iptables command fixture for port operation tests."""

import json
import shlex
import sys
from pathlib import Path


state_path = Path(sys.argv[1])
operation, chain, *arguments = sys.argv[2:]
state = json.loads(state_path.read_text())
if operation == "-N" and chain not in state:
    state[chain] = []
    state_path.write_text(json.dumps(state))
    sys.exit(0)
if chain not in state:
    sys.exit(1)
rules = state[chain]

if operation == "-S":
    print("-P INPUT ACCEPT" if chain == "INPUT" else f"-N {chain}")
    for rule in rules:
        print(shlex.join(["-A", chain, *rule]))
elif operation == "-C":
    sys.exit(0 if arguments in rules else 1)
elif operation == "-D":
    if arguments not in rules:
        sys.exit(1)
    rules.remove(arguments)
elif operation == "-I":
    if arguments and arguments[0].isdigit():
        position, *rule = arguments
    else:
        position, rule = "1", arguments
    rules.insert(int(position) - 1, rule)
elif operation == "-A":
    rules.append(arguments)
elif operation == "-F":
    rules.clear()
elif operation == "-X":
    if rules:
        sys.exit(1)
    del state[chain]
else:
    sys.exit(2)

if operation in ("-D", "-I", "-A", "-F", "-X"):
    state_path.write_text(json.dumps(state))
