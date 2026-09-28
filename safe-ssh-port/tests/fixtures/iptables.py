"""Minimal stateful iptables command fixture for port operation tests."""

import json
import shlex
import sys
from pathlib import Path


state_path = Path(sys.argv[1])
operation, chain, *arguments = sys.argv[2:]
state = json.loads(state_path.read_text())
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
    position, *rule = arguments
    rules.insert(int(position) - 1, rule)
else:
    sys.exit(2)

if operation in ("-D", "-I"):
    state_path.write_text(json.dumps(state))
