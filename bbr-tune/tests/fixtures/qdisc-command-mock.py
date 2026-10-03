#!/usr/bin/env python3
"""Stateful ip/tc test double; never accesses host network configuration."""
import json
import os
from pathlib import Path
import sys
from decimal import Decimal

base = Path(os.environ['QDISC_TEST_DIR'])
args = sys.argv[1:]
command = Path(sys.argv[0]).name
ns = None
with (base / 'commands.log').open('a') as f:
    f.write(command + ' ' + ' '.join(args) + '\n')
if command == 'ip':
    if args[:2] == ['netns', 'add']:
        if (base / 'fail-namespace').exists():
            sys.exit(1)
        (base / (args[2] + '.json')).write_text('[{"kind":"noqueue","handle":"0:","root":true,"options":{}}]')
        sys.exit(0)
    if args[:2] == ['netns', 'del']:
        (base / (args[2] + '.json')).unlink()
        if (base / 'drift-after-probe').exists():
            (base / 'live.json').write_text((base / 'fq_codel.json').read_text())
        sys.exit(0)
    if args[:2] == ['netns', 'exec']:
        ns = args[2]
        assert args[3] == 'tc', args
        args = args[4:]
    else:
        assert args[:2] == ['link', 'show'] or (args[0] == '-n' and args[2:4] == ['link', 'add']), args
        sys.exit(0)
file = base / (ns + '.json' if ns else 'live.json')
state = json.loads(file.read_text())
if 'filter' in args:
    print((base / 'filters.json').read_text() if (base / 'filters.json').exists() else '[]')
    sys.exit(0)
if 'show' in args:
    if '-j' in args:
        print(json.dumps(state))
    else:
        for q in state:
            attach = 'root' if q.get('root') else 'parent ' + q['parent']
            print(f"qdisc {q['kind']} {q['handle']} {attach}")
    sys.exit(0)
assert args[:1] == ['qdisc'], args
if not ns:
    with (base / 'live-writes').open('a') as f:
        f.write(' '.join(args) + '\n')
    if (base / 'false-success').exists():
        sys.exit(0)
parent = args[args.index('parent')+1] if 'parent' in args else 'root'
if not ns and (base / 'fail-parent').exists() and parent == (base / 'fail-parent').read_text().strip():
    sys.exit(1)
if args[1] == 'del':
    assert parent == 'root', args
    file.write_text('[{"kind":"noqueue","root":true,"handle":"0:","options":{}}]')
    sys.exit(0)
assert args[1] in ('replace', 'change'), args
pos = args.index('parent')+2 if 'parent' in args else args.index('root')+1
handle = None
if args[pos] == 'handle':
    handle = args[pos+1]
    pos += 2
kind = args[pos]
if ns and kind == 'cake' and (base / 'unsupported-cake').exists():
    sys.exit(1)
args = args[pos+1:]
index = next((i for i, q in enumerate(state) if ('root' if q.get('root') else q.get('parent')) == parent), None)
assert index is not None, (parent, state)
old = state[index]
if args and kind == 'cake' and '200000000bit' in args and ns and (base / 'fail-restore-probe').exists():
    sys.exit(1)
# ip netns exec keeps the original outer argv, so a direct change also works.
is_change = kind == old['kind'] and 'change' in sys.argv
if is_change:
    q = json.loads(json.dumps(old))
else:
    defaults = json.loads((base / 'defaults.json').read_text())
    q = {'kind':kind,'handle':handle or '8001:', 'options':dict(defaults[kind])}
    if parent == 'root':
        q['root'] = True
    else:
        q['parent'] = parent
options = q['options']
flags = {'unlimited':('bandwidth','unlimited'), 'pacing':('pacing',True), 'nopacing':('pacing',False),
         'ecn':('ecn',True), 'noecn':('ecn',False), 'nat':('nat',True), 'nonat':('nat',False),
         'wash':('wash',True), 'nowash':('wash',False), 'ingress':('ingress',True), 'egress':('ingress',False),
         'split-gso':('split_gso',True), 'no-split-gso':('split_gso',False), 'raw':('raw',True),
         'no-ack-filter':('ack-filter','disabled'), 'ack-filter':('ack-filter','enabled'),
         'ack-filter-aggressive':('ack-filter','aggressive'), 'horizon_cap':('horizon_cap',None),
         'horizon_drop':('horizon_drop',None), 'autorate-ingress':('autorate','autorate-ingress')}
for val in ['besteffort','diffserv3','diffserv4','diffserv8']:
    flags[val] = ('diffserv',val)
for val in ['flowblind','srchost','dsthost','hosts','flows','dual-srchost','dual-dsthost','triple-isolate']:
    if kind == 'cake':
        flags[val] = ('flowmode',val)
for val in ['atm','ptm','noatm']:
    flags[val] = ('atm',val)
i = 0
while i < len(args):
    key = args[i]
    if key == 'bands':
        assert args[i+1:i+3] == ['3', 'priomap'], args
        priomap = [int(v) for v in args[i+3:i+19]]
        assert len(priomap) == 16, args
        options.update(bands=3, priomap=priomap)
        i += 19
        continue
    if key == 'weights':
        weights = [int(v) for v in args[i+1:i+4]]
        assert len(weights) == 3, args
        options['weights'] = weights
        i += 4
        continue
    if key in flags:
        k,v = flags[key]; options[k] = v
        if k == 'bandwidth': options.pop('autorate',None)
        i += 1
        continue
    val = args[i+1]; i += 2
    if key in ('bandwidth','maxrate','defrate','low_rate_threshold'):
        if val.endswith('mbit'):
            options[key] = int(Decimal(val[:-4])*1000000/8)
        else:
            assert val.endswith('bit'), val
            options[key] = int(Decimal(val[:-3])/8)
        if key == 'bandwidth': options.pop('autorate',None)
    elif key in ('rtt','refill_delay','ce_threshold','horizon','offload_horizon','target','interval'):
        assert val.endswith('us'), val
        options[key] = int(val[:-2])
    elif key == 'timer_slack':
        assert val.endswith('ns'), val
        options[key] = int(val[:-2])
    elif key == 'fwmark':
        mark = int(val,0)
        options[key] = hex(mark) if mark else '0'
    elif key == 'ce_threshold_selector':
        a,b = val.split('/'); options[key]=int(a); options['ce_threshold_mask']=int(b)
    else:
        options[key] = int(val)
if kind == 'cake' and options.get('raw') and options.get('atm') == 'noatm':
    options.pop('atm')
state[index] = q
file.write_text(json.dumps(state))
