#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "$ROOT" "$BASH" <<'PY'
import fcntl, os, pathlib, subprocess, sys, tempfile, time
root, bash = sys.argv[1:]
with tempfile.TemporaryDirectory(prefix='bbr-lock-') as tmp:
    base=pathlib.Path(tmp); bindir=base/'bin'; bindir.mkdir()
    # An inherited-descriptor flock shim makes the concurrency regression test
    # runnable on macOS too, without requiring packages or Linux root access.
    exe=bindir/'flock'
    exe.write_text('#!'+sys.executable+'''\nimport fcntl,sys
op=fcntl.LOCK_UN if '-u' in sys.argv else fcntl.LOCK_EX
if '-n' in sys.argv: op |= fcntl.LOCK_NB
try: fcntl.flock(int(sys.argv[-1]),op)
except BlockingIOError: sys.exit(1)
''')
    exe.chmod(0o755)
    env=dict(os.environ, PATH=str(bindir)+os.pathsep+os.environ['PATH'])
    state=base/'state'
    prelude='''source "$1/bbr-tune.sh"
STATE_DIR="$2"
require_linux() { :; }; require_root() { :; }
'''
    owner=subprocess.Popen([bash,'-c',prelude+'''
acquire_operation_lock
echo ready >"$STATE_DIR/ready"
while [[ ! -f "$STATE_DIR/release" ]]; do sleep 0.05; done
''','owner',root,str(state)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    waiter=None
    try:
        deadline=time.monotonic()+5
        while not (state/'ready').exists():
            assert owner.poll() is None, owner.communicate()
            assert time.monotonic()<deadline, 'lock setup timed out'
            time.sleep(0.05)
        tcp=subprocess.run([bash,'-c',prelude+'acquire_operation_lock','tcp',root,str(state)],env=env,capture_output=True,text=True)
        assert tcp.returncode!=0 and '正在运行' in tcp.stderr, tcp
        queue=subprocess.run([bash,'-c',prelude+"main qdisc --qdisc cake",'queue',root,str(state)],env=env,capture_output=True,text=True)
        assert queue.returncode!=0 and '正在运行' in queue.stderr,queue
        kernel=subprocess.run([bash,'-c','''source "$1/bbr-kernel.sh"
K_ROOT="$2/kernels"
k_lock
''','kernel',root,str(state)],env=env,capture_output=True,text=True)
        assert kernel.returncode!=0 and '正在运行' in kernel.stderr,kernel
        waiter=subprocess.Popen([bash,'-c',prelude+'''
BBR_AUTO_ROLLBACK=1
acquire_operation_lock
echo acquired >"$STATE_DIR/waiter"
''','watchdog',root,str(state)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        time.sleep(0.2)
        assert waiter.poll() is None and not (state/'waiter').exists(), 'watchdog raced TCP writer'
        (state/'release').touch()
        out,err=owner.communicate(timeout=5)
        assert owner.returncode==0,(out,err)
        out,err=waiter.communicate(timeout=5)
        assert waiter.returncode==0 and (state/'waiter').exists(),(out,err)
    finally:
        for child in (owner,waiter):
            if child is not None and child.poll() is None:
                child.terminate(); child.communicate(timeout=5)
print('All TCP/queue/kernel mutual-exclusion and watchdog serialization tests passed.')
PY
