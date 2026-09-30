#!/usr/bin/env bash
# Optional integration test: real reverse TCP on loopback, without TCP tuning.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v iperf3 >/dev/null 2>&1; then
  printf 'SKIP: iperf3 is not installed; loopback test does not install dependencies\n'
  exit 0
fi
python3 - "$ROOT" "$(command -v iperf3)" "$BASH" <<'PY_LOOPBACK'
import json, os, pathlib, signal, socket, subprocess, sys, tempfile, time
root, iperf, bash=sys.argv[1:]
version=subprocess.run([iperf,'--version'],capture_output=True,text=True,check=True).stdout.splitlines()[0]
with tempfile.TemporaryDirectory(prefix='bbr-iperf-loopback-') as temp:
    for streams in (1,4):
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
        prefix=pathlib.Path(temp)/f'streams-{streams}'
        final=str(prefix)+'.json'; errors=str(prefix)+'.err'
        env=dict(os.environ, REAL_IPERF=iperf)
        code='''source "$1"
iperf3() { "$REAL_IPERF" -B 127.0.0.1 "$@"; }
iperf_server_loop "$2" "$3" "$4" -4 "$5" 3
'''
        server=subprocess.Popen([bash,'-c',code,'loopback-test',str(pathlib.Path(root)/'bbr-tune.sh'),
                                 final,errors,str(port),str(streams)],env=env,
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
        try:
            # Only a real iperf client connects; no TCP readiness probe consumes the one-shot session.
            for attempt in range(10):
                time.sleep(0.2)
                client=subprocess.run([iperf,'-4','-c','127.0.0.1','-p',str(port),'-R',
                                       '-P',str(streams),'-t','3','-b','10M','-J'],
                                      capture_output=True,text=True,timeout=12)
                if client.returncode==0: break
                if 'unable to connect' not in client.stdout+client.stderr:
                    raise AssertionError(f'client failed: {client.stdout}\n{client.stderr}')
            assert client.returncode==0, client.stdout+client.stderr
            output, err=server.communicate(timeout=10)
            assert server.returncode==0, (server.returncode,output,err)
            data=json.loads(pathlib.Path(final).read_text())
            assert data['end']['sum_sent']['bytes']>0
            assert len(data['end']['streams'])==streams
            assert 'ignored_connection=' not in pathlib.Path(errors).read_text()
            # A rejected complete result would leave an attempt JSON and never finish on old releases.
            assert not list(pathlib.Path(temp).glob(f'streams-{streams}.attempt-*.json'))
            parsed=subprocess.run([bash,'-c','''source "$1"; parse_iperf_json "$2" "$3" 3
printf '%s %s\\n' "$RESULT_MBPS" "$RESULT_RATE_SOURCE"
''','loopback-parser',str(pathlib.Path(root)/'bbr-tune.sh'),final,str(streams)],
                                  capture_output=True,text=True,check=True)
            mbps, source=parsed.stdout.strip().split()
            assert float(mbps)>0
            receiver=data['end'].get('sum_received',{})
            if receiver.get('bytes')==0 and receiver.get('bits_per_second')==0:
                assert source=='sender-unreported-receiver', source
            print(f'PASS: {version}; reverse P={streams}; {mbps} Mbps; source={source}; first session accepted')
        finally:
            if server.poll() is None:
                os.killpg(server.pid,signal.SIGTERM)
                try: server.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(server.pid,signal.SIGKILL); server.communicate()
PY_LOOPBACK
