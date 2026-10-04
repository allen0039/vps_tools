#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cp "$ROOT/tests/fixtures/qdisc-command-mock.py" "$tmp/bin/tc"
cp "$tmp/bin/tc" "$tmp/bin/ip"
chmod +x "$tmp/bin/"{tc,ip}

{
  printf 'source %q\n' "$ROOT/bbr-tune.sh"
  cat <<'RUNNER'
STATE_DIR="$1"; mode="$2"
SESSION_ROOT="$STATE_DIR/sessions"; BACKUP_ROOT="$STATE_DIR/backups"; LATEST_BACKUP="$STATE_DIR/latest"
PENDING_DIR="$STATE_DIR/pending"; PENDING_LATEST="$STATE_DIR/pending-latest"; ACTIVE_SESSION_FILE="$STATE_DIR/active-session"
SYSCTL_FILE="$STATE_DIR/config/sysctl"; MODULES_FILE="$STATE_DIR/config/modules"; ENV_FILE="$STATE_DIR/config/env"
QDISC_HELPER="$STATE_DIR/config/helper"; SERVICE_FILE="$STATE_DIR/config/service"
export QDISC_TEST_DIR="$STATE_DIR"
eval "$(declare -f qdisc_default_mq_device | sed '1s/qdisc_default_mq_device/qdisc_default_mq_device_real/')"
qdisc_default_mq_device() { qdisc_default_mq_device_real "$1" "$STATE_DIR/queues"; }
require_linux() { :; }; require_root() { :; }
systemd_available() { [[ "$mode" != no-systemd ]]; }
sysctl_get() { awk -F '\t' -v k="$1" '$1==k {sub(/^[^\t]*\t/, ""); print}' "$STATE_DIR/sysctls.tsv"; }
sysctl_exists() { [[ -n "$(sysctl_get "$1")" ]]; }
sysctl() {
  local key="${2%%=*}" value="${2#*=}"
  printf '%s\n' "$2" >>"$STATE_DIR/sysctl-writes"
  if [[ "$key" == net.core.rmem_max && "$value" == 262144 ]]; then
    [[ ! -f "$STATE_DIR/fail-sysctl" ]] || return 1
    [[ ! -f "$STATE_DIR/false-sysctl" ]] || return 0
    [[ ! -f "$STATE_DIR/interrupt-sysctl" ]] || exit 130
    if [[ "$mode" == hangup* ]]; then
      python3 -c 'import os; print(os.getppid())' >"$STATE_DIR/clear-worker-pid"
      while true; do sleep 0.02; done
    fi
  fi
  awk -F '\t' -v k="$key" -v v="$value" '$1==k {$0=k "\t" v} {print}' "$STATE_DIR/sysctls.tsv" >"$STATE_DIR/sysctls.new"
  mv "$STATE_DIR/sysctls.new" "$STATE_DIR/sysctls.tsv"
}
systemctl() {
  printf '%s\n' "$*" >>"$STATE_DIR/service-calls"
  case "$1" in
    is-enabled)
      if [[ -f "$SERVICE_FILE" ]]; then cat "$STATE_DIR/service-enabled"; else echo not-found; fi ;;
    is-active) cat "$STATE_DIR/service-active" ;;
    disable)
      [[ ! -f "$STATE_DIR/fail-service-stop" ]] || return 1
      echo disabled >"$STATE_DIR/service-enabled"; echo inactive >"$STATE_DIR/service-active" ;;
    enable)
      if [[ -f "$STATE_DIR/false-service-enable" ]]; then command rm "$STATE_DIR/false-service-enable"; return 0; fi
      echo enabled >"$STATE_DIR/service-enabled" ;;
    daemon-reload) : ;;
    *) return 1 ;;
  esac
}
ip() {
  [[ "$mode" != missing-interface || "$*" != 'link show dev eth0' ]] || return 1
  command ip "$@"
}
cp() {
  if [[ -f "$STATE_DIR/fail-file" && "$*" == *'/restore-target/modules.file '* ]]; then
    command rm "$STATE_DIR/fail-file"; return 1
  fi
  command cp "$@"
}
rm() {
  if [[ -f "$STATE_DIR/false-delete" && "$*" == "-f $SYSCTL_FILE" ]]; then
    command rm "$STATE_DIR/false-delete"; return 0
  fi
  command rm "$@"
}

case "$mode" in
  confirmed|confirm-rollback)
    confirm_tuning
    [[ -d "$BACKUP_ROOT/02-latest" && ! -e "$PENDING_LATEST" ]] || exit 99
    if [[ "$mode" == confirm-rollback ]]; then
      YES=1; rollback_command; exit
    fi ;;
esac
if [[ "$mode" == menu-clear ]]; then
  parse_args restore
  restore_interactive
else
  parse_args clear-tuning ${3:+"$3"}
  clear_tuning_command
fi
RUNNER
} >"$tmp/runner.sh"

python3 - "$ROOT" "$tmp" "$BASH" <<'PY'
import json, os, pathlib, pty, select, signal, subprocess, sys, time
root, tmp, bash = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
env = dict(os.environ, PATH=str(tmp/'bin')+os.pathsep+os.environ['PATH'])
cases = ['success', 'menu-clear', 'cake', 'noqueue', 'mq', 'partial-queue', 'changed-topology',
         'confirmed', 'confirm-rollback', 'cancel', 'no-yes', 'repeat', 'undo',
         'no-systemd', 'existing-service', 'legacy-sysctls', 'missing-original',
         'missing-file', 'incomplete-sysctls', 'unsupported-cc', 'missing-interface',
         'legacy-queue', 'fail-namespace', 'filters', 'fail-sysctl', 'false-sysctl',
         'interrupt-sysctl', 'hangup', 'hangup-disconnect', 'fail-file', 'false-delete', 'fail-service-stop',
         'false-service-enable', 'fail-queue', 'corrupt-queue']
cases += ['default-mq', 'default-mq-older-tc', 'default-mq-broken-weights', 'default-mq-reset-mismatch',
          'default-mq-fail-sysctl', 'default-mq-undo', 'default-mq-cancel',
          'default-mq-foreign-driver', 'default-mq-extra-tx', 'default-mq-custom-leaf',
          'default-mq-fail-tap', 'default-mq-filters', 'default-mq-changed-default',
          'default-mq-unsupported-weights', 'default-mq-interrupt-reset', 'hangup-default-mq']
if os.environ.get('BBR_CLEAR_TEST_CASES'):
    selected=os.environ['BBR_CLEAR_TEST_CASES'].split(',')
    assert set(selected)<=set(cases),selected
    cases=[name for name in cases if name in selected]
early_failures = {'no-yes', 'missing-original', 'missing-file', 'incomplete-sysctls',
                  'unsupported-cc', 'missing-interface', 'legacy-queue',
                  'fail-namespace', 'filters', 'corrupt-queue', 'changed-topology'}
early_failures |= {'default-mq-foreign-driver', 'default-mq-extra-tx', 'default-mq-custom-leaf',
                   'default-mq-fail-tap', 'default-mq-filters', 'default-mq-changed-default',
                   'default-mq-unsupported-weights'}
recovered_failures = {'fail-sysctl', 'false-sysctl', 'interrupt-sysctl', 'fail-file',
                      'false-delete', 'false-service-enable', 'fail-queue', 'partial-queue',
                      'hangup', 'hangup-disconnect'}
recovered_failures |= {'default-mq-reset-mismatch', 'default-mq-fail-sysctl', 'default-mq-interrupt-reset', 'hangup-default-mq'}
defaults = {'fq': {'limit':10000, 'quantum':1514, 'pacing':True},
            'fq_codel': {'limit':10240, 'flows':1024, 'quantum':1514, 'ecn':True},
            'cake': {'bandwidth':'unlimited', 'diffserv':'diffserv3', 'flowmode':'triple-isolate',
                     'nat':False, 'wash':False, 'ingress':False, 'ack-filter':'disabled',
                     'split_gso':True, 'rtt':100000, 'raw':False, 'atm':'noatm', 'overhead':0, 'fwmark':'0'}}
original = {'net.core.default_qdisc':'fq_codel', 'net.ipv4.tcp_congestion_control':'cubic',
            'net.core.rmem_max':'262144', 'net.core.wmem_max':'262144',
            'net.ipv4.tcp_rmem':'4096\t131072\t6291456', 'net.ipv4.tcp_wmem':'4096 16384 4194304',
            'net.ipv4.tcp_mem':'100 200 300', 'net.ipv4.tcp_moderate_rcvbuf':'1',
            'net.ipv4.tcp_sack':'1', 'net.ipv4.tcp_dsack':'1', 'net.ipv4.tcp_window_scaling':'1',
            'net.ipv4.tcp_available_congestion_control':'cubic reno bbr', 'kernel.panic':'10'}
latest = dict(original, **{'net.ipv4.tcp_congestion_control':'reno'})
tuned = dict(original, **{'net.core.default_qdisc':'fq', 'net.ipv4.tcp_congestion_control':'bbr',
                        'net.core.rmem_max':'8388608', 'net.core.wmem_max':'8388608',
                        'net.ipv4.tcp_rmem':'4096 131072 8388608', 'net.ipv4.tcp_wmem':'4096 16384 8388608'})
def write_sysctls(state, values):
    (state/'sysctls.tsv').write_text(''.join(k+'\t'+v+'\n' for k,v in values.items()))
def read_sysctls(state):
    return dict(line.split('\t',1) for line in (state/'sysctls.tsv').read_text().splitlines())
def configs(state):
    return {f.name:(f.read_bytes(), f.stat().st_mode & 0o777) for f in (state/'config').iterdir()}
def run(state, name, inputs=None):
    args = [bash, str(tmp/'runner.sh'), str(state), name]
    if inputs is None:
        if name != 'no-yes': args.append('--yes')
        if name.startswith('hangup'):
            proc=subprocess.Popen(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            deadline=time.monotonic()+15
            try:
                while not (state/'clear-worker-pid').exists() or not (state/'clear-worker-pid').stat().st_size:
                    assert proc.poll() is None,(name,proc.communicate())
                    assert time.monotonic()<deadline,(name,'signal setup timed out')
                    time.sleep(0.02)
                if name=='hangup-disconnect': proc.stdout.close()
                os.kill(int((state/'clear-worker-pid').read_text()),signal.SIGHUP)
                if name=='hangup-disconnect':
                    proc.wait(timeout=5)
                    stdout=''.join(p.read_text() for p in (state/'sessions').glob('clear-*/clear-tuning.log'))
                    return subprocess.CompletedProcess(args,proc.returncode,stdout,proc.stderr.read())
                stdout,stderr=proc.communicate(timeout=5)
                return subprocess.CompletedProcess(args,proc.returncode,stdout,stderr)
            finally:
                if proc.poll() is None: proc.kill(); proc.wait()
        return subprocess.run(args, env=env, capture_output=True, text=True, timeout=15)
    master, slave = pty.openpty()
    proc = subprocess.Popen(args, env=env, stdin=slave, stdout=slave, stderr=slave)
    os.close(slave); os.write(master, inputs)
    output=bytearray(); deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        ready,_,_=select.select([master],[],[],0.1)
        if ready:
            try: chunk=os.read(master,65536)
            except OSError: break
            if not chunk: break
            output.extend(chunk)
        if proc.poll() is not None and not ready: break
    proc.wait(timeout=1); os.close(master)
    return subprocess.CompletedProcess(args,proc.returncode,output.decode(errors='replace'),'')
for name in cases:
    state=tmp/name; (state/'config').mkdir(parents=True)
    default_mq=name.startswith('default-mq') or name=='hangup-default-mq'
    if default_mq:
        (state/'queues/tx-0').mkdir(parents=True)
        defaults['fq'].update(weights=[589824,196608,65536])
    for session in ['01-initial','02-latest']:
        (state/'sessions'/session).mkdir(parents=True)
    (state/'defaults.json').write_text(json.dumps(defaults))
    saved=[{'kind':'fq_codel','handle':'1:','root':True,'options':defaults['fq_codel']}]
    if name=='cake':
        options=dict(defaults['cake'], bandwidth=23750000, nat=True, overhead=44)
        saved=[{'kind':'cake','handle':'1:','root':True,'options':options}]
    if name=='noqueue': saved=[{'kind':'noqueue','handle':'0:','root':True,'options':{}}]
    if name in {'mq','partial-queue','changed-topology'}:
        saved=[{'kind':'mq','handle':'1:','root':True,'options':{}}]+[
            {'kind':'fq_codel','handle':f'{i}0:','parent':f'1:{i}','options':defaults['fq_codel']} for i in (1,2)]
    if default_mq:
        saved=[{'kind':'mq','handle':'0:','root':True,'options':{}},
               {'kind':'fq','handle':'0:','parent':':1','options':defaults['fq']}]
        (state/'default-mq.json').write_text(json.dumps(saved))
        if name=='default-mq-older-tc':
            # Older backup omits a disabled option that current tc prints.
            current_default=json.loads(json.dumps(saved))
            current_default[1]['options']['offload_horizon']=0
            (state/'default-mq.json').write_text(json.dumps(current_default))
        if name=='default-mq-custom-leaf':
            saved=json.loads(json.dumps(saved)); saved[1]['options']['limit']=12345
        if name=='default-mq-broken-weights': (state/'broken-weights').touch()
        # Preserve a single standard default algorithm throughout reset probes.
        original['net.core.default_qdisc']=latest['net.core.default_qdisc']=tuned['net.core.default_qdisc']='fq'
    (state/'live.json').write_text(json.dumps(saved))
    (state/'config/modules').write_text('# Original modules\nsch_fq_codel\n')
    (state/'config/env').write_text('# Original environment\n')
    (state/'config/env').chmod(0o600)
    (state/'service-enabled').write_text('disabled\n'); (state/'service-active').write_text('inactive\n')
    if name in {'existing-service','false-service-enable'}:
        (state/'config/service').write_text('# Original queue service\n')
        (state/'service-enabled').write_text('enabled\n')
    initial_config=configs(state)
    write_sysctls(state,original)
    # Build real backups with the same functions used by tuning and manual backups.
    prelude=(tmp/'runner.sh').read_text().split('case "$mode" in\n')[0]
    seed=tmp/'seed.sh'; seed.write_text(prelude+'''
SESSION_ID=01-initial; QDISC_ONLY=1; QDISC_POLICY=preserve
create_backup eth0 0 '' 0 >/dev/null
sed 's/cubic$/reno/' "$STATE_DIR/sysctls.tsv" >"$STATE_DIR/new"
mv "$STATE_DIR/new" "$STATE_DIR/sysctls.tsv"
SESSION_ID=02-latest; QDISC_ONLY=0; QDISC_POLICY=manage
create_backup eth0 1 '最近一次调优前' 0 >/dev/null
touch "$BACKUP_ROOT/02-latest/qdisc-changed"
''')
    seeded=subprocess.run([bash,str(seed),str(state),name],env=env,capture_output=True,text=True,timeout=5)
    assert seeded.returncode==0,seeded
    write_sysctls(state,tuned)
    live=[{'kind':'fq','handle':'1:','root':True,'options':defaults['fq']}]
    if name in {'mq','partial-queue'}:
        live=[saved[0]]+[{**q,'kind':'fq','options':defaults['fq']} for q in saved[1:]]
    (state/'live.json').write_text(json.dumps(live))
    for filename in ['sysctl','modules','env','helper','service']:
        (state/'config'/filename).write_text('# Tuned '+filename+'\n')
    (state/'config/helper').chmod(0o755)
    (state/'service-enabled').write_text('enabled\n'); (state/'service-active').write_text('active\n')
    (state/'active-session').write_text('02-latest\n')
    (state/'history.tsv').write_text('history must survive\n')
    for id in ['01-initial','02-latest']:
        pending=state/'pending'/id; pending.mkdir(parents=True)
        (pending/'armed').write_text('token\n'); (pending/'backup').write_text(str(state/'backups'/id)+'\n')
    (state/'pending-latest').symlink_to(state/'pending/02-latest')
    before_sysctls=read_sysctls(state); before_config=configs(state); before_queue=(state/'live.json').read_text()
    initial=state/'backups/01-initial'
    if name=='missing-original': (state/'original-backup').write_text('missing\n')
    if name=='missing-file': (initial/'modules.file').unlink()
    if name=='legacy-sysctls': (initial/'full-sysctl.tsv').unlink()
    if name=='incomplete-sysctls':
        p=initial/'full-sysctl.tsv'; p.write_text(''.join(s for s in p.read_text().splitlines(True) if not s.startswith('net.core.wmem_max\t')))
    if name=='unsupported-cc':
        values=dict(tuned, **{'net.ipv4.tcp_available_congestion_control':'reno bbr'}); write_sysctls(state,values)
        before_sysctls=read_sysctls(state)
    if name=='legacy-queue': (initial/'qdisc-original.json').unlink()
    if name=='corrupt-queue': (initial/'qdisc-original.json').write_text('[]')
    if name=='filters': (state/'filters.json').write_text('[{"kind":"bpf"}]')
    if name in {'fail-namespace','fail-sysctl','false-sysctl','interrupt-sysctl','fail-file','false-delete','fail-service-stop','false-service-enable'}:
        (state/name).touch()
    if name=='fail-queue': (state/'fail-parent').write_text('root\n')
    if name=='partial-queue': (state/'fail-parent').write_text('1:2\n')
    if name=='default-mq-reset-mismatch': (state/'bad-default-reset').touch()
    if name=='default-mq-fail-sysctl': (state/'fail-sysctl').touch()
    if name=='default-mq-foreign-driver': (state/'device.json').write_text('[{"parentbus":"pci","num_tx_queues":2}]')
    if name=='default-mq-extra-tx': (state/'queues/tx-1').mkdir()
    if name=='default-mq-fail-tap': (state/'fail-tap').touch()
    if name=='default-mq-filters': (state/'filters.json').write_text('[{"kind":"bpf"}]')
    if name=='default-mq-changed-default':
        values=read_sysctls(state); values['net.core.default_qdisc']='fq_codel'; write_sysctls(state,values)
        before_sysctls=read_sysctls(state)
    if name=='default-mq-unsupported-weights': (state/'unsupported-weights').touch()
    if name=='default-mq-interrupt-reset': (state/'interrupt-root-reset').touch()
    original_files={f.name:f.read_bytes() for f in initial.iterdir() if f.is_file()}
    inputs=b'n\n' if name in {'cancel','default-mq-cancel'} else b'2\ny\n' if name=='menu-clear' else None
    result=run(state,name,inputs)
    screen=result.stdout+result.stderr
    should_succeed=name not in early_failures|recovered_failures|{'fail-service-stop','fail-queue'}
    assert (result.returncode==0)==should_succeed,(name,screen)
    assert (state/'history.tsv').read_text()=='history must survive\n',(name,screen)
    assert (state/'latest').readlink()==state/'backups/02-latest',(name,screen)
    assert {f.name:f.read_bytes() for f in initial.iterdir() if f.is_file()}==original_files,(name,screen)
    assert not list(state.glob('bbrq-*.json')),(name,screen)
    undo_backups=list((state/'backups').glob('clear-*'))
    if name in early_failures|{'cancel','default-mq-cancel'}:
        assert not undo_backups and not (state/'sysctl-writes').exists(),(name,screen)
        assert configs(state)==before_config and (state/'live.json').read_text()==before_queue,(name,screen)
        assert (state/'pending-latest/armed').exists() and (state/'active-session').exists(),(name,screen)
    elif name in recovered_failures:
        assert len(undo_backups)==1 and '已恢复清理前状态' in screen,(name,screen)
        assert read_sysctls(state)==before_sysctls and configs(state)==before_config,(name,screen)
        assert json.loads((state/'live.json').read_text())==json.loads(before_queue),(name,screen)
        assert (state/'pending-latest/armed').exists() and (state/'active-session').exists(),(name,screen)
        assert '调优参数已清理：' not in screen,(name,screen)
    elif name=='fail-service-stop':
        assert undo_backups and '清理前状态也未完整恢复' in screen,(name,screen)
        assert (state/'pending-latest/armed').exists() and (state/'active-session').exists(),(name,screen)
    elif name=='confirm-rollback':
        assert read_sysctls(state)==latest and '调优前备份仍然保留' in screen,(name,screen)
    else:
        assert read_sysctls(state)==original and configs(state)==initial_config,(name,screen)
        expected_queue=json.loads(json.dumps(saved))
        if name=='default-mq-older-tc': expected_queue[1]['options']['offload_horizon']=0
        assert json.loads((state/'live.json').read_text())==expected_queue,(name,screen)
        assert not (state/'pending-latest').exists() and not (state/'active-session').exists(),(name,screen)
        assert not list((state/'pending').glob('*')),(name,screen)
        assert len(undo_backups)==1 and '调优参数已清理：' in screen,(name,screen)
        if name=='repeat':
            repeated=run(state,name)
            assert repeated.returncode==0,(name,repeated)
            assert read_sysctls(state)==original and configs(state)==initial_config,(name,repeated)
        if name in {'undo','default-mq-undo'}:
            undo=tmp/'undo.sh'; undo.write_text(prelude+'''\nBACKUP_PATH="$3"; YES=1\nrollback_command\n''')
            undone=subprocess.run([bash,str(undo),str(state),name,str(undo_backups[0])],env=env,capture_output=True,text=True,timeout=5)
            assert undone.returncode==0,(name,undone)
            assert read_sysctls(state)==before_sysctls and configs(state)==before_config,(name,undone,read_sysctls(state),before_sysctls,configs(state),before_config)
            assert json.loads((state/'live.json').read_text())==json.loads(before_queue),(name,undone)
print(f'All {len(cases)} clearing, persistence, confirmation, cancellation and recovery scenarios passed.')
PY
