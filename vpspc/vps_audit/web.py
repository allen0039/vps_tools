from __future__ import annotations
import argparse
import hmac
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlsplit
from .behavior_audit import list_incidents, load_incident
from .runtime import health, load_runtime_config, review_behavior_incident, run_cycle

PAGE = """<!doctype html><html lang=zh-CN><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>VPSPC 审计台</title>
<style>body{margin:0;background:#11161b;color:#e8edf2;font:14px system-ui,-apple-system,sans-serif}main{max-width:1180px;margin:auto;padding:24px}h1{font-size:24px;margin:0 0 4px}.muted{color:#91a0ad}.bar,.actions{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap;margin-bottom:18px}button{background:#2f81f7;color:#fff;border:0;border-radius:5px;padding:9px 14px;cursor:pointer}button:disabled{opacity:.5}input{flex:1;min-width:220px;background:#0d1117;color:#e8edf2;border:1px solid #3c4a57;border-radius:5px;padding:9px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}.stat,section{background:#1a222b;border:1px solid #2d3945;border-radius:6px;padding:14px}.stat b{display:block;font-size:22px;margin-top:5px}section{margin:12px 0}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 7px;border-bottom:1px solid #2d3945;vertical-align:top}tr:hover{background:#202b36}.sev-critical,.sev-high{color:#ff7b72}.sev-medium{color:#d29922}.sev-low{color:#7ee787}.detail{white-space:pre-wrap;background:#0d1117;padding:12px;border-radius:4px;overflow:auto}@media(max-width:760px){main{padding:14px}.grid{grid-template-columns:repeat(2,1fr)}th:nth-child(n+4),td:nth-child(n+4){display:none}}</style>
<main><div class=bar><div><h1>VPSPC 审计台</h1><span class=muted>连接元数据、行为规则与人工 AI 复核</span></div><button id=run>立即巡查</button></div><div id=stats class=grid></div><section><h2>行为事件</h2><div id=incidents>加载中...</div></section><section><h2>报告 / 事件详情</h2><div id=ai-actions class=actions hidden><input id=question placeholder='可选：输入需要 AI 进一步判断的问题'><button id=ai>AI 复核</button></div><div id=report class=detail>加载中...</div></section></main>
<script>
const token=prompt('输入 Web Token'); if(!token) document.body.innerHTML='<main><h1>需要 Web Token</h1></main>';
const headers={'X-Web-Token':token||''};const api=async(u,o={})=>{o.headers={...headers,...(o.headers||{})};const r=await fetch(u,o);if(!r.ok)throw new Error(await r.text());return r.json()};const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function load(){try{const[h,r,i]=await Promise.all([api('/api/health'),api('/api/report'),api('/api/incidents')]);document.querySelector('#stats').innerHTML='<div class=stat>状态<b>'+esc(h.status)+'</b></div><div class=stat>事件<b>'+esc(r.summary?.event_count||0)+'</b></div><div class=stat>发现<b>'+esc(r.summary?.finding_count||0)+'</b></div><div class=stat>用户<b>'+esc(r.summary?.user_count||0)+'</b></div>';document.querySelector('#report').textContent=JSON.stringify(r,null,2);document.querySelector('#incidents').innerHTML=i.length?'<table><tr><th>ID</th><th>用户</th><th>等级</th><th>规则</th><th>节点</th><th>时间</th></tr>'+i.map(x=>'<tr data-id="'+esc(x.incident_id)+'"><td>'+esc(x.incident_id)+'</td><td>'+esc(x.user)+'</td><td class=sev-'+esc(x.severity)+'>'+esc(x.severity)+'</td><td>'+esc(x.rule_id)+'</td><td>'+esc(x.node_name||x.node_id||'-')+'</td><td>'+esc(x.generated_at)+'</td></tr>').join('')+'</table>':'暂无事件';document.querySelectorAll('tr[data-id]').forEach(e=>e.onclick=()=>detail(e.dataset.id))}catch(e){document.querySelector('#report').textContent=e.message}}
let currentIncident='';async function detail(id){try{currentIncident=id;document.querySelector('#ai-actions').hidden=false;document.querySelector('#report').textContent=JSON.stringify(await api('/api/incidents/'+encodeURIComponent(id)),null,2)}catch(e){alert(e.message)}}document.querySelector('#ai').onclick=async()=>{if(!currentIncident)return;document.querySelector('#ai').disabled=true;try{const result=await api('/api/incidents/'+encodeURIComponent(currentIncident)+'/ai',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({question:document.querySelector('#question').value})});document.querySelector('#report').textContent=JSON.stringify(result,null,2)}catch(e){alert(e.message)}finally{document.querySelector('#ai').disabled=false}};document.querySelector('#run').onclick=async()=>{document.querySelector('#run').disabled=true;try{await api('/api/run',{method:'POST'});await load()}catch(e){alert(e.message)}finally{document.querySelector('#run').disabled=false}};load();setInterval(load,30000);
</script>"""

def _read_token(path: str) -> str:
    value=Path(path).read_text(encoding='utf-8').strip()
    if not value or len(value)>512: raise ValueError('Web token file is empty or invalid')
    return value

def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value,ensure_ascii=False,separators=(',',':'))+'\n').encode('utf-8')

def create_handler(config_path: str):
    expected=_read_token(str(load_runtime_config(config_path)['web']['token_file']))
    class Handler(BaseHTTPRequestHandler):
        server_version='VPSPCWeb/1.0'
        def log_message(self,fmt: str,*args: Any)->None: sys.stderr.write('vps-audit-web: '+(fmt%args)+'\n')
        def _authorized(self)->bool:
            supplied=self.headers.get('X-Web-Token','')
            if not supplied:
                auth=self.headers.get('Authorization','')
                if auth.lower().startswith('bearer '): supplied=auth[7:].strip()
            return hmac.compare_digest(supplied,expected)
        def _send(self,status: int,value: Any,content_type: str='application/json')->None:
            body=value.encode('utf-8') if isinstance(value,str) else _json_bytes(value)
            self.send_response(status);self.send_header('Content-Type',content_type+'; charset=utf-8');self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(body)
        def _read_json(self)->Dict[str,Any]:
            length=int(self.headers.get('Content-Length','0'))
            if length>64*1024: raise ValueError('request body too large')
            value=json.loads((self.rfile.read(length) if length else b'{}').decode('utf-8'))
            if not isinstance(value,dict): raise ValueError('request body must be an object')
            return value
        def do_GET(self)->None:
            if not self._authorized(): self._send(401,{'error':'unauthorized'});return
            path=urlsplit(self.path).path.rstrip('/') or '/'
            try:
                current=load_runtime_config(config_path)
                if path=='/': self._send(200,PAGE,'text/html')
                elif path=='/api/health': self._send(200,health(config_path))
                elif path=='/api/report':
                    report_path=Path(current['report_dir'])/'latest.json';self._send(200,json.loads(report_path.read_text(encoding='utf-8')) if report_path.exists() else {})
                elif path=='/api/incidents': self._send(200,list_incidents(Path(current['behavior_audit']['archive_dir']),100))
                elif path.startswith('/api/incidents/'): self._send(200,load_incident(Path(current['behavior_audit']['archive_dir']),path.rsplit('/',1)[-1].upper()))
                else: self._send(404,{'error':'not found'})
            except (OSError,ValueError,json.JSONDecodeError) as exc: self._send(400,{'error':str(exc)})
        def do_POST(self)->None:
            if not self._authorized(): self._send(401,{'error':'unauthorized'});return
            path=urlsplit(self.path).path.rstrip('/')
            try:
                if path=='/api/run': self._send(200,{'ok':True,'report':run_cycle(config_path)})
                elif path.startswith('/api/incidents/') and path.endswith('/ai'):
                    body=self._read_json();identifier=path.split('/')[-2].upper();review=review_behavior_incident(config_path,identifier,str(body.get('question',''))[:2000]);self._send(200,{'ok':True,'review':review})
                else: self._send(404,{'error':'not found'})
            except (OSError,ValueError,RuntimeError,json.JSONDecodeError) as exc: self._send(400,{'error':str(exc)})
    return Handler

def serve(config_path: str)->None:
    config=load_runtime_config(config_path);web=config['web']
    if not web.get('enabled'): raise ValueError('Web management is disabled in the runtime config')
    server=ThreadingHTTPServer((str(web['listen_host']),int(web['listen_port'])),create_handler(config_path));print(f"vps-audit-web listening on {web['listen_host']}:{web['listen_port']}",flush=True)
    try: server.serve_forever()
    finally: server.server_close()

def main(argv: List[str]|None=None)->int:
    parser=argparse.ArgumentParser(prog='vps-audit-web');parser.add_argument('--config',default='/etc/vps-audit/config.json');args=parser.parse_args(argv)
    try: serve(args.config)
    except (OSError,ValueError,json.JSONDecodeError) as exc: print(f'vps-audit-web: {exc}',file=sys.stderr);return 1
    return 0

if __name__=='__main__': raise SystemExit(main())
