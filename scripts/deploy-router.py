#!/usr/bin/env python3
"""Deploy an accepted WSL candidate, retaining container settings and full rollback.

Passwords are read from the terminal only. A matching pre-existing SSH host key
is mandatory. No build or test container runs on the production router.
"""
import argparse
import copy
from datetime import datetime, timezone
import getpass
import hashlib
import http.client
import importlib
import json
from pathlib import Path
import shlex
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.tools/deploy-python'))
import paramiko

def create_payload(old,image):
    """Docker's create API preserves fields that a hand-written CLI can miss."""
    host=copy.deepcopy(old['HostConfig'])
    if host['NetworkMode']!='host' or host.get('AutoRemove') or host.get('ContainerIDFile'):
        raise ValueError('Expected a persistent host-network container without a CID file')
    data=next((m for m in old['Mounts'] if m['Destination']=='/data'),None)
    if not data or data['Type'] not in ['volume','bind']:
        raise ValueError('A persistent /data mount is required')
    if not any(':\u002fdata' in b for b in host.get('Binds') or []) and not any(m['Target']=='/data' for m in host.get('Mounts') or []):
        raise ValueError('Anonymous data mount must be made explicit before deployment')
    config=copy.deepcopy(old['Config']);config['Image']=image
    return dict(config,HostConfig=host)

class Router:
    def __init__(self,args):
        self.args=args;self.ssh=paramiko.SSHClient()
        self.ssh.load_host_keys(str(args.known_hosts));self.ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        password=getpass.getpass('Router SSH password: ')
        self.ssh.connect(args.host,port=args.port,username='root',password=password,look_for_keys=False,allow_agent=False,timeout=10)
        del password
        self.ssh.get_transport().set_keepalive(10)
    def run(self,argv,timeout=60):
        _,out,err=self.ssh.exec_command(shlex.join(list(map(str,argv))),timeout=timeout)
        data=out.read();error=err.read();code=out.channel.recv_exit_status()
        if code:raise RuntimeError('Remote command failed: '+error.decode(errors='replace')[-800:])
        return data
    def docker(self,*args,**kw):return self.run([self.args.docker,*args],**kw)
    def inspect(self,name):return json.loads(self.docker('inspect',name))[0]
    def api(self,method,path,body=None):
        channel=self.ssh.get_transport().open_session(timeout=15);channel.settimeout(60)
        channel.exec_command(shlex.join([self.args.docker,'system','dial-stdio']))
        data=b'' if body is None else json.dumps(body).encode()
        header=f'{method} {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n'.encode()
        try:
            channel.sendall(header+data);response=http.client.HTTPResponse(channel);response.begin();result=response.read()
            if response.status>=300:raise RuntimeError('Docker API '+str(response.status)+': '+result.decode(errors='replace')[:800])
            return json.loads(result) if result else {}
        finally:channel.close()
    def upload(self,file,folder):
        channel=self.ssh.get_transport().open_session();channel.exec_command('scp -t '+shlex.quote(folder))
        def ack():
            if channel.recv(1)!=b'\0':raise RuntimeError('Image transfer rejected')
        try:
            ack();channel.sendall(f'C0600 {file.stat().st_size} {file.name}\n'.encode());ack()
            with file.open('rb') as stream:
                while block:=stream.read(1024*1024):channel.sendall(block)
            channel.sendall(b'\0');ack()
        finally:channel.close()

def business_probes(host,config,router=None):
    """Read-only probes of existing IPv4 entries; never send arbitrary payloads."""
    result={}
    for rule in config.get('rules',[]):
        if not rule.get('enabled'):continue
        port=int(rule['listen'].rsplit(':',1)[1]);key=rule['id']
        try:
            if rule['kind']=='web':
                for route in rule.get('routes',[]):
                    if not route.get('enabled'):continue
                    domain=next((d for d in route.get('domains',[]) if '*' not in d),host)
                    prefix=route.get('pathPrefix') or '/'
                    if rule.get('network')!='ipv6':
                        if rule.get('tls'):
                            conn=http.client.HTTPSConnection(domain,port,timeout=8,context=ssl.create_default_context())
                            conn._create_connection=lambda address,timeout,source_address=None:socket.create_connection((host,port),timeout,source_address)
                        else:conn=http.client.HTTPConnection(host,port,timeout=8)
                        try:
                            conn.request('GET',urllib.parse.quote(prefix,safe='/'),headers={'Host':domain,'Connection':'close'})
                            reply=conn.getresponse();reply.read(4096);result[key+':'+route['id']]='HTTP '+str(reply.status)
                        finally:conn.close()
                    if router and rule.get('network') in ['dual','ipv6']:
                        channel=router.ssh.get_transport().open_channel('direct-tcpip',('::1',port),('::1',0));channel.settimeout(8)
                        try:
                            channel.sendall(f'GET {urllib.parse.quote(prefix,safe="/")} HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n'.encode())
                            reply=http.client.HTTPResponse(channel);reply.begin();reply.read(4096);result[key+':'+route['id']+':ipv6-loopback']='HTTP '+str(reply.status)
                        finally:channel.close()
            elif rule['kind'] in ['tcp','tcpudp']:
                if rule.get('network')=='ipv6':continue
                with socket.create_connection((host,port),timeout=8):pass
                result[key]='TCP connected'
        except (OSError,http.client.HTTPException):result[key]='unreachable'
    return result

def data_manifest(router,helper,source,kind):
    output=router.docker('run','--rm','--network','none','--cap-drop','ALL','--read-only','--security-opt','no-new-privileges:true','--mount',f'type={kind},source={source},target=/backup,readonly',helper,'sh','-ec','cd /backup; find . -type f -exec sha256sum {} + | sort',timeout=180)
    return hashlib.sha256(output).hexdigest()

def health(host,port,version):
    client=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(50):
        try:
            with client.open(f'http://{host}:{port}/api/health',timeout=3) as response:
                state=json.load(response)
            if state.get('ok') and state.get('version')==version:return
        except (OSError,ValueError):pass
        time.sleep(1)
    raise RuntimeError('Candidate health/version check failed')

def rollback(router,record):
    name=record['container'];old=record['old'];folder=record['remoteFolder']
    current=router.inspect(name)
    if current['Id']!=record['newID']:raise RuntimeError('Container changed; refusing automatic rollback')
    router.docker('stop','--time','40',name)
    router.run(['mkdir','-p',folder+'/failed-data'])
    router.docker('cp','-a',name+':/data/.',folder+'/failed-data/')
    # The helper can access only the explicitly inspected data mount, no network.
    data=next(m for m in old['Mounts'] if m['Destination']=='/data')
    source=data.get('Name') if data['Type']=='volume' else data['Source']
    mount=f"type={data['Type']},source={source},target=/restore"
    router.docker('run','--rm','--network','none','--cap-drop','ALL','--read-only','--security-opt','no-new-privileges:true','--mount',mount,record['helperID'],'sh','-ec','test -f /restore/master.key; find /restore -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +')
    router.docker('cp','-a',folder+'/data/.',name+':/data/')
    if data_manifest(router,record['helperID'],source,data['Type'])!=record['dataManifestSHA256']:
        raise RuntimeError('Restored data does not match the backup; both containers remain stopped')
    router.docker('rm',name)
    router.docker('rename',record['oldName'],name)
    router.docker('start',name)
    record['result']='rolled-back';record['newID']=''

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host',default='10.31.0.1');p.add_argument('--port',type=int,default=22)
    p.add_argument('--known-hosts',type=Path,required=True)
    p.add_argument('--docker',default='/mnt/docker_disk/mi_docker/docker-binaries/docker')
    p.add_argument('--container',default='linknest');p.add_argument('--admin-port',type=int,default=17880)
    p.add_argument('--stage',type=Path,default=ROOT/'.tools'/('validation-'+importlib.import_module('release-wsl').source_version()))
    p.add_argument('--preflight',action='store_true');p.add_argument('--rollback',type=Path)
    args=p.parse_args();router=Router(args)
    try:
        if args.rollback:
            record=json.loads(args.rollback.read_text(encoding='utf-8'));rollback(router,record);args.rollback.write_text(json.dumps(record,indent=2),encoding='utf-8');print('Old image and pre-upgrade data restored');return
        old=router.inspect(args.container);create_payload(old,old['Image'])
        api_version=router.api('GET','/version')['ApiVersion']
        if not old['State']['Running']:raise RuntimeError('Production container is not running')
        router.run(['sh','-ec','test -r /proc/sys/net/ipv4/ip_forward; test -r /proc/sys/net/ipv6/conf/all/forwarding; test -w /run/xtables.lock; iptables -t nat -S >/dev/null; ip6tables -t nat -S >/dev/null'])
        config=json.loads(router.docker('exec',args.container,'cat','/data/config.json'))
        summary={'containerID':old['Id'],'image':old['Image'],'network':old['HostConfig']['NetworkMode'],'dockerAPI':api_version,'rules':[{'id':r['id'],'kind':r['kind'],'enabled':r.get('enabled'),'network':r.get('network'),'listen':r['listen'],'mode':r.get('forwardMode')} for r in config.get('rules',[])]}
        print(json.dumps(summary,ensure_ascii=False),flush=True)
        if args.preflight:return
        gate=json.loads((args.stage/'accepted.json').read_text(encoding='utf-8'))
        if gate['sourceSHA256']!=importlib.import_module('release-wsl').source_digest():raise RuntimeError('Source differs from accepted source')
        for file,key in [('candidate-arm64.tar','archiveSHA256'),('rollback-helper-arm64.tar','helperArchiveSHA256')]:
            if hashlib.sha256((args.stage/file).read_bytes()).hexdigest()!=gate[key]:raise RuntimeError('Accepted archive changed')
        stamp=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S');folder='/mnt/docker_disk/mi_docker/linknest-backups/'+stamp
        router.run(['mkdir','-p',folder+'/data']);router.run(['chmod','700',folder,folder+'/data'])
        for file in ['candidate-arm64.tar','rollback-helper-arm64.tar']:
            router.upload(args.stage/file,folder);router.docker('load','-i',folder+'/'+file,timeout=180)
        image=gate['images']['arm64']['id'];router.docker('image','inspect',image);router.docker('image','inspect',gate['helperID'])
        before=business_probes(args.host,config,router)
        router.docker('image','save','-o',folder+'/old-image.tar',old['Image'],timeout=180)
        latest=router.inspect(args.container)
        if latest['Id']!=old['Id'] or latest['Image']!=old['Image']:raise RuntimeError('Production container changed during preflight')
        record={'container':args.container,'old':old,'oldName':args.container+'-rollback-'+stamp,'oldRenamed':False,'newID':'','image':image,'helperID':gate['helperID'],'remoteFolder':folder,'before':before,'result':'prepared'}
        record_file=args.stage/('deployment-'+stamp+'.json')
        def save():record_file.write_text(json.dumps(record,indent=2),encoding='utf-8')
        save();router.docker('stop','--time','40',args.container)
        try:
            router.docker('cp','-a',args.container+':/data/.',folder+'/data/')
            router.run(['sh','-ec','test -s "$1/config.json" && test -s "$1/master.key" && test -s "$1/auth.json"','sh',folder+'/data'])
            data=next(m for m in old['Mounts'] if m['Destination']=='/data')
            record['dataManifestSHA256']=data_manifest(router,gate['helperID'],data.get('Name') if data['Type']=='volume' else data['Source'],data['Type'])
            if data_manifest(router,gate['helperID'],folder+'/data','bind')!=record['dataManifestSHA256']:raise RuntimeError('Production backup differs from the stopped data volume')
            router.docker('rename',args.container,record['oldName']);record['oldRenamed']=True;save()
            created=router.api('POST','/containers/create?name='+urllib.parse.quote(args.container),create_payload(old,image))
            record['newID']=created['Id'];save();router.docker('start',args.container)
            health(args.host,args.admin_port,gate['version'])
            time.sleep(3)
            current=router.inspect(args.container)
            if current['Image']!=image or current['RestartCount']!=0:raise RuntimeError('Image identity/restart check failed')
            new_config=json.loads(router.docker('exec',args.container,'cat','/data/config.json'))
            if new_config['schema']!=5:raise RuntimeError('Configuration migration failed')
            after=business_probes(args.host,new_config,router)
            if any(after.get(key)!=value for key,value in before.items() if value!='unreachable'):raise RuntimeError('Existing business endpoint regressed')
            for rule in new_config.get('rules',[]):
                if rule.get('enabled') and rule.get('forwardMode')=='kernel':
                    binary='ip6tables-legacy-save' if rule.get('network')=='ipv6' else 'iptables-legacy-save'
                    rules=router.docker('exec',args.container,binary,'-t','nat').decode()
                    port=rule['listen'].rsplit(':',1)[1]
                    if not any('LNEST_' in line and '--dport '+port in line for line in rules.splitlines()):raise RuntimeError('Missing kernel forwarding rule')
            record.update(result='deployed',after=after);save()
            print(json.dumps({'result':'deployed','version':gate['version'],'image':image,'backup':folder,'rollbackRecord':str(record_file),'business':after},ensure_ascii=False))
        except BaseException:
            if record['newID']:rollback(router,record)
            else:
                # Creation failed before the candidate could touch the volume.
                if record['oldRenamed'] and router.inspect(record['oldName'])['Id']==old['Id']:router.docker('rename',record['oldName'],args.container)
                router.docker('start',args.container);record['result']='restored-before-start'
            save();raise
    finally:router.ssh.close()

if __name__=='__main__':main()
