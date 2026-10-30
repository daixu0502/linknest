#!/usr/bin/env python3
"""Publish exactly the WSL-accepted and router-verified images to Docker Hub."""
import argparse, getpass, hashlib, importlib, json, re, subprocess, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stage',type=Path,default=ROOT/'.tools'/('validation-'+importlib.import_module('release-wsl').source_version()))
    p.add_argument('--registry-proxy',help='HTTP proxy for WSL registry commands, including Buildx')
    p.add_argument('--source-worktree',type=Path,required=True)
    p.add_argument('--deployment',type=Path,required=True)
    args=p.parse_args();release=importlib.import_module('release-wsl');source=args.source_worktree.resolve()
    gate=json.loads((args.stage/'accepted.json').read_text(encoding='utf-8'))
    deployment=json.loads(args.deployment.read_text(encoding='utf-8'))
    if deployment['result']!='deployed' or deployment['image']!=gate['images']['arm64']['id']:
        raise RuntimeError('Router verification of this exact candidate is required')
    git=['git','-c','safe.directory='+source.as_posix(),'-C',str(source)]
    if release.run(git+['status','--porcelain']) or release.source_digest(source)!=gate['sourceSHA256']:
        raise RuntimeError('Use a clean committed worktree matching the accepted source')
    for name,key in [('candidate-arm64.tar','archiveSHA256'),('rollback-helper-arm64.tar','helperArchiveSHA256')]:
        if hashlib.sha256((args.stage/name).read_bytes()).hexdigest()!=gate[key]:raise RuntimeError('Accepted archive changed')
    repository='jacoyyyy/linknest';version=gate['version'];token=getpass.getpass('Docker Hub token: ')
    with tempfile.TemporaryDirectory(prefix='registry-auth-',dir=ROOT/'.tools') as directory:
        # Only this newly created authentication directory is removed on exit.
        assert Path(directory).resolve().parent==(ROOT/'.tools').resolve()
        proxy=['env','HTTP_PROXY='+args.registry_proxy,'HTTPS_PROXY='+args.registry_proxy] if args.registry_proxy else []
        docker=['wsl.exe','--exec',*proxy,'docker','--context','default','--config',release.linux_path(directory)]
        def command(*values):return release.run(docker+list(values))
        try:
            login=subprocess.run(docker+['login','-u','jacoyyyy','--password-stdin'],input=(token+'\n').encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            del token
            if login.returncode:raise RuntimeError('Docker Hub login failed; no image was published')
            for arch,image in gate['images'].items():
                tag=f'{repository}:{version}-{arch}'
                command('tag',image['tag'],tag);command('push',tag);command('pull','--platform','linux/'+arch,tag)
                if json.loads(command('image','inspect','--platform','linux/'+arch,tag))[0]['Id']!=image['localID']:raise RuntimeError('Remote architecture image differs from accepted image')
            tag=f'{repository}:{version}'
            command('buildx','imagetools','create','--tag',tag,tag+'-amd64',tag+'-arm64')
            manifest=json.loads(command('buildx','imagetools','inspect',tag,'--raw'))
            architectures={m.get('platform',{}).get('architecture') for m in manifest['manifests']}
            if not {'amd64','arm64'}<=architectures:raise RuntimeError('Missing published architecture')
            def digest(tag):
                return re.search(r'^Digest:\s+(sha256:[a-f0-9]{64})',command('buildx','imagetools','inspect',tag),re.M)[1]
            published=digest(tag)
            command('buildx','imagetools','create','--tag',repository+':latest',repository+'@'+published)
            if digest(repository+':latest')!=published:raise RuntimeError('latest digest mismatch')
            result={'version':version,'digest':published,'sourceCommit':release.run(git+['rev-parse','HEAD']),'images':gate['images'],'routerImage':deployment['image']}
            (args.stage/'published.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result,indent=2))
        finally:
            subprocess.run(docker+['logout','docker.io'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__=='__main__':main()
