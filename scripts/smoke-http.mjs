// Only a fresh disposable localhost instance. Never reuse production credentials.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';

const base=new URL(process.argv[2]||'http://127.0.0.1:18890/');
if(base.protocol!=='http:'||base.hostname!=='127.0.0.1'||process.argv[4]!=='--disposable')throw Error('Use an explicitly disposable localhost test instance');
const token=fs.readFileSync(process.argv[3],'utf8').trim();let cookie='';
async function call(path,method='GET',data){const res=await fetch(new URL('api/'+path,base),{method,redirect:'manual',headers:{'X-LinkNest-Request':'1','Content-Type':'application/json',...(cookie?{Cookie:cookie}:{})},body:data===undefined?undefined:JSON.stringify(data),signal:AbortSignal.timeout(45000)});if(res.headers.get('set-cookie'))cookie=res.headers.get('set-cookie').split(';')[0];const body=await res.json();if(!res.ok)throw Error(`${path}: HTTP ${res.status}: ${body.error}`);return body;}
assert.equal((await call('health')).initialized,false,'Not a fresh disposable instance');
const password=crypto.randomBytes(24).toString('hex');await call('setup','POST',{token,username:'qa',password});await call('login','POST',{username:'qa',password});
let state=await call('state');assert.equal(state.version,'1.0.0');assert.equal(state.config.schema,4);assert.equal(state.firewall.enabled,false);assert.equal(state.config.access.autoBan.enabled,false);
await call('access/ban','POST',{ip:'203.0.113.8',seconds:60});assert.equal((await call('access/state')).access.bans.length,1);await call('access/unban','POST',{ip:'203.0.113.8'});assert.equal((await call('access/state')).access.bans.length,0);
const cfg=state.config,adminPort=Number(state.adminAddress.split(':').at(-1));assert.ok(adminPort>=1024&&adminPort<=65535);cfg.rules=[{id:'qa-http',name:'Local HTTP',kind:'web',enabled:true,listen:'127.0.0.1:28080',target:'http://127.0.0.1:'+adminPort,openFirewall:false},{id:'qa-tcp',name:'Local TCP',kind:'tcp',enabled:true,listen:'127.0.0.1:28082',target:'127.0.0.1:'+adminPort,openFirewall:false}];await call('config','PUT',cfg);state=await call('state');assert.ok(state.rules.every(r=>r.state==='running'));assert.equal(state.config.rules[0].routes.length,1);
for(const asset of ['security.js','workflows.js','portal.css','portal.js','certificates.js','navigation.js'])assert.equal((await fetch(new URL(asset,base))).status,200);
// One real request to the IPv6 feed only; IPv4 is not requested by this smoke test.
if(process.argv.includes('--live-feed')){
 cfg.access.sources=[{id:'qa-spamhaus-v6',name:'Spamhaus Project DROP IPv6',url:'https://www.spamhaus.org/drop/drop_v6.json',format:'spamhaus',enabled:true,intervalHours:24}];await call('config','PUT',cfg);await call('access/update','POST',{id:'qa-spamhaus-v6'});const feed=(await call('access/state')).access.sources[0];assert.ok(feed.count>0);assert.equal(feed.error,'');console.log('Official Spamhaus IPv6 JSON parsed and cached:',feed.count,'networks');
}
cfg.rules=[];cfg.access.sources=[];await call('config','PUT',cfg);await call('logout','POST',{});assert.equal((await call('health')).authenticated,false);
console.log('Disposable ARM64 HTTP smoke passed: setup / auth / schema / ban / unban / routing / assets / stop / logout.');
