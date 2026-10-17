import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
let saved,dialogResult;
const ctx={location:{hash:'#/forwards/upnp'},document:{addEventListener(){}},queueMicrotask(){},setInterval(){},loggedIn:true,page:'forwards',structuredClone,
 state:{interfaces:[{name:'br-lan'}],config:{sshHosts:[]},twoFactor:{enabled:false}},
 esc:v=>String(v??'').replaceAll('<','&lt;'),pill:String,icon:()=>'',ibtn:()=>'<button>test</button>',btn:()=>'',panel:(t,s,b)=>b,actionNote:s=>s,functionNote:s=>s,statusNote:s=>s,empty:(t,s)=>t+s,notice:String,
 field:(n,l,v)=>n+':'+v,picker:(n,l,v)=>n+':'+v,toggle:(n,l,v,h)=>n+l+(h||''),area:n=>n,uid:()=> 'new-id',nextTwoFactorDialog:fn=>fn(),
 dialog:(title,body,save)=>{dialogResult={title,body,save}},api:async(path,method,data)=>{if(path==='upnp/state')return fixture;saved={path,method,data};return{message:'done'}},toast(){},async refresh(){},navigatePage:(...p)=>{ctx.route=p},$:()=>null,$$:()=>[],
};vm.createContext(ctx);vm.runInContext(fs.readFileSync(new URL('../web/upnp.js',import.meta.url),'utf8'),ctx);
assert.equal(ctx.forwardTab(),'upnp');assert.match(ctx.forwardTabs(),/路由器 UPnP/);assert.match(ctx.upnpPage(),/upnp-mappings/);
await ctx.upnpAction('forward-tab:rules');assert.equal(ctx.route.join('/'),'forwards/rules');
const source=fs.readFileSync(new URL('../web/upnp.js',import.meta.url),'utf8');
const fixture={config:{enabled:true,writePolicy:'service',descriptionUrl:'http://192.168.1.1:5351/rootDesc.xml',interface:'br-lan',lanZone:'lan',blacklist:[]},mappings:[{protocol:'TCP',externalPort:6881,internalIP:'192.168.1.3',internalPort:6881,enabled:true,description:'test',remoteHost:'',leaseSeconds:60}]};
vm.runInContext('upnpState='+JSON.stringify(fixture),ctx);
ctx.upnpEditMapping(0);assert.match(dialogResult.title,/编辑/);await dialogResult.save({description:'changed',protocol:'UDP',externalPort:'6882',internalIP:'192.168.1.4',internalPort:'8080',remoteHost:'',leaseSeconds:'3600'});
assert.equal(saved.path,'upnp/mapping');assert.equal(saved.data.operation,'edit');assert.equal(saved.data.before.externalPort,6881);assert.equal(saved.data.after.externalPort,6882);
await ctx.upnpAction('upnp-delete:0');assert.match(dialogResult.body,/重新申请/);await dialogResult.save();assert.equal(saved.data.operation,'delete');
ctx.upnpPolicyDialog();assert.match(dialogResult.title,/可信/);await dialogResult.save();assert.equal(ctx.route[0],'terminal');
ctx.state.upnpPorts={managementEnabled:true,enabled:false,forwardPorts:[6082,6881]};
ctx.upnpPortsDialog(true);assert.match(dialogResult.title,/可信/);
ctx.state.config.sshHosts=[{id:'router',username:'root',fingerprint:'verified',address:'192.168.1.1:22',name:'router'}];
vm.runInContext('upnpState.forwardPorts=[6082,6881];upnpState.config.portProtection=true;upnpState.config.protectedPorts=[6082];upnpState.portsPending=true',ctx);
ctx.state.upnpPorts={managementEnabled:true,enabled:true,forwardPorts:[6082,6881],protectedPorts:[6082],pending:true};
assert.match(ctx.forwardPortProtectionPanel(),/待同步/);assert.match(ctx.forwardPortProtectionPanel(),/TCP.*UDP/);
assert.doesNotMatch(ctx.upnpPage(),/id="upnp-ports"/);
// No UPnP SOAP read is needed to render or open protection on the rules tab.
vm.runInContext('upnpState=null',ctx);ctx.location.hash='#/forwards/rules';
ctx.upnpPortsDialog(true);assert.match(dialogResult.title,/应用转发端口保护/);assert.match(dialogResult.body,/不会自动删除映射/);
await dialogResult.save({adminPassword:'test-only',password:'one-time'});assert.equal(saved.path,'upnp/ports');assert.equal(saved.data.enabled,true);
ctx.upnpPortsDialog(false);assert.match(dialogResult.title,/解除/);await dialogResult.save({});assert.equal(saved.data.enabled,false);
const html=fs.readFileSync(new URL('../web/index.html',import.meta.url),'utf8');assert.match(html,/upnp\.js\?v=/);assert.match(html,/upnp\.css\?v=/);
vm.runInContext('upnpState='+JSON.stringify(fixture),ctx);ctx.location.hash='#/forwards/upnp';
vm.runInContext("upnpState.config.writePolicy='own';upnpState.clientIP='192.168.1.1'",ctx);
assert.equal(ctx.upnpCanWrite(fixture.mappings[0]),false);assert.match(ctx.upnpMappingButtons(fixture.mappings[0],0),/disabled/);
assert.equal(ctx.upnpCanWrite({internalIP:'192.168.1.1'}),true);
assert.match(source,/未保存|不会保存/);assert.ok(!source.includes('localStorage'));assert.match(source,/policyPending/);
// Cached data is present synchronously even if the whole page is rendered again.
assert.doesNotMatch(ctx.upnpPage(),/正在读取/);assert.match(ctx.upnpPage(),/6881/);
fixture.config.writePolicy='own';fixture.clientIP='192.168.1.1';
const elements=Object.fromEntries(['upnp-status','upnp-mappings','upnp-blacklist'].map(id=>[id,{innerHTML:'',className:''}]));
ctx.$=s=>elements[s.slice(1)]||null;ctx.upnpRender();
const oldMappings=elements['upnp-mappings'].innerHTML,oldBlocks=elements['upnp-blacklist'].innerHTML;
let complete,requests=0;
ctx.api=()=>{requests++;return new Promise(resolve=>{complete=resolve})};
const pending=ctx.refreshUPnP(),duplicate=ctx.refreshUPnP();
assert.equal(requests,1);assert.equal(elements['upnp-mappings'].innerHTML,oldMappings);assert.doesNotMatch(ctx.upnpPage(),/正在读取/);
complete(fixture);await Promise.all([pending,duplicate]);
assert.equal(elements['upnp-mappings'].innerHTML,oldMappings);
ctx.api=async()=>{throw Error('timeout')};await ctx.refreshUPnP();
assert.equal(elements['upnp-mappings'].innerHTML,oldMappings);assert.equal(elements['upnp-blacklist'].innerHTML,oldBlocks);
assert.match(elements['upnp-status'].innerHTML,/上次读取结果.*timeout/);
ctx.api=async()=>fixture;await ctx.refreshUPnP();assert.doesNotMatch(elements['upnp-status'].innerHTML,/timeout/);
// A response from the previous login must not repopulate the new session cache.
ctx.api=()=>new Promise(resolve=>{complete=resolve});const stale=ctx.refreshUPnP();
ctx.resetUPnPState();complete(fixture);await stale;
assert.match(ctx.upnpPage(),/正在读取/);assert.equal(vm.runInContext('upnpState',ctx),null);
console.log('UPnP tabs, mapping fields, delete confirmation, trusted SSH requirement and no credential persistence passed.');
