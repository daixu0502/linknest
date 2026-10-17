import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
let saved,dialogResult;
const ctx={location:{hash:'#/forwards/upnp'},document:{addEventListener(){}},queueMicrotask(){},setInterval(){},loggedIn:true,page:'forwards',structuredClone,
 state:{interfaces:[{name:'br-lan'}],config:{sshHosts:[]},twoFactor:{enabled:false}},
 esc:v=>String(v??'').replaceAll('<','&lt;'),pill:String,icon:()=>'',ibtn:()=>'<button>test</button>',btn:()=>'',panel:(t,s,b)=>b,actionNote:s=>s,empty:(t,s)=>t+s,notice:String,
 field:(n,l,v)=>n+':'+v,picker:(n,l,v)=>n+':'+v,toggle:n=>n,area:n=>n,uid:()=> 'new-id',
 dialog:(title,body,save)=>{dialogResult={title,body,save}},api:async(path,method,data)=>{if(path==='upnp/state')return fixture;saved={path,method,data};return{message:'done'}},toast(){},navigatePage:(...p)=>{ctx.route=p},$:()=>null,
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
const html=fs.readFileSync(new URL('../web/index.html',import.meta.url),'utf8');assert.match(html,/upnp\.js\?v=/);assert.match(html,/upnp\.css\?v=/);
vm.runInContext("upnpState.config.writePolicy='own';upnpState.clientIP='192.168.1.1'",ctx);
assert.equal(ctx.upnpCanWrite(fixture.mappings[0]),false);assert.match(ctx.upnpMappingButtons(fixture.mappings[0],0),/disabled/);
assert.equal(ctx.upnpCanWrite({internalIP:'192.168.1.1'}),true);
assert.match(source,/未保存|不会保存/);assert.ok(!source.includes('localStorage'));assert.match(source,/policyPending/);
console.log('UPnP tabs, mapping fields, delete confirmation, trusted SSH requirement and no credential persistence passed.');
