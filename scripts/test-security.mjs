import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';

let saved,submit;
const ctx={console,setInterval:()=>{},queueMicrotask:()=>{},document:{addEventListener:()=>{}},page:'security',loggedIn:true,
 state:{config:{access:{autoBan:{enabled:false,threshold:20,windowSeconds:60,banSeconds:3600,statusCodes:[404],ignorePrivate:true,ignoredPaths:[]},sources:[]},blacklist:[],whitelist:[]},firewall:{state:'applied',ports:[]}},
 structuredClone,Date,Number,Error,esc:v=>String(v).replaceAll('<','&lt;'),notice:s=>s,actionNote:s=>s,panel:(t,s,b)=>t+s+b,field:()=>'',picker:()=>'',toggle:()=>'',area:()=>'',btn:()=>'',ibtn:()=>'',pill:()=>'',row:()=>'',empty:()=>'',uid:()=> 'new-source',
 dialog:(t,c,onSave)=>{submit=onSave},api:async(path,method,data)=>{if(method==='POST')saved={path,method,data};return {access:{bans:[],sources:[]}}},$:()=>null,saveConfig:async c=>{saved=c},toast:()=>{}
};
vm.createContext(ctx);vm.runInContext(fs.readFileSync(new URL('../web/security.js',import.meta.url),'utf8'),ctx);
assert.ok(ctx.securityPage().includes('异常访问自动封禁'));
assert.ok(ctx.securityPage().includes('内核 NAT'));
assert.ok(!ctx.securityPage().includes('不是 GeoIP 地理数据库'));
assert.ok(ctx.securityPage().includes('grid-equal access-settings'));
assert.match(fs.readFileSync(new URL('../web/layout-fixes.css',import.meta.url),'utf8'),/\.access-settings form>\.modal-actions\{margin-top:auto;padding-top:24px\}/);
await ctx.securityAction('access-unban:2001:db8::1');await submit();assert.equal(saved.data.ip,'2001:db8::1');
await ctx.securityAction('access-presets');await submit({preset:'spamhaus-v4'});assert.equal(saved.access.sources[0].enabled,false);assert.equal(saved.access.sources[0].format,'spamhaus');
ctx.state.config.access.sources=[{id:'x',name:'<script>',enabled:true}];await ctx.securityAction('access-delete:x');await submit();assert.equal(saved.access.sources.length,0);
const app=fs.readFileSync(new URL('../web/app.js',import.meta.url),'utf8'),html=fs.readFileSync(new URL('../web/index.html',import.meta.url),'utf8');
assert.ok(app.includes('securityAction(key)'));assert.ok(app.includes('c.access.autoBan.enabled=false'));assert.ok(app.includes('[1,2,3,4]'));assert.ok(html.includes('/security.js?v=__VERSION__'));
console.log('Access UI / IPv6 unban / disabled presets / safe import regressions passed.');
