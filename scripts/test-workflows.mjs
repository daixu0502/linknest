import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const context={structuredClone,$$:()=>[],document:{addEventListener(){}},modal:{contains(){return false;}},
 state:{config:{ddns:[{id:'task',records:[{id:'record',domain:'home.example.com',type:'A',line:'default'}]}],rules:[]},certificates:[]},
 certificateAction:async()=>false,bookmarkAction:async()=>false,notice:s=>s,actionNote:s=>s,functionNote:s=>s,statusNote:s=>s,
 toggle:(name,label,value,hint)=>`${name}:${value}:${label}:${hint}`,
 dialog:(title,body,save)=>{context.dialogResult={title,body,save};},
 api:async(path,method,payload)=>{if(path!=='state')context.request={path,method,payload};return {message:'done'};},render(){},toast(){},
 picker:(name,label,value)=>`${name}:${label}:${value}`,field:(name,label)=>`${name}:${label}`,conditions(){},
 saveItem:async(group,item)=>{context.saved={group,item};},uid:()=> 'new-rule'};
vm.createContext(context);
vm.runInContext(fs.readFileSync(new URL('../web/workflows.js',import.meta.url),'utf8'),context);
await context.workflowAction('record-delete:task:record');
assert.match(context.dialogResult.body,/deleteRemote:false/);
assert.match(context.dialogResult.body,/home.example.com/);
await context.dialogResult.save({deleteRemote:true});
assert.equal(context.request.path,'ddns/record/delete');
assert.equal(context.request.payload.recordId,'record');
assert.equal(context.request.payload.deleteRemote,true);
context.state={config:{rules:[]},certificates:[]};
context.editListener('forwards');
assert.match(context.dialogResult.body,/forwardMode:转发方式:proxy/);
await context.dialogResult.save({name:'test',host:'',port:'39642',network:'ipv4',kind:'tcpudp',forwardMode:'kernel',target:'192.0.2.20:3389',enabled:false,openFirewall:true});
assert.equal(context.saved.item.forwardMode,'kernel');
assert.equal(context.saved.item.listen,'0.0.0.0:39642');
const css=fs.readFileSync(new URL('../web/portal.css',import.meta.url),'utf8');
assert.ok(!css.includes('background:#6125db'));
assert.ok(!css.includes('--canvas-color'));
assert.ok(!css.includes('background-color:'));
assert.match(css,/body\{[^}]*display:flex/);
assert.ok(!css.includes('100dvh - 104px'));
assert.match(css,/\.canvas-background\{[^}]*position:absolute[^}]*background-image:/);
assert.match(css,/grain\.svg/);
assert.match(css,/safe-area-inset-bottom/);
const html=fs.readFileSync(new URL('../web/portal.html',import.meta.url),'utf8');
assert.ok(!html.includes('theme-color'));
assert.match(html,/canvas-background[^<]*"true"/);
assert.match(html,/scrollbars\.css\?v=/);
const bars=fs.readFileSync(new URL('../web/scrollbars.css',import.meta.url),'utf8');
assert.match(bars,/scrollbar-color:var\(--scroll-thumb\) transparent/);
assert.match(bars,/::-webkit-scrollbar-thumb/);
assert.match(bars,/forced-colors:active/);
assert.match(bars,/html\{scrollbar-gutter:stable\}/);
assert.match(css,/body\.panel-page\{[^}]*height:100dvh[^}]*overflow:hidden/);
assert.match(css,/\.cards-area\{[^}]*min-height:0[^}]*overflow-y:auto/);
assert.match(html,/class="panel-controls"/);
assert.match(html,/class="cards-area" aria-label="站点卡片" tabindex="0"/);
assert.match(css,/\.clock-time\{height:30px\}/);
const js=fs.readFileSync(new URL('../web/portal.js',import.meta.url),'utf8');
const clockFn=js.slice(js.indexOf('const clockGlyphs='),js.indexOf('\nif(clock)'));
const clockContext={document:{createElementNS(ns,tag){return {ns,tag,attrs:{},children:[],setAttribute(k,v){this.attrs[k]=v;},replaceChildren(...children){this.children=children;}};}}};
vm.createContext(clockContext);vm.runInContext(clockFn,clockContext);
const parts=clockContext.panelClockParts(new Date(2026,9,13,9,18,37));
assert.equal(parts.time,'09:18:37');assert.equal(parts.date,'2026-10-13 周二');
assert.equal(clockContext.panelClockParts(new Date(2027,0,1,0,0,0)).time,'00:00:00');
const drawing=clockContext.createClockDrawing('clock-time');
for(let day=0;day<7;day++)drawing.draw(clockContext.panelClockParts(new Date(2026,9,11+day)).date);
drawing.draw('0123456789:');assert.equal(drawing.svg.children.length,11);
assert.equal(drawing.svg.attrs.viewBox,'0 0 252 40');
assert.equal(drawing.svg.attrs['aria-hidden'],'true');
assert.ok(drawing.svg.children.every(p=>p.tag==='path'&&p.ns==='http://www.w3.org/2000/svg'&&p.attrs.d));
const children=drawing.svg.children;drawing.draw('0123456789:');assert.equal(drawing.svg.children,children);
assert.ok(!clockFn.includes("createElementNS(ns,'text')"));
assert.equal(clockContext.panelClockStyle('simple'),'simple');
assert.equal(clockContext.panelClockStyle('digital'),'digital');
assert.equal(clockContext.panelClockStyle('stacked'),'stacked');
assert.equal(clockContext.panelClockStyle('bad'),'vector');
clockContext.document.createElement=tag=>({tag,attrs:{},textContent:'',setAttribute(k,v){this.attrs[k]=v;}});
const ordinary=clockContext.createClockText('clock-time-text');ordinary.draw('09:18:37');assert.equal(ordinary.svg.textContent,'09:18:37');
const digitalDrawing=vm.runInContext("createClockDrawing('clock-time',digitalClockGlyphs)",clockContext);digitalDrawing.draw('0123456789:');assert.equal(digitalDrawing.svg.children.length,11);assert.notEqual(digitalDrawing.svg.children[0].attrs.d,drawing.svg.children[0].attrs.d);
assert.match(html,/data-clock-style=/);
assert.match(css,/\.header-actions>#theme-toggle,\.header-actions>\.background-picker>summary\{[^}]*place-items:center[^}]*width:34px;height:34px/);
for(const [file,removed] of [
 ['certificates.js','不复用 DDNS 账户'],
 ['bookmarks.js','左侧引用反代入口'],
 ['bookmarks.js','访问密码或免密码开关在'],
 ['icons.js','默认提供 Iconify 与 selfh.st。请求由浏览器发出']
])assert.ok(!fs.readFileSync(new URL('../web/'+file,import.meta.url),'utf8').includes(removed));
const app=fs.readFileSync(new URL('../web/app.js',import.meta.url),'utf8');
assert.ok(app.includes("state.firewall.state==='error'?notice(state.firewall.message,true):''"));
context.parts=(heading,body)=>heading+body;
context.when=(key,value,body)=>body;
context.area=(key,label)=>label;
// Render the actual route editor: capabilities are automatic, not dead toggles.
context.state={config:{rules:[{id:'proxy',routes:[]}]},certificates:[]};
context.field=(name,label,value,hint)=>`${name}:${label}:${hint||''}`;
context.editRoute('proxy');
assert.match(context.dialogResult.body,/HTTP\/HTTPS\/WS\/WSS/);
assert.match(context.dialogResult.body,/WebSocket 自动转发/);
assert.match(context.dialogResult.body,/X-Forwarded-Host \/ Proto \/ For/);
assert.ok(!context.dialogResult.body.includes('websocketEnabled'));
console.log('DNS delete / native forward / canvas / card scroll / vector clock / simplified notices checks passed.');
