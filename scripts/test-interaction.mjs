import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const app=fs.readFileSync(new URL('../web/app.js',import.meta.url),'utf8');
const css=fs.readFileSync(new URL('../web/interaction.css',import.meta.url),'utf8');
const line=name=>app.split('\n').find(l=>l.startsWith('function '+name+'('));
const ctx={state:{config:{rules:[],ddns:[{enabled:true}],bookmarks:[],terminalEnabled:false},rules:[],certificates:[],firewall:{state:'applied',enabled:true},events:[{time:'2026-10-14T13:00:00+08:00',message:'safe <event>'}],adminAddress:'127.0.0.1:17880'},esc:v=>String(v).replaceAll('<','&lt;'),icon:()=>'<svg></svg>',ruleRows:()=>'',empty:()=>'',btn:()=>'',pill:String,notice:String};
vm.createContext(ctx);vm.runInContext(line('panel'),ctx);
vm.runInContext(app.slice(app.indexOf('function overview('),app.indexOf('\nfunction pageContent(')),ctx);
const html=ctx.overview();
assert.equal((html.match(/class="stat stat-link"/g)||[]).length,4);
for(const route of ['web','ddns','certs','bookmarks'])assert.match(html,new RegExp(`href="#/${route}"`));
assert.ok(!html.includes('快捷操作'));assert.ok(html.includes('safe &lt;event>'));
for(const name of ['services','security','activity'])assert.ok(html.includes('panel overview-'+name));
assert.match(css,/grid-template-areas:"services security" "activity activity"/);
assert.match(css,/@media\(max-width:1050px\)/);
assert.match(css,/\.modal-content \.picker-menu\{position:static;[^}]*max-height:min\(210px,35dvh\)/);
const pickerCtx={};vm.createContext(pickerCtx);vm.runInContext(line('revealPickerMenu'),pickerCtx);
for(const [top,bottom,expected] of [[140,270,48],[120,230,30],[90,170,12]]){
 const body={scrollTop:30,getBoundingClientRect:()=>({top:100,bottom:260})};
 pickerCtx.revealPickerMenu({closest:()=>body,getBoundingClientRect:()=>({top,bottom})});assert.equal(body.scrollTop,expected);
}
pickerCtx.revealPickerMenu({closest:()=>null});
assert.match(css,/\.icon-button\.refresh-button\{border-radius:50%/);
assert.match(css,/\.refresh-button\.is-loading \.icon\{animation:spin/);
assert.match(css,/@media\(prefers-reduced-motion:reduce\)/);
assert.match(fs.readFileSync(new URL('../web/index.html',import.meta.url),'utf8'),/interaction\.css\?v=/);
const feedback=fs.readFileSync(new URL('../web/button-feedback.css',import.meta.url),'utf8');
assert.match(feedback,/@media\(hover:hover\) and \(pointer:fine\)/);
assert.match(feedback,/button:not\(\.nav-shade\):not\(:disabled\):not\(\[aria-disabled=true\]\):hover/);
assert.match(feedback,/:focus-visible/);assert.match(feedback,/:active/);
assert.match(feedback,/box-shadow:inset 0 0 0 1px var\(--control-highlight-border\)/);
assert.ok(!feedback.includes('border-width'));assert.ok(!feedback.includes('transform:'));
assert.match(feedback,/\.button\.primary\{[^}]*--control-highlight-text:#fff/);
assert.match(feedback,/\.button\.danger,\.icon-button\.danger\{[^}]*--control-highlight-border:var\(--red\)/);
assert.match(feedback,/html\.public-portal/);assert.match(feedback,/prefers-reduced-motion:reduce/);assert.match(feedback,/forced-colors:active/);
for(const file of ['index.html','portal.html'])assert.match(fs.readFileSync(new URL('../web/'+file,import.meta.url),'utf8'),/button-feedback\.css\?v=/);
const glyphCtx={};vm.createContext(glyphCtx);vm.runInContext(app.slice(app.indexOf('const paths ='),app.indexOf('\nconst navs =')),glyphCtx);
const refreshPath=vm.runInContext('paths.refresh',glyphCtx);
assert.equal((refreshPath.match(/a/gi)||[]).length,1,'single-arc refresh glyph');
assert.ok(!refreshPath.includes('M4 17'));
const iconButtonCtx={icon:()=>'<svg/>',esc:String};vm.createContext(iconButtonCtx);vm.runInContext(line('ibtn'),iconButtonCtx);
assert.match(iconButtonCtx.ibtn('刷新','refresh','refresh'),/icon-button refresh-button/);
assert.match(iconButtonCtx.ibtn('删除','delete:test','trash'),/icon-button danger/);
const routeCtx={};vm.createContext(routeCtx);vm.runInContext("let renderedRoute='';"+line('pageTransitionChanged'),routeCtx);
assert.equal(routeCtx.pageTransitionChanged('overview'),false);
assert.equal(routeCtx.pageTransitionChanged('ddns'),true);
assert.equal(routeCtx.pageTransitionChanged('ddns'),false);
assert.equal(routeCtx.pageTransitionChanged('bookmarks:sites'),true);
assert.equal(routeCtx.pageTransitionChanged('bookmarks:network'),true);
function fakeButton(refresh){const classes=new Set(refresh?['refresh-button']:[]);return {disabled:false,innerHTML:'icon',attrs:{},spinners:0,classList:{contains:c=>classes.has(c),add:c=>classes.add(c),remove:c=>classes.delete(c),toggle(c,v){v?classes.add(c):classes.delete(c);}},setAttribute(k,v){this.attrs[k]=v;},insertAdjacentHTML(){this.spinners++;}};}
for(const refresh of [false,true])for(const fail of [false,true]){
 const button=fakeButton(refresh);let release;
 const gate=new Promise(r=>release=r),busyCtx={fetching:false,$$:()=>[], $:()=>({open:false}),toast(){}};
 vm.createContext(busyCtx);vm.runInContext(app.slice(app.indexOf('async function busy('),app.indexOf('\nfunction btn(')),busyCtx);
 const task=busyCtx.busy(button,async()=>{await gate;if(fail)throw Error('test failure');});
 assert.equal(button.disabled,true);assert.equal(button.attrs['aria-busy'],'true');
 assert.equal(button.classList.contains('is-loading'),refresh);assert.equal(button.spinners,refresh?0:1);
 release();await task;assert.equal(button.disabled,false);assert.equal(button.classList.contains('is-loading'),false);assert.equal(button.attrs['aria-busy'],'false');
}
// A refresh redraw replaces the old button. Both the new button and error path
// must leave the loading state; subsequent background polling must not animate pages.
for(const fail of [false,true]){
 let button=fakeButton(true),release;
 const gate=new Promise(r=>release=r),refreshCtx={fetching:false,loggedIn:true,page:'overview',state:{},modal:{open:false},$$:s=>s==='[data-action="refresh"]'?[button]:[],api:async()=>{await gate;if(fail)throw Error('offline');return {};},render(){button=fakeButton(true);refreshCtx.syncRefreshControls();}};
 vm.createContext(refreshCtx);vm.runInContext(line('syncRefreshControls')+'\n'+app.split('\n').find(l=>l.startsWith('async function refresh(')),refreshCtx);
 const task=refreshCtx.refresh(true);assert.equal(button.disabled,true);assert.equal(button.classList.contains('is-loading'),true);
 release();if(fail)await assert.rejects(task,/offline/);else await task;
 assert.equal(button.disabled,false);assert.equal(button.classList.contains('is-loading'),false);assert.equal(button.attrs['aria-busy'],'false');
}
console.log('Overview links / layout / dropdown containment / circular refresh / failures / route-only animations passed.');
