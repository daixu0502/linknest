import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

// Exercise the actual buildless refresh function, including an empty DOM.
const source = fs.readFileSync(new URL('../web/app.js', import.meta.url), 'utf8');
const refreshSource = source.split('\n').find(line => line.startsWith('async function refresh('));
assert.ok(refreshSource, 'refresh function exists');
async function scenario(page, initial, replacement, apiError = false) {
  let nodes = initial;
  const context = {
    fetching: false, loggedIn: true, page, modal: {open: false}, state: {},
    renderCount: 0,
    $: () => nodes[0] || null,
    $$: () => nodes,
    api: async () => { if (apiError) throw Error('test network failure'); return {version: 'test'}; },
    syncRefreshControls: () => {},
    render: () => { context.renderCount++; nodes = replacement; },
  };
  vm.createContext(context);
  vm.runInContext(refreshSource, context);
  if (apiError) await assert.rejects(context.refresh(true), /test network failure/);
  else await context.refresh(true);
  assert.equal(context.fetching, false, 'refresh lock released');
  assert.equal(context.renderCount, apiError ? 0 : 1, 'render after successful read');
  return nodes;
}
for (const page of ['certs', 'devices', 'overview']) await scenario(page, [], []);
const nodes = await scenario('certs', [
  {dataset: {certJob: 'first'}, open: true},
  {dataset: {certJob: 'second'}, open: false},
], [
  {dataset: {certJob: 'first'}, open: false},
  {dataset: {certJob: 'second'}, open: true},
  {dataset: {certJob: 'new'}, open: true},
]);
assert.deepEqual(nodes.map(node => node.open), [true, false, true]);
await scenario('certs', [], [], true);
console.log('UI refresh regression tests passed (empty / multiple jobs / errors).');

const workflows=fs.readFileSync(new URL('../web/workflows.js',import.meta.url),'utf8');
const immediate=workflows.slice(workflows.indexOf('async function saveImmediateSetting('),workflows.indexOf("\ndocument.addEventListener('change'"));
for(const fail of [false,true]){
 const controls=[{disabled:false}],status={textContent:''},calls=[];
 const ctx={savingImmediateSetting:false,state:{config:{terminalEnabled:false}},structuredClone,location:{protocol:'http:'},page:'settings',loggedIn:true,
  $:()=>status,$$:()=>controls,stopTerminal:()=>{},render:()=>{},toast:()=>{},
  api:async(path,method,body)=>{calls.push({path,body});if(fail)throw Error('offline');if(path==='state')return {config:{terminalEnabled:true}};return {ok:true};}};
 vm.createContext(ctx);vm.runInContext(immediate,ctx);
 await ctx.saveImmediateSetting({name:'terminalEnabled',checked:true});
 assert.equal(ctx.state.config.terminalEnabled,!fail);assert.equal(ctx.savingImmediateSetting,false);assert.equal(controls[0].disabled,false);
 assert.equal(calls[0].body.terminalEnabled,true);
}
assert.ok(!workflows.includes("btn('保存开关'"));
const route=source.split('\n').find(l=>l.startsWith('function pageFromHash('));
const routing={navs:[['overview'],['rules'],['ddns'],['bookmarks']]};vm.createContext(routing);vm.runInContext(route,routing);
assert.equal(routing.pageFromHash('#/web'),'rules');assert.equal(routing.pageFromHash('#/ddns'),'ddns');
assert.equal(routing.pageFromHash('#/bookmarks/network'),'bookmarks');assert.equal(routing.pageFromHash('#/invalid'),'overview');
console.log('Immediate setting save/failure and hash routing regressions passed.');

const authSource=source.slice(source.indexOf('function renderAuth('),source.indexOf('\nfunction render()'));
for(const initialized of [false,true]){
 const elements={'#app':{},'#auth-form':{}};
 const ctx={$:s=>elements[s],field:(name,label,value,hint)=>`<label>${label}<input name="${name}">${hint}</label>`};
 vm.createContext(ctx);vm.runInContext(authSource,ctx);ctx.renderAuth(initialized);
 assert.equal(elements['#app'].innerHTML.includes('至少 12 字节'),!initialized);
 assert.ok(elements['#app'].innerHTML.includes('id="auth-error"'));
 assert.ok(elements['#app'].innerHTML.includes('id="auth-username" name="username" type="text" autocomplete="username"'));
 assert.ok(elements['#app'].innerHTML.includes(`autocomplete="${initialized?'current-password':'new-password'}"`));
 assert.ok(elements['#app'].innerHTML.includes(`action="/api/${initialized?'login':'setup'}" method="post" autocomplete="on"`));
 assert.equal(elements['#app'].innerHTML.includes('minlength="12"'),!initialized);
}
const fixes=fs.readFileSync(new URL('../web/layout-fixes.css',import.meta.url),'utf8');
assert.match(fixes,/\.auth-form #auth-error\{[^}]*height:3em[^}]*overflow-y:auto/);
assert.ok(authSource.includes("$('#auth-error').textContent=''"));
console.log('Login hint / initialization guidance / fixed error-space regressions passed.');

const accessLinks=workflows.slice(workflows.indexOf('function routeAccessLinks('),workflows.indexOf('\nfunction proxyPage('));
const links={esc:s=>s};vm.createContext(links);vm.runInContext(accessLinks,links);
assert.ok(links.routeAccessLinks({listen:'[::]:18080',tls:true},{domains:['::1']}).includes('https://[::1]:18080/'));
assert.ok(immediate.includes('location.search+location.hash'));
