import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const dialogs=[],closed=[],calls=[];
const state={username:'qa',twoFactor:{enabled:false,recoveryCodesRemaining:0}};
const codes=['01234567-89ABCDEF-01234567-89ABCDEF'];
const ctx={
 state,
 modal:{addEventListener(type,callback,options){assert.equal(type,'close');assert.equal(options.once,true);closed.push(callback);}},
 requestAnimationFrame:callback=>callback(),
 esc:value=>String(value).replaceAll('<','&lt;'),
 panel:(title,sub,body)=>title+sub+body,pill:text=>text,
 btn:(label,action)=>`<button data-action="${action}">${label}</button>`,notice:text=>text,field:name=>`<input name="${name}">`,toggle:name=>`<input name="${name}" type="checkbox">`,
 dialog:(title,content,onSave)=>dialogs.push({title,content,onSave}),
 render(){},toast(){},
 async api(path,method,body){calls.push({path,method,body});if(path==='2fa/begin')return{secret:'TEST-ONLY',qrDataURL:'data:image/png;base64,test-only'};if(path==='state')return state;return{recoveryCodes:codes};},
};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(new URL('../web/twofactor.js',import.meta.url),'utf8'),ctx);
assert.equal(await ctx.twoFactorAction('not-2fa'),false);
assert.match(ctx.twoFactorPanel(),/扫码绑定/);
assert.match(ctx.twoFactorCodeField(true),/inputmode="numeric"/);
await ctx.twoFactorAction('2fa-begin');
assert.equal(dialogs.length,1);
await dialogs[0].onSave({password:'test-only'});
assert.equal(dialogs.length,1,'next dialog must wait for close cleanup');
closed.shift()();
assert.equal(dialogs[1].title,'扫码绑定两步验证');
assert.match(dialogs[1].content,/data:image\/png;base64,test-only/);
assert.doesNotMatch(dialogs[1].content,/<img[^>]+src="https?:/);
await dialogs[1].onSave({password:'test-only',code:'123456'});
assert.equal(dialogs.length,2,'recovery dialog must also wait for close cleanup');
closed.shift()();
assert.equal(dialogs[2].title,'保存一次性恢复码');
await assert.rejects(dialogs[2].onSave({saved:false}),/先保存/);
await dialogs[2].onSave({saved:true});
state.twoFactor={enabled:true,recoveryCodesRemaining:10};
assert.match(ctx.twoFactorPanel(),/10 个/);
await ctx.twoFactorAction('2fa-recovery');
await dialogs.at(-1).onSave({password:'test-only',code:codes[0]});
assert.equal(calls.at(-2).path,'2fa/recovery');
closed.shift()();
assert.equal(dialogs.at(-1).title,'保存一次性恢复码');
const app=fs.readFileSync(new URL('../web/app.js',import.meta.url),'utf8');
assert.match(app,/if\(result.twoFactorRequired\)/);
assert.match(app,/autocomplete="one-time-code"/);
assert.match(app,/code:data.code\|\|''/);
assert.match(app,/state.twoFactor\?\.enabled\?twoFactorCodeField/);
const index=fs.readFileSync(new URL('../web/index.html',import.meta.url),'utf8');
assert.match(index,/twofactor.js/);assert.match(index,/twofactor.css/);
console.log('2FA binding, dialog transitions, recovery display, login and account UI regressions passed.');
