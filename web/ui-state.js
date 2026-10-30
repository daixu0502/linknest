'use strict';
let authEpoch=0, stateEpoch=0, lastStateSuccess=0, stateReadError='', activeDialog=null, dialogSequence=0;
const ruleFilters={rules:{query:'',status:'all'},forwards:{query:'',status:'all'}};
function markFormError(form,error){
 if(!form?.isConnected)return;
 let box=form.querySelector('#form-error,[data-save-error]');if(!box){box=document.createElement('p');box.className='form-error';box.dataset.saveError='true';box.id=(form.id||'page-form')+'-save-error';box.setAttribute('role','alert');form.append(box);}box.textContent=error.message;
 if(error.status===412&&box){const button=document.createElement('button');button.type='button';button.className='button';button.textContent='读取最新配置并核对';button.addEventListener('click',()=>busy(button,async()=>{const fresh=await api('state');if(!form.isConnected)return;const details=document.createElement('details');details.open=true;const summary=document.createElement('summary');summary.textContent='服务器上的最新配置（当前输入已保留）';const pre=document.createElement('pre');pre.className='conflict-config';pre.textContent=JSON.stringify(fresh.config,null,2);const accept=document.createElement('button');accept.type='button';accept.className='button';accept.textContent='已核对，继续编辑';accept.onclick=()=>{if(!form.isConnected)return;state=fresh;stateEpoch++;form.dataset.revision=fresh.configRevision;details.remove();box.textContent='最新版本已载入，请检查草稿后再次保存。';};details.append(summary,pre,accept);box.replaceChildren(details);}));box.append(' ',button);}

 form.querySelectorAll('[aria-invalid]').forEach(e=>e.removeAttribute('aria-invalid'));
 const hints=[['路径','pathPrefix'],['AccessKey','accessKeyId'],['Secret','secret'],['名称','name'],['监听','port'],['目标','target'],['域名','domains'],['证书','certificate'],['密码','password']];
 const field=hints.find(([text,name])=>error.message.includes(text)&&form.elements[name]);
 if(field){const input=form.elements[field[1]];input.setAttribute('aria-invalid','true');input.setAttribute('aria-describedby',box.id);input.closest('details')?.setAttribute('open','');input.focus();}
}
function discardDraft(form){return !form?.dataset.dirty||form.dataset.dirty!=='true'||confirm('有尚未保存的修改，确定放弃并离开？');}
function advanced(title,body,open=false){return `<details class="advanced-fields" ${open?'open':''}><summary>${esc(title)}</summary><div class="content-stack">${body}</div></details>`;}
function copyValue(value,label='复制地址'){return `<button type="button" class="icon-button copy-value" data-action="copy" data-copy="${esc(value)}" title="${esc(label)}" aria-label="${esc(label)}">${icon('copy')}</button>`;}
function ruleProblem(r){const s=state.rules.find(x=>x.id===r.id);return r.enabled&&(s?.state==='error'||s?.firewall?.state==='error'||s?.backend?.state==='error');}
function ruleStatusMarkup(r){
 const s=state.rules.find(x=>x.id===r.id),pending=state.application?.state==='pending';
 const part=(label,value)=>`<span class="rule-state-item" title="${esc(value?.message||'未检查')}"><small>${label}</small>${pill(value?.state==='error'?'失败':['running','applied','reachable'].includes(value?.state)?'正常':value?.state==='not_applicable'?'内核转发':value?.state==='disabled'?'未授权':value?.state==='unmanaged'?'手动管理':'未检查',value?.state==='error'?'error':['running','applied','reachable'].includes(value?.state)?'good':'')}</span>`;
 if(!r.enabled)return pill('已停用');
 return `${pending?pill('等待应用','blue'):''}<div class="rule-state-parts">${part('监听',s?.listener||{state:s?.state,message:s?.message})}${part('防火墙',s?.firewall)}${part('后端',s?.backend)}</div>${s?.state==='error'?`<p class="form-error">${esc(s.message)}</p>`:''}${s?.firewall?.state==='error'?`<p class="form-error">${esc(s.firewall.message)}</p>`:''}${s?.backend?.state==='error'?`<p class="form-error">${esc(s.backend.message)}</p>`:''}${s?.traffic?`<small class="muted">连接 ${s.traffic.active} / ${s.traffic.capacity} · 丢弃 ${s.traffic.dropped}</small>`:''}`;
}
function ruleToolbar(kind){const f=ruleFilters[kind];return `<div class="rule-toolbar"><label class="field"><span>搜索规则</span><input type="search" data-rule-search="${kind}" value="${esc(f.query)}" placeholder="名称、域名、监听或目标地址"></label><label class="field"><span>状态</span><select data-rule-filter="${kind}">${[['all','全部'],['enabled','已启用'],['disabled','已停用'],['error','异常']].map(([v,t])=>`<option value="${v}" ${f.status===v?'selected':''}>${t}</option>`).join('')}</select></label><span class="rule-filter-count" role="status"></span></div>`;}
function applyRuleFilters(){
 const kind=page==='rules'?'rules':page==='forwards'?'forwards':null;if(!kind)return;
 const f=ruleFilters[kind];let shown=0,total=0;
 for(const el of document.querySelectorAll('[data-rule-id]')){const r=state.config.rules.find(x=>x.id===el.dataset.ruleId);if(!r)continue;total++;const match=JSON.stringify(r).toLowerCase().includes(f.query.toLowerCase())&&(f.status==='all'||f.status==='enabled'&&r.enabled||f.status==='disabled'&&!r.enabled||f.status==='error'&&ruleProblem(r));el.hidden=!match;if(match)shown++;}
 const count=document.querySelector('.rule-filter-count');if(count)count.textContent=`显示 ${shown} / ${total}`;
}
function syncStateBanner(){
 const el=document.querySelector('#state-status');if(!el)return;
 const app=state?.application;el.className='state-status'+(stateReadError||app?.state==='error'?' error':'');
 el.textContent=stateReadError?`${stateReadError}；保留上次结果${lastStateSuccess?'（'+new Date(lastStateSuccess).toLocaleTimeString()+'）':''}`:app?.state==='pending'?'配置已保存，正在应用…':app?.state==='error'?app.message:lastStateSuccess?'状态更新于 '+new Date(lastStateSuccess).toLocaleTimeString():'';
}
// The tab bar stays mounted. Only the content below it enters on tab changes.
function pageContentMarkup(animate=false){
 const fragment=document.createElement('template');fragment.innerHTML=pageContent();
 const candidate=fragment.content.firstElementChild,tabs=candidate?.matches('.panel-tabs')?candidate:null;
 const tabHTML=tabs?.outerHTML||'';tabs?.remove();
 const action=pageAction();
 if(action){
  const toolbar=fragment.content.querySelector('.rule-toolbar'),head=fragment.content.querySelector('.panel-head');
  if(toolbar)toolbar.insertAdjacentHTML('beforeend',`<div class="actions content-actions">${action}</div>`);
  else if(head){
   let actions=head.querySelector(':scope > .actions');
   if(!actions){actions=document.createElement('div');actions.className='actions';while(head.children.length>1)actions.append(head.children[1]);head.append(actions);}
   actions.insertAdjacentHTML('beforeend',action);
  }
 }
 return `${tabHTML}<div class="page-body${animate?' page-transition':''}">${fragment.innerHTML}</div>`;
}
function patchPageContent(content,next,changed=false){
 const tabs=content.querySelector(':scope > .panel-tabs'),nextTabs=next.querySelector(':scope > .panel-tabs');
 if(tabs&&nextTabs){
  for(const button of tabs.querySelectorAll('button')){
   const match=[...nextTabs.querySelectorAll('button')].find(b=>b.dataset.action===button.dataset.action);
   if(match)patchNode(button,match);
  }
  const body=content.querySelector(':scope > .page-body'),nextBody=next.querySelector(':scope > .page-body');
  if(changed)body.replaceWith(nextBody);else patchNode(body,nextBody);
 }else if(changed)content.replaceChildren(...next.childNodes);else patchNode(content,next);
 syncTabIndicators();
}
function syncTabIndicators(){
 for(const tabs of document.querySelectorAll('#page-content > .panel-tabs')){
  const selected=tabs.querySelector('[aria-selected=true],[aria-current=page]');if(!selected)continue;
  tabs.style.setProperty('--tab-x',selected.offsetLeft+'px');
  tabs.style.setProperty('--tab-width',selected.offsetWidth+'px');
  if(!tabs.classList.contains('has-tab-indicator')){tabs.getBoundingClientRect();tabs.classList.add('has-tab-indicator');}
 }
}
function nodeIdentity(node){if(node.nodeType!==1)return '';return node.id||node.getAttribute('data-rule-id')||node.getAttribute('data-cert-job')||node.getAttribute('data-action')||node.getAttribute('name')||'';}
// Reconcile changed status text in place. Forms, focused controls and expanded
// details keep their nodes; polling never replaces the application shell.
function patchNode(old,next){
 if(old.nodeType!==next.nodeType||old.nodeName!==next.nodeName){old.replaceWith(next.cloneNode(true));return;}
 if(old.nodeType===3){if(old.textContent!==next.textContent)old.textContent=next.textContent;return;}
 if(old.nodeType!==1||old.isEqualNode(next))return;
 if(old.matches('form,input,textarea,select')||old.contains(document.activeElement)&&old.matches('.picker'))return;
 for(const attr of [...old.attributes]){if(attr.name==='open'||attr.name==='data-dirty')continue;if(!next.hasAttribute(attr.name))old.removeAttribute(attr.name);}
 for(const attr of [...next.attributes]){if(attr.name==='open')continue;if(old.getAttribute(attr.name)!==attr.value)old.setAttribute(attr.name,attr.value);}
 const oldChildren=[...old.childNodes],used=new Set();let cursor=old.firstChild;
 for(const child of [...next.childNodes]){
  const key=nodeIdentity(child);let existing=key?oldChildren.find(n=>!used.has(n)&&nodeIdentity(n)===key&&n.nodeName===child.nodeName):oldChildren.find(n=>!used.has(n)&&!nodeIdentity(n)&&n.nodeType===child.nodeType&&n.nodeName===child.nodeName);
  if(existing){used.add(existing);if(existing!==cursor)old.insertBefore(existing,cursor);patchNode(existing,child);cursor=existing.nextSibling;}
  else{const added=child.cloneNode(true);old.insertBefore(added,cursor);}
 }
 for(const child of oldChildren)if(!used.has(child))child.remove();
}
function refreshPageContent(){
 if(!loggedIn||!state)return;
 const content=document.querySelector('#page-content');if(!content){render();return;}
 const next=document.createElement('div');next.innerHTML=pageContentMarkup();
 const old=document.createElement('div'); // only children are reconciled, not the container's layout attributes
 old.innerHTML=next.innerHTML;old.id=content.id;old.className=content.className;
 patchPageContent(content,old);applyRuleFilters();syncStateBanner();stampForms();
}
function stampForms(){for(const form of document.querySelectorAll('.main form')){if(form.dataset.dirty!=='true')form.dataset.revision=state?.configRevision||'';}}
function attentionPanel(){
 const items=[];
 for(const r of state.config.rules)if(ruleProblem(r))items.push({text:r.name+' · 规则异常',page:r.kind==='web'?'rules':'forwards'});
 for(const c of state.certificates)if(c.error||c.remainingDays<=30)items.push({text:(c.name||c.id)+' · '+(c.error||'证书剩余 '+c.remainingDays+' 天'),page:'certs'});
 for(const s of state.ddns)if(s.state==='error')items.push({text:(state.config.ddns.find(d=>d.id===s.id)?.name||s.id)+' · '+s.message,page:'ddns'});
 if(state.application?.state==='pending')items.unshift({text:'配置已保存，等待应用',page:'rules'});
 return items.length?panel('需要处理',`${items.length} 项状态需要关注`,`<div class="attention-list">${items.map(v=>`<button type="button" data-action="page:${v.page}">${icon('info')}<span>${esc(v.text)}</span>${icon('chevron')}</button>`).join('')}</div>`,'','attention-panel'):'';
}
function diagnosticsPanel(){
 const d=state.diagnostics||{},items=[['操作系统 / 架构',`${d.os||'未确认'} / ${d.architecture||'未确认'}`],['网络模式',d.networkMode||'未确认'],['防火墙授权',d.firewallAuthorized?'已授权':'未授权'],['NET_ADMIN',d.netAdmin?'具备':'未确认 / 缺少'],['NET_RAW',d.netRaw?'具备':'未确认 / 缺少'],['xtables 锁',d.xtablesLock||'未确认']];
 for(const [family,status] of Object.entries(state.firewall?.families||{}))items.push([family.toUpperCase()+' 自动放行',status.message+' ('+status.state+')']);
 for(const [family,v] of Object.entries(d.families||{}))for(const [key,label] of [['backend','后端'],['filter','filter'],['nat','NAT'],['forwarding','转发开关']])items.push([family.toUpperCase()+' '+label,typeof v[key]==='boolean'?(v[key]?'已开启':'未开启'):v[key]]);
 return panel('运行环境诊断',d.checked?'检查于 '+new Date(d.checked).toLocaleString():'尚未检查',`<div class="panel-body"><dl class="diagnostic-list">${items.map(([k,v])=>`<div><dt>${esc(k)}</dt><dd>${esc(v||'未确认')}</dd></div>`).join('')}</dl>${functionNote('可读取内核表不代表业务已放行。容器内无法可靠确认宿主网络及锁的共享挂载，请核对部署参数。')}</div>`,btn(d.refreshing?'检查中':'重新检查','diagnostics','refresh'));
}
function settingsTabs(){const selected=settingsTab();return `<div class="panel-tabs settings-tabs">${[['account','账户安全'],['https','管理 HTTPS'],['environment','运行环境'],['data','数据与外观']].map(([v,t])=>`<button type="button" data-action="settings-tab:${v}" aria-current="${selected===v?'page':'false'}">${t}</button>`).join('')}</div>`;}
function settingsTab(){const tab=location.hash.split('/')[2];return ['account','https','environment','data'].includes(tab)?tab:'account';}
function pathPreview(parent,id){
 const form=document.querySelector('#dialog-form');if(!form)return;
 const box=document.querySelector('#path-preview');if(!box)return;
 const prefix=form.elements.pathPrefix?.value||'/',target=form.elements.target?.value||'后端地址';
 box.textContent=`匹配 ${prefix} 及其路径段下的请求 → ${target}；保留原路径和查询参数。`;
 const canonical=p=>(p||'/').replace(/\/$/,'')||'/';
 const domains=String(form.elements.domains?.value||'').toLowerCase().split(/[\r\n,]+/).map(x=>x.trim()).filter(Boolean);if(!domains.length)domains.push('*');
 const rule=state.config.rules.find(r=>r.id===parent);const duplicate=(rule?.routes||[]).some(r=>r.id!==id&&r.enabled&&canonical(r.pathPrefix)===canonical(prefix)&&(r.domains?.length?r.domains:['*']).some(d=>domains.includes(d.toLowerCase())));
 if(duplicate){box.textContent='相同域名和路径已有启用规则，请调整路径或停用重复规则。';box.classList.add('error');}else box.classList.remove('error');
}
document.addEventListener('input',e=>{const form=e.target.closest('form');if(form&&form.id!=='auth-form'){form.dataset.dirty='true';if(activeDialog?.form===form)activeDialog.dirty=true;}if(e.target.dataset.ruleSearch){ruleFilters[e.target.dataset.ruleSearch].query=e.target.value;applyRuleFilters();}});
document.addEventListener('change',e=>{if(e.target.dataset.ruleFilter){ruleFilters[e.target.dataset.ruleFilter].status=e.target.value;applyRuleFilters();}const form=e.target.closest('form');if(form&&form.id!=='auth-form'){form.dataset.dirty='true';if(activeDialog?.form===form)activeDialog.dirty=true;}});
window.addEventListener('beforeunload',e=>{if(document.querySelector('form[data-dirty="true"]')){e.preventDefault();e.returnValue='';}});

async function copyText(value){
 if(navigator.clipboard&&window.isSecureContext)return navigator.clipboard.writeText(value);
 const focus=document.activeElement,el=document.createElement('textarea');el.value=value;el.style.cssText='position:fixed;left:-10000px';document.body.append(el);el.select();const copied=document.execCommand('copy');el.remove();focus?.focus({preventScroll:true});if(!copied)throw Error('浏览器禁止复制，请手动选中地址');
}
