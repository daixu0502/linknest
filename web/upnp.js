'use strict';
let upnpState=null,upnpRefreshing=false,upnpRequest=null,upnpEpoch=0,upnpReadError='';
function resetUPnPState(){upnpEpoch++;upnpState=null;upnpReadError='';upnpRequest=null;upnpRefreshing=false;}
function syncUPnPControls(){for(const button of $$('[data-action="upnp-refresh"]')){button.disabled=upnpRefreshing;button.classList.toggle('is-loading',upnpRefreshing);button.setAttribute('aria-busy',String(upnpRefreshing));}}
function forwardTab(){return location.hash.split('/')[2]==='upnp'?'upnp':'rules';}
function forwardTabs(){return `<div class="panel-tabs" role="tablist" aria-label="转发管理">${[['rules','LinkNest 转发'],['upnp','路由器 UPnP']].map(([id,label])=>`<button type="button" role="tab" aria-selected="${forwardTab()===id}" data-action="forward-tab:${id}">${label}</button>`).join('')}</div>`;}
function upnpPage(){
 const view=upnpState?upnpView():null;
 queueMicrotask(()=>{syncUPnPControls();refreshUPnP();});
 return `<div class="upnp-page">${panel('原厂 UPnP 映射','直接管理路由器现有映射，不启动另一套 UPnP 服务',`<div id="upnp-status" class="panel-body muted" role="status">${view?view.status:'正在读取 UPnP 管理设置…'}</div><div id="upnp-mappings">${view?view.mappings:''}</div>`,`<div class="actions">${ibtn('刷新 UPnP 映射','upnp-refresh','refresh')}${btn('连接设置','upnp-settings','settings')}${btn('添加映射','upnp-add','plus')}</div>`)}${panel('设备黑名单','只限制设备申请映射，不限制普通上网',`<div id="upnp-blacklist"${view?'':' class="panel-body muted"'}>${view?view.blocks:'正在读取设备策略…'}</div>`,`<div class="actions">${btn('添加设备','upnp-block-add','plus')}${btn('应用到路由器','upnp-policy','shield')}</div>`)}</div>`;
}
function upnpCanWrite(m){return upnpState?.config.writePolicy==='service'||Boolean(upnpState?.clientIP&&m.internalIP===upnpState.clientIP);}
function upnpMappingButtons(m,i){const enabled=upnpCanWrite(m),suffix=enabled?'':'（安全模式：仅可查看）';return ibtn('编辑映射'+suffix,'upnp-edit:'+i,'edit').replace('<button',enabled?'<button':'<button disabled aria-disabled="true"')+ibtn('删除映射'+suffix,'upnp-delete:'+i,'trash').replace('<button',enabled?'<button':'<button disabled aria-disabled="true"');}
function upnpModeDialog(allow){
 if(!upnpState?.config.enabled){toast('请先启用 UPnP 管理',true);return;}
 const hosts=(state.config.sshHosts||[]).filter(h=>h.username==='root'&&h.fingerprint);
 if(!hosts.length){dialog('需要可信路由器 SSH',actionNote('请先在 Web 终端添加路由器 root SSH 主机并核实指纹。不会自动信任指纹或保存 SSH 凭据。'),async()=>navigatePage('terminal'),'前往 SSH 主机');return;}
 dialog(allow?'允许跨设备管理':'恢复原厂安全模式',actionNote(allow?'将关闭原厂 miniupnpd 安全模式并短暂重启 UPnP。局域网客户端也可能管理其他设备的映射，安全隔离降低。请通过 HTTPS 或 SSH 隧道操作。':'将恢复原厂安全模式并短暂重启 UPnP。之后其他设备的映射仅可查看。',true)+actionNote('先保存租约并核对现有映射；核对失败或操作中断会请求回滚。只适配已核实的 OpenWrt miniupnpd 启动脚本，不重启 Docker 或整个防火墙。')+picker('hostId','路由器 root SSH',hosts[0].id,hosts.map(h=>[h.id,h.name+' · '+h.address]))+field('adminPassword','管理员密码','','','password')+(state.twoFactor?.enabled?twoFactorCodeField():'')+field('password','本次 SSH 密码','','私钥方式可留空，不会保存','password')+area('privateKey','本次 SSH 私钥（可选）','','不会保存'),async d=>{const result=await api('upnp/mode','POST',{...d,enabled:allow});await refreshUPnP();nextTwoFactorDialog(()=>dialog('UPnP 模式切换结果',actionNote(result.message),async()=>{},'知道了'));},'授权切换并核对');
}
document.addEventListener('change',e=>{if(e.target.name==='upnpCrossDevice'){const allow=e.target.checked;e.target.checked=upnpState?.config.writePolicy==='service';upnpModeDialog(allow);}});
function upnpView(){
 const s=upnpState,c=s.config;
 const status=(upnpReadError?actionNote('刷新失败，正在显示上次读取结果：'+upnpReadError,true):'')+(s.error?actionNote(s.error,true):'')+`<div class="upnp-connection"><span>${pill(!c.enabled?'管理已停用':s.error?'读取失败':'已连接',!c.enabled?'':s.error?'error':'good')}</span><span class="muted">${esc(c.descriptionUrl||'尚未配置路由器地址')}${c.interface?' · '+esc(c.interface):''}</span></div>`+toggle('upnpCrossDevice','允许跨设备管理映射',c.writePolicy==='service','开启后关闭原厂安全模式；关闭后恢复。需二次验证及 SSH 授权，并短暂重启 UPnP。')+actionNote(c.writePolicy==='service'?'最近配置为跨设备管理；请以原厂实际权限为准。'+(c.writePolicyUpdatedAt?' 最近设置：'+new Date(c.writePolicyUpdatedAt).toLocaleString():''):'安全模式：其他设备的映射仅可查看，编辑与删除已禁用。本机请求地址：'+(s.clientIP||'尚未获取'))+(s.truncated?actionNote('映射超过 512 条，仅展示前 512 条，请减少映射或使用原厂工具核对。',true):'');
 const mappings=c.enabled?(s.mappings?.length?s.mappings.map((m,i)=>`<article class="upnp-mapping"><div><strong>${esc(m.description||'未命名映射')}</strong><p>${pill(m.protocol,'blue')} ${esc(String(m.externalPort))} <span class="flow-arrow">→</span> ${esc(m.internalIP)}:${esc(String(m.internalPort))}</p><small>${m.enabled?'已启用':'已停用'} · ${m.leaseSeconds?`剩余租期约 ${Math.ceil(m.leaseSeconds/60)} 分钟`:'永久租期'}${m.remoteHost?' · 限来源 '+esc(m.remoteHost):''}</small></div><div class="actions">${upnpMappingButtons(m,i)}</div></article>`).join(''):s.error?'':empty('暂无映射','设备自动申请或手动添加的映射会显示在这里。')):empty('UPnP 管理尚未启用','连接设置只启用 LinkNest 管理，不会替你开启路由器 UPnP。');
 const blocks=`<div class="panel-body"><div class="upnp-policy-state">${pill(s.policyPending?'有待应用修改':s.nativePolicyApplied?'已写入原厂配置':'尚未应用',s.policyPending?'blue':'')}<small>${s.appliedAt?'最近成功应用：'+esc(new Date(s.appliedAt).toLocaleString()):'名单先保存，点击“应用到路由器”后才实际限制请求。'}</small></div><p class="split-note">持久规则由原厂防火墙加载；此处记录最近应用结果，不代表已重新验证路由器当前状态。原厂已有的其他黑名单保持不变。</p></div>`+(c.blacklist?.length?c.blacklist.map(b=>`<article class="upnp-mapping"><div><strong>${esc(b.name||'未命名设备')}</strong><p>${esc(b.address)}</p><small>${s.policyPending?(b.enabled?'配置已启用，待应用':'配置已停用，待应用解除'):(b.enabled?'已写入原厂配置':'已应用停用配置；其他原厂限制不变')}</small></div><div class="actions">${ibtn('编辑设备','upnp-block-edit:'+b.id,'edit')}${ibtn('删除设备','upnp-block-delete:'+b.id,'trash')}</div></article>`).join(''):empty('暂无自定义黑名单','支持私网 IPv4、网段和 MAC；MAC 可避免 DHCP 地址变化。'));
 return {status,mappings,blocks};
}
function upnpRender(){
 if(!upnpState)return;
 const view=upnpView();
 for(const [id,content] of [['upnp-status',view.status],['upnp-mappings',view.mappings],['upnp-blacklist',view.blocks]]){const el=$('#'+id);if(!el)continue;if(id==='upnp-blacklist')el.className='';if(el.upnpContent!==content){if(el.innerHTML!==content)el.innerHTML=content;el.upnpContent=content;}}
}
async function refreshUPnP(){
 if(page!=='forwards'||forwardTab()!=='upnp'||!loggedIn)return;
 if(upnpRequest)return upnpRequest;
 const epoch=upnpEpoch;upnpRefreshing=true;syncUPnPControls();
 upnpRequest=(async()=>{
  try{const next=await api('upnp/state');if(epoch!==upnpEpoch||!loggedIn)return;upnpState=next;upnpReadError='';if(page==='forwards'&&forwardTab()==='upnp')upnpRender();}
  catch(e){if(epoch!==upnpEpoch||!loggedIn)return;upnpReadError=e.message;if(page==='forwards'&&forwardTab()==='upnp'){if(upnpState)upnpRender();else{const el=$('#upnp-status');if(el)el.innerHTML=actionNote(e.message,true);}}}
  finally{if(epoch===upnpEpoch){upnpRefreshing=false;upnpRequest=null;syncUPnPControls();}}
 })();
 return upnpRequest;
}
async function upnpSaveConfig(c){await api('upnp/config','PUT',c);upnpState={...(upnpState||{}),config:c};await refreshUPnP();}
function upnpSettings(){const c=upnpState?.config||{enabled:false,descriptionUrl:'',interface:'',lanZone:'lan',blacklist:[]};
 dialog('UPnP 连接设置',actionNote('仅接入原厂服务，不会开启原厂 UPnP 或更改现有映射。停用此管理功能不会撤销已写入路由器的黑名单。')+`<div class="form-grid">${field('descriptionUrl','设备描述地址',c.descriptionUrl||'http://192.168.1.1:5351/rootDesc.xml','私网 IPv4 地址；不支持公网或跳转','url',true)}${picker('interface','绑定网卡（可选）',c.interface||'',[['','不指定'],...(state.interfaces||[]).map(i=>[i.name,i.name])])}${field('lanZone','原厂 LAN 防火墙区域',c.lanZone||'lan','持久黑名单使用；OpenWrt 通常为 lan')}</div><p class="split-note">小米路由器本机访问原厂接口时通常需要绑定 br-lan，并使用 host 网络与 NET_RAW。其他设备上的 LinkNest 可不指定网卡。</p>`+toggle('enabled','启用 UPnP 管理',c.enabled),async d=>{await upnpSaveConfig({...c,...d,descriptionUrl:d.descriptionUrl.trim(),interface:d.interface,lanZone:d.lanZone.trim()});toast('连接设置已保存');});
}
function upnpEditMapping(index){const old=index===undefined?null:upnpState?.mappings?.[Number(index)];if(index!==undefined&&!old)return;if(old&&!upnpCanWrite(old))throw Error('安全模式下此设备映射仅可查看');
 const m=old||{description:'',protocol:'TCP',externalPort:'',internalIP:upnpState?.clientIP||'',internalPort:'',remoteHost:'',leaseSeconds:3600,enabled:true};
 dialog(old?'编辑原厂映射':'添加原厂映射',actionNote(old?'UPnP 没有直接修改接口。将核对旧记录后删除并重建；失败时尝试恢复，期间连接可能短暂中断。':'将直接创建路由器端口映射，可能向外网开放目标端口。不会自动覆盖其他设备的记录。')+(upnpState.config.writePolicy!=='service'?actionNote('当前仅允许管理 LinkNest 本机（'+(upnpState.clientIP||'未获取')+'）的映射；不会自动关闭原厂安全模式。'):'')+`<div class="form-grid">${field('description','映射说明',m.description)}${picker('protocol','协议',m.protocol,[['TCP','TCP'],['UDP','UDP']])}${field('externalPort','外部端口',m.externalPort,'1—65535','number')}${field('internalIP','内网目标 IP',m.internalIP,'私网 IPv4')}${field('internalPort','目标端口',m.internalPort,'1—65535','number')}${field('leaseSeconds','租期（秒）',m.leaseSeconds,'0 为永久，最长 604800 秒','number')}${field('remoteHost','限制远端来源（可选）',m.remoteHost,'留空允许任意来源 IPv4','text',true)}</div>`,async d=>{
  const after={description:d.description.trim(),protocol:d.protocol,externalPort:Number(d.externalPort),internalIP:d.internalIP.trim(),internalPort:Number(d.internalPort),remoteHost:d.remoteHost.trim(),leaseSeconds:Number(d.leaseSeconds),enabled:m.enabled};
  await api('upnp/mapping','POST',{operation:old?'edit':'add',before:old||{},after});await refreshUPnP();toast('映射已确认更新');
 });
}
function upnpEditBlock(id){const c=upnpState?.config;if(!c){toast('请先读取连接设置',true);return;}const old=c.blacklist.find(b=>b.id===id)||{};
 dialog(id?'编辑黑名单设备':'添加黑名单设备',`<div class="form-grid">${field('name','设备备注',old.name)}${field('address','IPv4 / 网段 / MAC',old.address,'支持短横线、冒号等 MAC 格式')}</div>`+toggle('enabled','启用此限制',old.enabled??true,'保存仅修改待应用名单，需另外应用到路由器'),async d=>{const next=structuredClone(c),b={id:id||uid(),name:d.name.trim(),address:d.address.trim(),enabled:d.enabled},i=next.blacklist.findIndex(x=>x.id===id);if(i<0)next.blacklist.push(b);else next.blacklist[i]=b;await upnpSaveConfig(next);toast('已保存，应用到路由器后生效');});
}
function upnpPolicyDialog(){
 if(!upnpState?.config.enabled){toast('请先启用 UPnP 管理',true);return;}
 const hosts=(state.config.sshHosts||[]).filter(h=>h.username==='root'&&h.fingerprint);
 if(!hosts.length){dialog('需要可信路由器 SSH',actionNote('请先在 Web 终端添加路由器的 root SSH 地址并核实指纹。黑名单应用只执行受限的原厂防火墙配置命令，不保存 SSH 凭据。'),async()=>{navigatePage('terminal');},'前往 SSH 主机');return;}
 dialog('应用设备黑名单',actionNote('请通过 HTTPS 或 SSH 隧道操作。只替换 LinkNest 自己创建的黑名单规则，不修改原厂已有规则。不重启 UPnP、不刷新整个防火墙。应用后即使 LinkNest 停止，原厂持久规则仍保留。')+picker('hostId','路由器 root SSH',hosts[0].id,hosts.map(h=>[h.id,h.name+' · '+h.address]))+field('adminPassword','当前管理员密码','','用于授权路由器配置操作','password')+(state.twoFactor?.enabled?twoFactorCodeField():``)+field('password','本次 SSH 密码','','私钥方式可留空；不会保存','password')+area('privateKey','本次 SSH 私钥（可选）','','未加密私钥；不会保存')+toggle('deleteExisting','同时删除能确认属于黑名单设备的已有映射',false,'默认保留；MAC 无法识别或服务拒绝删除时会提示，请手动核对'),async d=>{const result=await api('upnp/policy','POST',d);await refreshUPnP();nextTwoFactorDialog(()=>dialog('黑名单应用结果',actionNote(result.message,Boolean(result.warning)),async()=>{},'知道了'));},'授权并应用');
}
async function upnpAction(key){
 if(key.startsWith('forward-tab:')){navigatePage('forwards',key.split(':')[1]);return true;}
 if(!key.startsWith('upnp-'))return false;
 const [kind,id]=key.split(':');
 if(kind==='upnp-refresh'){await refreshUPnP();return true;}
 if(kind==='upnp-settings'){upnpSettings();return true;}
 if(kind==='upnp-add'||kind==='upnp-edit'){if(!upnpState?.config.enabled)throw Error('请先启用 UPnP 管理');upnpEditMapping(kind==='upnp-edit'?id:undefined);return true;}
 if(kind==='upnp-delete'){const before=upnpState?.mappings?.[Number(id)];if(!before)return true;if(!upnpCanWrite(before))throw Error('安全模式下此设备映射仅可查看');dialog('删除原厂 UPnP 映射',actionNote(`${before.protocol}/${before.externalPort} → ${before.internalIP}:${before.internalPort}。仅删除这次映射；设备可能立即重新申请。如需阻止重新申请，请设置设备黑名单。`),async()=>{await api('upnp/mapping','POST',{operation:'delete',before,after:{}});await refreshUPnP();toast('映射已删除');},'确认删除');return true;}
 if(kind==='upnp-block-add'||kind==='upnp-block-edit'){upnpEditBlock(id);return true;}
 if(kind==='upnp-block-delete'){dialog('移除黑名单设备',actionNote('先移除本地名单；应用到路由器后才解除原有请求限制。不会自动重建映射。'),async()=>{const c=structuredClone(upnpState.config);c.blacklist=c.blacklist.filter(b=>b.id!==id);await upnpSaveConfig(c);});return true;}
 if(kind==='upnp-policy'){upnpPolicyDialog();return true;}
 return false;
}
setInterval(()=>{if(page==='forwards'&&forwardTab()==='upnp'&&loggedIn&&!document.hidden&&!modal.open)refreshUPnP();},15000);
