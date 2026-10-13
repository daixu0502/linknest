'use strict';
let savingImmediateSetting=false;
async function saveImmediateSetting(input){
 if(savingImmediateSetting)return;
 const oldConfig=structuredClone(state.config),config=structuredClone(state.config),name=input.name;
 const isTLS=name.startsWith('adminTls');
 if(isTLS){
  const enabled=$('[name=adminTlsEnabled]').checked;
  config.adminTls={enabled,redirect:enabled&&$('[name=adminTlsRedirect]').checked,certificate:$('[name=adminTlsCertificate]').value};
 }else config.terminalEnabled=input.checked;
 savingImmediateSetting=true;
 const controls=$$('.main input,.main .picker button');
 controls.forEach(x=>x.disabled=true);
 const status=$(isTLS?'#tls-setting-status':'#terminal-setting-status');
 if(status)status.textContent='正在保存…';
 try{
  await api('config','PUT',config);
  state.config=config;
  if(!config.terminalEnabled)stopTerminal();
  toast('设置已生效');
  if(isTLS&&location.protocol==='http:'&&config.adminTls.redirect){location.replace('https://'+location.host+location.pathname+location.search+location.hash);return;}
  if(isTLS&&location.protocol==='https:'&&!config.adminTls.enabled){location.replace('http://'+location.host+location.pathname+location.search+location.hash);return;}
  const latest=await api('state');state=latest;
 }catch(error){
  state.config=oldConfig;
  try{state=await api('state');}catch{}
  toast(error.message+'；请核对当前开关状态',true);
 }finally{
  savingImmediateSetting=false;controls.forEach(x=>x.disabled=false);
  if(page==='settings'&&loggedIn)render();
 }
}
document.addEventListener('change',e=>{if(['terminalEnabled','adminTlsEnabled','adminTlsRedirect','adminTlsCertificate'].includes(e.target.name)&&!modal.contains(e.target))saveImmediateSetting(e.target);});

const lines=v=>String(v||'').split(/[\r\n,]+/).map(x=>x.trim()).filter(Boolean);
const when=(name,value,html)=>`<div class="conditional" data-field="${name}" data-equals="${value}">${html}</div>`;
function conditions(){ $$('.conditional',modal).forEach(el=>{const input=$(`[name="${el.dataset.field}"]`,modal);const value=input?.type==='checkbox'?String(input.checked):input?.value;el.hidden=!el.dataset.equals.split('|').includes(value);}); }
function parts(title,body){return `<div class="form-section"><h3>${esc(title)}</h3>${body}</div>`;}
function statePill(id,enabled){return serviceStatePill(state.rules.find(s=>s.id===id),enabled);}
function listenerActions(r){return `<div class="actions">${statePill(r.id,r.enabled)}${ibtn(r.enabled?'停用主规则':'启用主规则','toggle:'+r.id,'power')}${ibtn('编辑主规则','edit:rules:'+r.id,'edit')}${ibtn('删除主规则','delete:rules:'+r.id,'trash')}</div>`;}
function backendName(r){return r.backend==='bookmarks'?'内置轻面板':r.backend==='wol'?'内置 WOL':r.target;}
function routeAccessLinks(rule,sub){
 const port=rule.listen.slice(rule.listen.lastIndexOf(':')+1),scheme=rule.tls?'https':'http';
 const hosts=(sub.domains||[]).filter(h=>h&&!h.includes('*'));
 return hosts.length?hosts.map(h=>{const host=h.includes(':')&&!h.startsWith('[')?'['+h+']':h;const url=scheme+'://'+host+':'+port+'/';return `<a class="route-access" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(url)} ↗</a>`;}).join(''):'<small>请使用匹配此规则的实际域名访问</small>';
}
function proxyPage(){
 const rules=state.config.rules.filter(r=>r.kind==='web');
 return notice('不同主规则可共用同一端口，监听 IP 与网络栈须一致；按域名分流，各自选择证书。精确域名 → 最长通配后缀 → 默认入口；同端口域名不得重复，默认入口只能有一个。')+(rules.length?rules.map(r=>{
  const st=state.rules.find(s=>s.id===r.id);
  return panel(r.name,`${r.tls?'HTTPS':'HTTP'} · ${r.listen} · ${r.network==='ipv6'?'仅 IPv6':r.network==='ipv4'?'仅 IPv4':r.network==='dual'?'IPv4 / IPv6':'兼容监听'}${r.openFirewall?' · 已申请自动放行':''}`,
   (st?.state==='error'?`<div class="panel-body">${notice(st.message,true)}</div>`:st?.message?.includes('共享端口')?(()=>{const help=notice(st.message.replace(/^监听正常/,'运行正常'),false,'proxy-shared:'+r.id);return help?`<div class="panel-body notice-only">${help}</div>`:'';})():'')+
   `<div class="child-toolbar"><span>${(r.routes||[]).length} 条子规则</span>${btn('添加子规则','route-add:'+r.id,'plus')}</div>`+
   ((r.routes||[]).length?r.routes.map(sub=>`<article class="route-row"><div class="route-title"><strong>${esc(sub.name)}</strong>${pill(sub.enabled?'已启用':'已停用',sub.enabled?'blue':'')}</div><div class="route-flow"><div><small>前端域名</small><p>${esc(sub.domains.length?sub.domains.join(' · '):'默认入口（全部域名）')}</p>${routeAccessLinks(r,sub)}</div><span class="flow-arrow">→</span><div><small>后端服务</small><p>${esc(backendName(sub))}</p>${['bookmarks','wol'].includes(sub.backend)?`<small>${sub.publicAccess?'免密码访问':'独立密码保护'}</small>`:''}</div></div><div class="actions">${ibtn(sub.enabled?'停用子规则':'启用子规则','route-toggle:'+r.id+':'+sub.id,'power')}${ibtn('编辑子规则','route-edit:'+r.id+':'+sub.id,'edit')}${ibtn('删除子规则','route-delete:'+r.id+':'+sub.id,'trash')}</div></article>`).join(''):empty('添加第一条子规则','选择前端域名，以及外部 Web 服务、内置轻面板或 WOL。')),listenerActions(r));
 }).join(''):panel('反向代理','先创建监听入口，再添加子规则',empty('暂无主规则','例如使用一个 HTTPS 端口承接多个服务域名。')));
}
function forwardPage(){const rules=state.config.rules.filter(r=>r.kind!=='web');return notice('远程桌面建议使用 TCP + UDP。IPv4 内核加速直接走路由器 NAT，减少用户态中转；需 host 网络和防火墙授权。IPv6 或域名目标使用兼容转发。')+panel('转发规则','独立启停，与反向代理分开管理',rules.length?ruleRows(rules):empty('暂无端口转发','按协议创建监听端口与目标主机。'));}
function editListener(group,id){
 const old=state.config.rules.find(r=>r.id===id)||{};const web=old.kind?old.kind==='web':group==='rules';
 let host='',port=web?'18080':'19000';if(old.listen){const n=old.listen.lastIndexOf(':');host=old.listen.slice(0,n).replace(/^\[|\]$/g,'');port=old.listen.slice(n+1);if(['0.0.0.0','::'].includes(host))host='';}
 const network=old.network||(old.listen?.startsWith('[::]')?'dual':old.listen?.startsWith('[')?'ipv6':'ipv4');
 dialog((id?'编辑':'添加')+(web?'反向代理主规则':'端口转发'),`<div class="form-grid">${field('name','规则名称',old.name)}${picker('network','监听网络',network,[['ipv4','仅 IPv4'],['ipv6','仅 IPv6'],['dual','IPv4 + IPv6']])}${field('host','监听 IP（可选）',host,'留空监听所选协议族的所有地址；双栈请留空')}${field('port','监听端口',port,'反代可与其他主规则共用端口（监听 IP、网络栈一致）；不可与 TCP 转发或其他服务冲突','number')}${!web?picker('kind','转发协议',old.kind||'tcp',[['tcp','TCP'],['udp','UDP'],['tcpudp','TCP + UDP（同时转发）']])+picker('forwardMode','转发方式',old.forwardMode||'proxy',[['proxy','兼容转发（IPv4 / IPv6 / 域名）'],['kernel','内核加速（仅 IPv4）']])+field('target','目标主机:端口',old.target,'内核加速请选仅 IPv4 并填写 IPv4 地址；两种协议使用同一目标端口'):picker('certificate','TLS 证书',old.certificate||'',[['','不选择'],...state.certificates.map(c=>[c.id,c.name||c.id])])}</div>${!web?notice('内核模式不经 LinkNest 复制数据，适合远程桌面。目标看到路由器 IP；不支持路由器本机访问或转发回本机。切换后请重新连接，已建立的 NAT 会话可能保留至超时。'):''}${web?toggle('tls','HTTPS 监听',old.tls,'证书需要覆盖子规则的所有域名；可使用通配符 / 多域名证书')+when('tls','true',toggle('redirectHttp','HTTP 自动跳转 HTTPS',old.redirectHttp,'HTTP 与 HTTPS 使用相同端口，保留路径和查询参数；关闭后拒绝明文 HTTP')):''}${toggle('enabled','启用主规则',old.enabled,'默认停用，确认配置后再启用')}${toggle('openFirewall','防火墙自动放行',old.openFirewall,'放行仅作用于此服务端口；内核模式关闭时沿用路由器原有转发策略')}`,async d=>{
  let h=d.host.trim();if(!h)h=d.network==='ipv4'?'0.0.0.0':'::';if(h.includes(':')&&!h.startsWith('['))h='['+h+']';
  await saveItem('rules',{...old,id:id||uid(),name:d.name.trim(),kind:web?'web':d.kind,forwardMode:web?'':d.forwardMode,network:d.network,listen:`${h}:${d.port}`,target:web?'':d.target.trim(),domain:'',routes:web?(old.routes||[]):[],tls:web?d.tls:false,redirectHttp:web&&d.tls?d.redirectHttp:false,certificate:web?d.certificate:'',enabled:d.enabled,openFirewall:d.openFirewall});
 });conditions();
}
function editRoute(parent,id){
 const rule=state.config.rules.find(r=>r.id===parent),old=(rule.routes||[]).find(r=>r.id===id)||{};
 dialog((id?'编辑':'添加')+'子规则',parts('前端入口',`<div class="form-grid">${field('name','子规则名称',old.name)}${picker('backend','后端类型',old.backend||'proxy',[['proxy','外部 Web 服务'],['bookmarks','内置轻面板'],['wol','内置 WOL']])}${area('domains','前端域名',(old.domains||[]).join('\n'),'每行一个，仅填写域名；支持 *.example.com；使用 IP 访问时需明确添加该 IP。留空为默认入口。')}</div>`)+
  when('backend','proxy',parts('后端服务',field('target','后端地址',old.target,'例如 http://192.168.1.20:5244','url')+toggle('preserveHost','保留访问域名（Host）',old.preserveHost,'反代 LinkNest 等管理页面时建议开启，使 Host 与浏览器 Origin 中的域名和端口一致')+toggle('rewriteOrigin','同源请求来源适配',old.rewriteOrigin,'仅在仍报来源错误时开启：先严格校验公网入口同源，再将 Origin / Referer 适配为上游协议和 Host；不会放行跨站请求。HTTPS 应由本反代终止')+toggle('skipTlsVerify','跳过后端 TLS 证书验证',old.skipTlsVerify,'仅用于你信任的自签名后端；默认验证证书')))+
  when('backend','bookmarks|wol',parts('独立访问保护',notice('发布的是只读导航 / 设备唤醒页，不包含管理后台。请先在对应模块配置链接或设备，并优先使用 HTTPS 主规则。')+toggle('publicAccess','免密码访问',old.publicAccess,'关闭时要求独立密码；开启后任何能访问此入口的人都可查看链接或发送唤醒包')+when('publicAccess','false',field('accessPassword','此入口的独立访问密码','',id?'12—72 字节；留空保留已有密码；从免密改回需重新填写':'12—72 字节，不要与管理员密码相同','password'))))+toggle('enabled','启用子规则',old.enabled??true,'只在主规则启用后对外提供服务'),async d=>{
   const item={id:id||uid(),name:d.name.trim(),enabled:d.enabled,domains:lines(d.domains).map(s=>s.toLowerCase()),backend:d.backend,target:d.backend==='proxy'?d.target.trim():'',skipTlsVerify:d.backend==='proxy'?d.skipTlsVerify:false,preserveHost:d.backend==='proxy'&&d.preserveHost,rewriteOrigin:d.backend==='proxy'&&d.rewriteOrigin,publicAccess:d.backend!=='proxy'&&d.publicAccess,accessPassword:d.backend==='proxy'||d.publicAccess?'':d.accessPassword};
   const updated=structuredClone(rule);updated.routes=updated.routes||[];const n=updated.routes.findIndex(r=>r.id===id);if(n<0)updated.routes.push(item);else updated.routes[n]=item;await saveItem('rules',updated);
  });conditions();
}
function ddnsRouterAddresses(){const ips=state.routerIPs;return `<div class="ddns-router-ips" aria-label="路由器公网地址">${['ipv4','ipv6'].map(f=>{const ip=ips?.[f],value=ip?.value||(ip?.loading?'检测中…':'未获取');const hint=ip?.error||'路由器公网地址，独立于子记录来源';return `<div class="ddns-meta-item"><small>${f.toUpperCase()}</small><span class="ddns-address" title="${esc(hint)}">${esc(value)}${ip?.value&&ip?.error?'（上次检测）':''}</span></div>`;}).join('')}</div>`;}
function ddnsPage(){
 const c=state.config;
 return notice('自动 IPv4 查询公网出口；IPv6 优先选本机公网地址，存在多个候选时使用 IPv6 出口检测。部署在路由器并使用 host 网络，才能看到路由器网卡；检测成功不代表外网端口可达。')+
  `<div class="section-toolbar"><span>任务与解析记录</span>${btn('共享阿里云凭据','dns-account','shield')}</div>`+
  (c.ddns.length?c.ddns.map(d=>{const s=state.ddns.find(x=>x.id===d.id);return panel(d.name,`阿里云 DNS · ${d.interval} 秒检查 · 启动延迟 ${d.startDelay||0} 秒`,
   `<div class="ddns-summary record-summary"><div class="ddns-times"><div class="ddns-meta-item"><small>最近检查</small><time>${s?.updated?esc(new Date(s.updated).toLocaleString()):'尚未检查'}</time></div><div class="ddns-meta-item"><small>下次检查</small><time>${s?.next?esc(new Date(s.next).toLocaleString()):'手动 / 尚未计划'}</time></div></div>${ddnsRouterAddresses()}</div><div class="child-toolbar"><span>${esc(s?.message||'等待检查')} · 凭据${state.credentialFlags?.[d.id]?'已保存':'未配置'}</span><div class="actions">${btn('检测各记录 IP','detect:'+d.id,'globe')}${btn('添加记录','record-add:'+d.id,'plus')}</div></div>`+
   ((d.records||[]).length?`<div class="record-head"><span>类型</span><span>域名 / 线路</span><span>当前解析值 / 来源</span><span>同步状态</span><span>操作</span></div>`+d.records.map(r=>{const rs=s?.records?.find(x=>x.id===r.id);return `<article class="record-row"><div class="record-type">${esc(r.type.replace('_URL',''))}</div><div class="record-domain"><strong>${esc(r.domain)}</strong><small>${r.name?esc(r.name)+' · ':''}${esc(r.line)} · TTL ${r.ttl}${r.type==='MX'?' · 优先级 '+r.priority:''}</small><small>主域名：${esc(r.zone||rs?.zone||'自动识别')}</small></div><div class="record-value"><p>${esc(rs?.value||r.value)}</p><small>${esc(recordSourceLabel(r))}</small></div><div class="record-status">${pill(!r.enabled?'已停用':s?.state==='running'?'同步中':rs?.state==='error'?'更新失败':rs?.state==='success'?'已同步':'待同步',!r.enabled?'':rs?.state==='error'?'error':rs?.state==='success'?'good':'blue')}<small>${esc(rs?.message||(!d.enabled?'任务未启用自动更新':'等待同步'))}</small></div><div class="actions">${['A','AAAA'].includes(r.type)?ibtn('检测此记录 IP','detect:'+d.id+':'+r.id,'globe'):''}${ibtn('切换记录启用','record-toggle:'+d.id+':'+r.id,'power')}${ibtn('编辑记录','record-edit:'+d.id+':'+r.id,'edit')}${ibtn('删除记录','record-delete:'+d.id+':'+r.id,'trash')}</div></article>`;}).join(''):empty('还没有解析记录','支持地址、别名、邮件、文本、服务绑定等 13 种记录类型。')),
   `<div class="actions">${pill(d.enabled?'自动更新':'手动',d.enabled?'blue':'')}${ibtn('立即更新','run:'+d.id,'refresh')}${ibtn('编辑任务','edit:ddns:'+d.id,'edit')}${ibtn('删除任务','delete:ddns:'+d.id,'trash')}</div>`);}).join(''):panel('动态域名','阿里云 DNS',empty('创建第一个 DDNS 任务','一个任务管理多条记录，IPv4 / IPv6 分别检测、分别汇报。')));
}
function sourceFields(prefix,label,source={}){
 return parts(label,`<div class="form-grid">${picker(prefix+'Mode','获取方式',source.mode||'auto',[['auto','自动检测'],['interface','指定网卡'],['url','指定 HTTPS 检测接口']])}${when(prefix+'Mode','interface',picker(prefix+'Interface','网卡',source.interface||'',[['','请选择'],...(state.interfaces||[]).map(i=>[i.name,`${i.name} · ${[...i.ipv4,...i.ipv6].join(', ')||'暂无公网地址'}`])]))}${when(prefix+'Mode','url',field(prefix+'URL','检测接口',source.url||`https://api${prefix==='v4'?'4':'6'}.ipify.org`,'需返回纯文本公网 IP','url'))}</div>`);
}
function recordSourceLabel(r){if(!['{ipv4Addr}','{ipv6Addr}'].includes(r.value))return '固定解析内容';const s=r.source||{};return s.mode==='interface'?'网卡：'+s.interface:s.mode==='url'?'接口：'+s.url:'自动检测 '+(r.type==='AAAA'?'IPv6':'IPv4');}
function editDDNS(id){
 const old=state.config.ddns.find(r=>r.id===id)||{};const ref=old.credentialRef||(old.account?.accessKeyId?'':'@shared');
 dialog((id?'编辑':'添加')+'DDNS 任务',parts('任务设置',`<div class="form-grid">${field('name','任务名称',old.name)}${field('interval','检查 / 强制核对间隔（秒）',old.interval||300,'即使本机 IP 未变，也会核对远端记录','number')}${field('startDelay','首次检查延迟（秒）',old.startDelay||0,'供开机网络准备使用','number')}${picker('credentialRef','阿里云凭据',ref,[['','本任务独立填写'],['@shared','使用共享凭据'],...state.config.ddns.filter(x=>x.id!==id).map(x=>[x.id,'复用任务：'+x.name])])}</div>`)+when('credentialRef','',parts('阿里云 DNS 账户',`<div class="form-grid">${field('accessKeyId','AccessKey ID',old.account?.accessKeyId)}${field('secret','AccessKey Secret','',state.credentialFlags?.[id]?'已加密保存，留空保留':'建议使用最小权限 RAM 账户','password')}</div>`))+notice('IPv4 / IPv6 获取方式在每条解析子规则内设置，可使用不同网卡。')+toggle('enabled','启用自动更新',old.enabled,'启用后将按间隔实际写入该任务中已启用的 DNS 记录'),async d=>{
  await saveItem('ddns',{...old,id:id||uid(),name:d.name.trim(),enabled:d.enabled,interval:Number(d.interval),startDelay:Number(d.startDelay),credentialRef:d.credentialRef,account:d.credentialRef?(old.account||{accessKeyId:'',secret:''}):{accessKeyId:d.accessKeyId.trim(),secret:d.secret},records:old.records||[]});
 });conditions();
}
const dnsTypes=[['A','A · IPv4'],['AAAA','AAAA · IPv6'],['CNAME','CNAME · 域名别名'],['MX','MX · 邮件服务器'],['TXT','TXT · 文本'],['SRV','SRV · 服务位置'],['NS','NS · 域名服务器'],['CAA','CAA · 证书颁发授权'],['PTR','PTR · 反向解析'],['SVCB','SVCB · 服务绑定'],['HTTPS','HTTPS · HTTPS 服务绑定'],['REDIRECT_URL','显性 URL 转发'],['FORWARD_URL','隐性 URL 转发']];
const dnsHints={A:'公网 IPv4 或 {ipv4Addr}',AAAA:'公网 IPv6 或 {ipv6Addr}',CNAME:'目标域名，例如 home.example.com（可带末尾点）',MX:'邮件服务器域名，例如 mail.example.com；优先级在下方填写',TXT:'单行文本，例如 v=spf1 -all；保留内容原样',SRV:'优先级 权重 端口 目标，例如 0 5 443 server.example.com',NS:'DNS 服务器域名，例如 ns1.example.com',CAA:'例如 0 issue "letsencrypt.org"',PTR:'目标域名；需要对应 IP 反向解析区的管理权限',SVCB:'例如 1 . alpn="h2,h3"；别名模式为 0 target.example.com',HTTPS:'例如 1 . alpn="h2,h3"；具体参数由阿里云校验',REDIRECT_URL:'完整 HTTP/HTTPS 地址；阿里云可能要求备案和套餐权限',FORWARD_URL:'完整 HTTP/HTTPS 地址；阿里云可能要求备案和套餐权限'};
function updateDNSValueHint(){const type=$('[name=type]',modal)?.value;const hint=$('[data-dns-hint]',modal);if(hint)hint.textContent=dnsHints[type]||'';}
function editRecord(parent,id){
 const task=state.config.ddns.find(r=>r.id===parent),old=task.records.find(r=>r.id===id)||{};
 dialog((id?'编辑':'添加')+'解析记录',`<div class="form-grid">${field('name','记录备注',old.name)}${picker('type','记录类型',old.type||'A',dnsTypes)}${field('domain','完整解析域名',old.domain,'例如 home.example.com；SRV 支持 _service._tcp 前缀')}${field('zone','阿里云 DNS 主域名（可选）',old.zone,'留空从账户托管域名中自动匹配；需要 DescribeDomains 权限，失败可手填')}${field('value','解析内容',old.value??'{ipv4Addr}','','text',true)}<small class="wide" data-dns-hint></small>${when('type','MX',field('priority','MX 优先级',old.priority||1,'1—50，数值越小优先级越高','number'))}${field('ttl','TTL（秒）',old.ttl||600,'最小 TTL 以阿里云套餐为准','number')}${field('line','解析线路',old.line||'default','默认 default；其他填阿里云线路标识')}</div>`+when('type','A',sourceFields('v4','此记录的 IPv4 获取',old.source||task.ipv4))+when('type','AAAA',sourceFields('v6','此记录的 IPv6 获取',old.source||task.ipv6))+toggle('enabled','启用记录',old.enabled??true,'已启用任务的新增或修改记录保存后立即同步；停用任务不写入 DNS'),async d=>{const prefix=d.type==='AAAA'?'v6':'v4';const rec={id:id||uid(),name:d.name,enabled:d.enabled,type:d.type,priority:d.type==='MX'?Number(d.priority):0,ttl:Number(d.ttl),domain:d.domain.trim().toLowerCase().replace(/\.$/,''),zone:d.zone.trim().toLowerCase().replace(/\.$/,''),value:d.type==='TXT'?d.value:d.value.trim(),line:d.line.trim(),source:{mode:d[prefix+'Mode']||'auto',interface:d[prefix+'Interface']||'',url:d[prefix+'URL']||''}};const next=structuredClone(task),n=next.records.findIndex(r=>r.id===id);if(n<0)next.records.push(rec);else next.records[n]=rec;await saveItem('ddns',next);});conditions();updateDNSValueHint();
}
function settingsPage(){const c=state.config;return `<div class="grid-equal">${adminTLSPanel()}${panel('安全与外观','敏感能力按需开启',`<div class="panel-body">${toggle('terminalEnabled','启用 Web SSH 终端',c.terminalEnabled,'仅建议在受信网络中使用')}<p id="terminal-setting-status" class="split-note" role="status">切换后立即保存生效</p>${btn('切换外观','theme','sun')}<div class="section-label">账户 · ${esc(state.username||'admin')}</div>${btn('修改用户名和密码','password','shield')}${btn('退出登录','logout','logout')}</div>`)}${panel('说明提示','仅影响此浏览器，不改变服务配置',`<div class="panel-body"><p class="muted">“隐藏”持续到本次浏览器会话结束；“不再提示”会长期记住。故障与关键安全警告始终显示。</p>${btn('恢复所有提示','notice-restore','refresh')}</div>`)}${twoFactorPanel()}${panel('配置备份','导出不包含 DNS / 证书密钥、入口密码及管理员账户',`<div class="panel-body">${notice('完整备份请复制整个数据卷；master.key 与加密配置须一同保留。')}${btn('导出配置','export','download')}${btn('导入配置','import-config','plus')}</div>`)}${panel('关于栖网','LinkNest '+state.version,`<div class="panel-body"><p>单镜像 / 单容器的网络服务控制台。</p><p class="split-note">不挂载 Docker Socket，不需要宿主机权限助手；默认不管理防火墙。阿里云 DNS 凭据请在动态域名中设置，证书使用独立凭据。</p><p class="code">管理监听：${esc(state.adminAddress)}</p></div>`)}</div>`;}
async function workflowAction(key){
 if(await certificateAction(key)||await bookmarkAction(key))return true;
 const [action,parent,id]=key.split(':');
 if(action==='route-add'||action==='route-edit'){editRoute(parent,id);return true;}
 if(action==='record-add'||action==='record-edit'){editRecord(parent,id);return true;}
 if(action==='record-delete'){
  const task=state.config.ddns.find(x=>x.id===parent),record=task?.records.find(x=>x.id===id);if(!record)return true;
  dialog('删除解析记录',notice(`${record.domain} · ${record.type} · ${record.line||'default'}。默认只移除此子记录配置，远端解析保留。`)+toggle('deleteRemote','同时删除远端 DNS 记录',false,'勾选后会删除阿里云中同域名、同类型、同线路的唯一记录，可能影响现有服务。失败时保留本地配置；需 DeleteDomainRecord 权限。'),async d=>{
   const result=await api('ddns/record/delete','POST',{id:parent,recordId:id,deleteRemote:d.deleteRemote});state=await api('state');render();toast(result.message);
  },'确认删除');return true;
 }
 if(['route-toggle','route-delete','record-toggle'].includes(action)){
  const group=action.startsWith('route')?'rules':'ddns',children=group==='rules'?'routes':'records',item=structuredClone(state.config[group].find(r=>r.id===parent)),child=item[children].find(r=>r.id===id),deleting=action.endsWith('delete');
  dialog(deleting?'删除配置':child.enabled?'停用配置':'启用配置',notice(deleting?'只删除此配置，不删除远端 DNS 记录或目标文件。':'修改会立即应用；启用自动更新的 DNS 任务会立即同步。'),async()=>{if(deleting)item[children]=item[children].filter(r=>r.id!==id);else child.enabled=!child.enabled;await saveItem(group,item);},'确认');return true;
 }
 if(action==='dns-account'){dialog('共享阿里云 DNS 凭据',notice('仅供动态域名任务使用，不用于证书申请。凭据变更会立即同步引用它的已启用任务。')+`<div class="form-grid">${field('accessKeyId','AccessKey ID',state.config.dns.accessKeyId)}${field('secret','AccessKey Secret','',state.dnsSecretSet?'已加密保存，留空保留':'尚未配置','password')}</div>`,async d=>{const c=structuredClone(state.config);c.dns=d;await saveConfig(c);});return true;}
 if(action==='detect'){const v=await api('ddns/detect','POST',{id:parent,recordId:id||''});dialog('子规则 IP 检测结果',notice('此次只检测地址，没有修改任何 DNS 记录。停用记录只在单独检测时读取。')+(v.records||[]).map(r=>`<div class="form-section"><h3>${esc(r.type+' · '+r.domain)}</h3><p class="code">${esc(r.error||r.value||'已停用')}</p></div>`).join(''),async()=>{},'知道了');return true;}
 return false;
}
document.addEventListener('change',e=>{if(modal.contains(e.target)){conditions();if(e.target.name==='type'){const v=$('[name=value]',modal);if(v&&['{ipv4Addr}','{ipv6Addr}'].includes(v.value))v.value=e.target.value==='AAAA'?'{ipv6Addr}':e.target.value==='A'?'{ipv4Addr}':'';updateDNSValueHint();}}});
