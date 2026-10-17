'use strict';
const certStage={prepare:'准备申请',account:'连接 ACME',order:'创建订单',dns_create:'创建 TXT',dns_wait:'等待 DNS 生效',validation:'CA 验证',signing:'签发证书',save:'保存证书',cleanup:'清理 TXT'};
function certificateJobs(){
 return (state.certificateJobs||[]).slice().sort((a,b)=>String(b.updated).localeCompare(String(a.updated))).map(j=>`<details class="cert-job" data-cert-job="${esc(j.id)}" ${j.state==='running'||j.state==='error'?'open':''}><summary><span class="grow"><strong>${esc(j.id)}</strong><small>${esc(certStage[j.stage]||j.stage||'申请任务')} · ${j.updated?esc(new Date(j.updated).toLocaleString()):''}</small></span>${j.state==='running'?'<span class="spinner"></span>':''}${pill(j.state==='running'?'处理中':j.state==='success'?'已完成':'失败',j.state==='error'?'error':j.state==='success'?'good':'blue')}</summary><div class="cert-process"><p class="cert-result ${j.state==='error'?'form-error':''}">${esc(j.message)}</p><ol>${(j.steps||[]).map(s=>`<li><time>${esc(new Date(s.time).toLocaleTimeString())}</time><div><strong>${esc(certStage[s.stage]||s.stage)}</strong><p>${esc(s.message)}</p></div></li>`).join('')}</ol></div></details>`).join('')||empty('暂无过程记录','申请后显示各阶段结果，重启后仍保留最近一次过程。');
}
function certificatesPage(){
 const tasks=state.certificateTasks||[],certs=state.certificates||[],ids=[...new Set([...tasks.map(t=>t.id),...certs.map(c=>c.id)])];
 return notice('证书以长期任务保存。编辑只保存配置；手动申请 / 续期才会立即创建 DNS 验证记录。申请失败不替换原证书。')+
 panel('证书任务','自动续期每 12 小时检查；已签发证书剩余 30 天时尝试续期',ids.length?ids.map(id=>{
  const t=tasks.find(t=>t.id===id),c=certs.find(c=>c.id===id),j=(state.certificateJobs||[]).find(j=>j.id===id),busy=j?.state==='running';
  const valid=c&&!c.error&&Date.parse(c.expires)>Date.now();
  return `<article class="cert-card"><div class="cert-heading"><div class="grow"><strong>${esc(t?.name||c?.name||id)}</strong><small>${esc(id)} · ${esc((t?.domains||c?.domains||[]).join(' · '))}</small></div>${pill(busy?'申请中':valid?(c.staging?'测试证书':'有效'):c?'无效 / 已过期':'尚未签发',busy?'blue':valid?'good':'error')}</div><div class="cert-meta"><div><small>有效期</small><p>${c?valid?'剩余 '+Math.max(0,c.remainingDays)+' 天':'已过期 / 无效':'等待首次签发'}</p><small>${c?.expires?esc(new Date(c.expires).toLocaleString())+' 到期':''}</small></div><div><small>来源 / 自动续期</small><p>${t?'ACME · Let’s Encrypt':'手动导入'}</p><small>${t?(t.disabled?'自动续期已关闭':'自动续期已开启'):'不支持自动续期'}</small></div></div><div class="cert-actions">${t?`<button class="button" data-action="cert-run:${esc(id)}" ${busy?'disabled':''}>${icon('refresh')}${c?'手动续期':'申请证书'}</button><button class="button" data-action="cert-edit:${esc(id)}" ${busy?'disabled':''}>${icon('edit')}编辑</button>`:''}<button class="button" data-action="cert-log:${esc(id)}">${icon('info')}过程日志</button><button class="button danger" data-action="cert-delete:${esc(id)}" ${busy?'disabled':''}>${icon('trash')}删除</button></div></article>`;
 }).join(''):empty('暂无证书任务','创建申请任务，或导入现有 PEM 证书。'),btn('导入 PEM','import-cert','download'))+
 panel('申请过程','运行时每 2 秒刷新；不显示 DNS 验证值、AccessKey Secret 或私钥',certificateJobs());
}
function editCertificate(id){
 const old=(state.certificateTasks||[]).find(c=>c.id===id)||{};
 dialog(id?'编辑证书任务':'添加证书任务',actionNote('保存任务不会申请证书或修改 DNS。首次申请及手动续期需另行确认；同名成功签发后替换原证书。')+parts('证书信息',`<div class="form-grid">${field('name','证书名称',old.name)}${id?`<div class="field"><span>证书标识（不可修改）</span><p class="code">${esc(id)}</p></div>`:field('id','证书标识','','字母、数字、短横线或下划线')}${area('domains','证书域名',(old.domains||[]).join('\n'),'每行一个，例如 example.com 和 *.example.com')}${field('zone','阿里云 DNS 主域名',old.zone,'例如 example.com')}${field('email','联系邮箱',old.email,'','email')}</div>`)+parts('DNS 验证 · 独立凭据',`<div class="form-grid">${field('accessKeyId','AccessKey ID',old.account?.accessKeyId)}${field('secret','AccessKey Secret','',old.secretSet?'已保存，留空保留；更换 ID 时必须重新填写':'请独立填写','password')}</div>`)+toggle('staging','Let’s Encrypt 测试环境',old.staging??true,'测试证书不受浏览器信任；修改环境仅影响下次申请')+toggle('autoRenew','启用自动续期',!old.disabled,'首次签发后，到期前 30 天自动尝试续期'),async d=>{await api('certificates/task','PUT',{id:id||d.id.trim(),name:d.name.trim(),domains:lines(d.domains),zone:d.zone.trim().toLowerCase(),email:d.email.trim(),staging:d.staging,disabled:!d.autoRenew,account:{accessKeyId:d.accessKeyId.trim(),secret:d.secret}});await refresh(true);toast('任务已保存，点击申请证书开始首次签发');});
}
async function certificateAction(key){
 const [action,id]=key.split(':');
 if(action==='issue'||action==='cert-edit'){editCertificate(id);return true;}
 if(action==='cert-run'){dialog('申请 / 手动续期',actionNote('将使用此任务的独立凭据创建临时 DNS TXT。正式证书域名会进入公开证书透明度日志；继续表示同意 Let’s Encrypt 服务条款。',true)+'<p><a href="https://letsencrypt.org/repository/" target="_blank" rel="noopener noreferrer">查看服务条款</a></p>',async()=>{await api('certificates/run','POST',{id});await refresh(true);toast('任务已开始，可查看申请过程');},'同意并申请');return true;}
 if(action==='cert-delete'){dialog('删除证书任务',actionNote('删除此任务、证书文件及对应的加密凭据和过程日志。被反向代理或管理后台引用时禁止删除。此操作不撤销 CA 已签发证书。',true),async()=>{await api('certificates/delete','POST',{id});await refresh(true);toast('证书任务已删除');},'确认删除');return true;}
 if(action==='cert-log'){const el=$$('[data-cert-job]').find(e=>e.dataset.certJob===id);if(el){el.open=true;el.scrollIntoView({block:'start',behavior:'smooth'});}else toast('此任务尚无申请过程记录');return true;}

 return false;
}
function adminTLSPanel(){
 const t=state.config.adminTls||{};
 return panel('管理后台 HTTPS','HTTP / HTTPS 共用当前管理端口',`<div class="panel-body">${notice(state.adminTlsStatus?.message||'管理 HTTPS 未启用',t.enabled&&!state.adminTlsStatus?.ready)}${picker('adminTlsCertificate','管理后台证书',t.certificate||'',[['','请选择'],...state.certificates.filter(c=>!c.error&&Date.parse(c.expires)>Date.now()).map(c=>[c.id,(c.name||c.id)+(c.staging?'（测试证书）':'')])])}${toggle('adminTlsEnabled','启用 HTTPS',t.enabled,'使用所选证书；首次开启不会自动跳转')}${toggle('adminTlsRedirect','HTTP 自动跳转到 HTTPS',t.redirect,'请先用证书覆盖的域名验证 HTTPS；关闭 HTTPS 时跳转同时关闭')}<p class="split-note">监听地址 ${esc(state.adminAddress)} 保持不变。证书续期后新连接自动加载；证书丢失或过期时停止跳转，保留 HTTP 恢复入口。</p><p class="split-note" role="status" id="tls-setting-status">切换开关、选择证书后立即生效</p></div>`);
}
