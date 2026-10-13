'use strict';
const defaultIconSources=[
 {id:'iconify',name:'Iconify 矢量图标库',kind:'iconify',url:'https://api.iconify.design',disabled:false},
 {id:'selfhst',name:'selfh.st 自托管应用图标',kind:'selfhst',url:'https://cdn.jsdelivr.net/gh/selfhst/icons@main/index.json',disabled:false}
];
const iconSourceNames={iconify:'Iconify API',selfhst:'selfh.st 目录',json:'JSON 目录'};
const isLocalIcon=value=>/^\/__linknest\/icons\/[a-f0-9]{64}\.png$/.test(value);
function iconLibrarySources(){return state.config.panel?.iconSources??defaultIconSources;}
function safeIconURL(value,base){try{const u=new URL(value,base);return u.protocol==='https:'&&!u.username&&!u.password?u.href:'';}catch{return '';}}
function iconSearchResults(data,source,query){
 const base=source.url.replace(/\/+$/,'')+'/';
 if(source.kind==='iconify')return (Array.isArray(data.icons)?data.icons:[]).filter(name=>typeof name==='string'&&/^[a-z0-9-]+:[a-z0-9-]+$/.test(name)).slice(0,96).map(name=>({name,url:base+name.replace(':','/')+'.svg'}));
 if(source.kind==='selfhst'){
  if(!Array.isArray(data))throw Error('selfh.st 图标源需返回官方 index.json 数组');
  const q=query.trim().toLocaleLowerCase();
  return data.filter(item=>item&&typeof item.Name==='string'&&typeof item.Reference==='string'&&/^[a-z0-9][a-z0-9-]*$/.test(item.Reference)&&(item.SVG==='Yes'||item.PNG==='Yes')&&(item.Name+' '+item.Reference+' '+(typeof item.Tags==='string'?item.Tags:'')).toLocaleLowerCase().includes(q)).slice(0,96).map(item=>{const format=item.SVG==='Yes'?'svg':'png';return {name:item.Name.slice(0,120),url:safeIconURL(format+'/'+item.Reference+'.'+format,source.url)};}).filter(item=>item.url);
 }
 if(source.kind!=='json')throw Error('不支持的图标源类型');
 const items=Array.isArray(data)?data:data.icons;
 if(!Array.isArray(items))throw Error('JSON 图标源需返回 icons 数组');
 const q=query.trim().toLocaleLowerCase();
 return items.filter(item=>item&&typeof item.name==='string'&&typeof item.url==='string'&&(item.name+' '+(Array.isArray(item.keywords)?item.keywords.join(' '):'')).toLocaleLowerCase().includes(q)).map(item=>({name:item.name.slice(0,120),url:safeIconURL(item.url,source.url)})).filter(x=>x.url).slice(0,96);
}
function iconPickerMarkup(){
 const sources=iconLibrarySources().filter(x=>!x.disabled);
 return `<div class="icon-library wide" id="site-icon-library" hidden><div class="icon-library-title"><strong>选择图标</strong><button type="button" data-icon-library-close>收起</button></div><div class="icon-library-body"><p class="muted">搜索并点击图标，自动缓存到本机并填入上方地址。不发送后台凭据；图标源在“轻面板 → 图标库”管理。</p><div class="icon-search-tools"><label class="field"><span>搜索图标</span><input data-icon-query placeholder="例如 docker、youtube、nas"></label>${picker('iconSource','图标源',sources[0]?.id||'',sources.map(x=>[x.id,x.name]))}<button type="button" class="button primary" data-icon-search>搜索</button></div><p class="icon-search-status" role="status"></p><div class="icon-results"></div></div></div>`;
}
function iconFieldMarkup(value='',source=''){
 const original=isLocalIcon(value)&&safeIconURL(source)?source:'';
 return `<div class="field wide"><label for="site-icon-url">图标 URL / 本地缓存地址</label><div class="icon-input-row"><input id="site-icon-url" name="icon" type="text" value="${esc(value)}" autocomplete="off" placeholder="留空使用默认图标"><button type="button" class="button" data-icon-library aria-controls="site-icon-library" aria-expanded="false">${icon('services')}图标库</button></div><input type="hidden" name="iconSourceUrl" value="${esc(original)}"><div class="icon-cache-tools"><button type="button" class="button" data-icon-cache>缓存当前外链</button><button type="button" class="button" data-icon-rebuild ${original?'':'hidden'}>重新生成高清缓存</button></div><div class="icon-quality-preview"><img data-icon-preview alt="图标预览" hidden><p class="icon-cache-status split-note" role="status">从图标库选择后自动缓存为高清 PNG 并填写地址</p></div></div>`;
}
function iconSourcesPage(){
 const sources=iconLibrarySources();
 return panel('图标源','支持 Iconify、selfh.st 与自定义 JSON 图标目录',sources.map(source=>`<article class="source-item"><div><strong>${esc(source.name)}</strong><small>${esc(iconSourceNames[source.kind]||source.kind)} · ${esc(source.url)}</small></div><div class="actions">${ibtn('编辑图标源','icon-source-edit:'+source.id,'edit')}${btn(source.disabled?'启用':'停用','icon-source-toggle:'+source.id)}${ibtn('删除图标源','icon-source-delete:'+source.id,'trash')}</div></article>`).join('')||empty('没有图标源','添加图标源后，可在编辑站点时搜索并选择。'),`<div class="actions">${!sources.some(s=>s.kind==='selfhst')?btn('添加 selfh.st 默认源','icon-source-default'):''}${btn('添加图标源','icon-source-add','plus')}</div>`)+
 panel('自定义 JSON 格式','源需启用 CORS，并通过 HTTPS 返回 JSON；最多读取 2 MiB',`<div class="panel-body"><pre class="code">${esc(JSON.stringify({icons:[{name:'我的服务',url:'https://icons.example.com/service.svg',keywords:['nas','存储']}]},null,2))}</pre><p class="split-note">支持相对于 JSON 地址的图片路径。只作为图片引用，不执行 SVG 脚本。选中的图标转换为 PNG 存入 /data/icons/；升级或重建容器保留数据卷即可保留图标，停用或删除图标源不影响显示。手填外链需单独点击保存到本地。</p></div>`);
}
async function iconSourceAction(key){
 if(!key.startsWith('icon-source-'))return false;
 const [action,id]=key.split(':'),sources=structuredClone(iconLibrarySources()),old=sources.find(x=>x.id===id);
 const save=async list=>{const c=structuredClone(state.config);c.panel={...c.panel,iconSources:list};await saveConfig(c);};
 if(action==='icon-source-default'){if(!sources.some(s=>s.kind==='selfhst'))await save([...sources,{...defaultIconSources[1],id:uid()}]);return true;}
 if(action==='icon-source-add'||action==='icon-source-edit'){
  dialog(old?'编辑图标源':'添加图标源',`<div class="form-grid">${field('name','名称',old?.name)}${picker('kind','类型',old?.kind||'iconify',[['iconify','Iconify 兼容 API'],['selfhst','selfh.st 官方目录格式'],['json','JSON 图标目录']])}${field('url','HTTPS 地址',old?.url||'','Iconify 填 API 根地址；selfh.st 填 index.json 地址；JSON 填完整文件地址。不在 URL 中放账号或令牌。','url',true)}</div>`,async d=>{const item={id:old?.id||uid(),name:d.name.trim(),kind:d.kind,url:d.url.trim().replace(/\/+$/,''),disabled:old?.disabled||false};const n=sources.findIndex(x=>x.id===item.id);if(n<0)sources.push(item);else sources[n]=item;await save(sources);});return true;
 }
 if(!old)throw Error('图标源已不存在，请刷新');
 if(action==='icon-source-toggle'){old.disabled=!old.disabled;await save(sources);return true;}
 if(action==='icon-source-delete'){dialog('删除图标源',notice('仅删除图标源配置，不会清除已经选用的站点图标。'),async()=>save(sources.filter(x=>x.id!==id)),'删除');return true;}
 return false;
}
let iconSearchController;
async function searchIconLibrary(button){
 const container=button.closest('.icon-library'),query=container.querySelector('[data-icon-query]').value.trim(),status=container.querySelector('.icon-search-status'),results=container.querySelector('.icon-results');
 const source=iconLibrarySources().find(s=>s.id===container.querySelector('[name=iconSource]').value&&!s.disabled);
 if(!source){status.textContent='请先启用一个图标源';return;}if(source.kind==='iconify'&&!query){status.textContent='请输入搜索关键词';return;}
 iconSearchController?.abort();const controller=new AbortController();iconSearchController=controller;
 const timer=setTimeout(()=>controller.abort(),15000);button.disabled=true;status.textContent='正在搜索…';results.replaceChildren();
 try{
  const url=new URL(source.kind==='iconify'?source.url.replace(/\/+$/,'')+'/search':source.url);
  if(source.kind==='iconify'){url.searchParams.set('query',query);url.searchParams.set('limit','64');}
  const response=await fetch(url.href,{signal:controller.signal,credentials:'omit',referrerPolicy:'no-referrer',headers:{Accept:'application/json'}});
  if(!response.ok)throw Error('图标源返回 HTTP '+response.status);
  const reader=response.body.getReader(),chunks=[];let size=0;
  while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>2*1024*1024){await reader.cancel();throw Error('图标目录超过 2 MiB');}chunks.push(value);}
  const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
  const list=iconSearchResults(JSON.parse(new TextDecoder().decode(bytes)),source,query);
  if(!container.isConnected)return;
  results.innerHTML=list.map(item=>`<button type="button" class="icon-result" data-icon-url="${esc(item.url)}" title="${esc(item.name)}"><img src="${esc(item.url)}" alt="" loading="lazy" referrerpolicy="no-referrer"><span>${esc(item.name)}</span></button>`).join('');
  status.textContent=list.length?'找到 '+list.length+' 个图标，点击后自动保存到本地':'没有匹配图标，请换个关键词';
 }catch(error){if(container.isConnected)status.textContent=error.name==='AbortError'?'图标源请求超时或已取消':error instanceof SyntaxError?'图标源返回的不是有效 JSON':error.message==='Failed to fetch'?'连接失败，请检查网络、HTTPS 证书或图标源的 CORS 设置':error.message;}
 finally{clearTimeout(timer);button.disabled=false;}
}
function iconRasterSize(width,height,vector=false){
 if(!Number.isFinite(width)||!Number.isFinite(height)||width<=0||height<=0)throw Error('图标尺寸无效');
 const scale=vector?256/Math.max(width,height):Math.min(1,256/width,256/height);
 return {width:Math.max(1,Math.round(width*scale)),height:Math.max(1,Math.round(height*scale))};
}
// Parse detached XML only. Never put source SVG in the page DOM or upload it.
// Give SVG an explicit pixel viewport BEFORE image decoding (1em often becomes
// only 16px). Canvas then renders the vector at 256px, not a stretched 16px PNG.
function highResolutionSVG(text){
 if(/<!DOCTYPE|<!ENTITY/i.test(text))throw Error('SVG 不支持 DTD 或实体声明，请选择其他图标');
 const doc=new DOMParser().parseFromString(text,'image/svg+xml'),svg=doc.documentElement;
 if(doc.querySelector('parsererror')||svg.localName!=='svg'||svg.namespaceURI!=='http://www.w3.org/2000/svg')throw Error('SVG 图标格式无效');
 let box=(svg.getAttribute('viewBox')||'').trim().split(/[\s,]+/).map(Number);
 if(box.length!==4||!box.every(Number.isFinite)||box[2]<=0||box[3]<=0){
  const pixels=value=>/^\d+(?:\.\d+)?(?:px)?$/.test(value||'')?parseFloat(value):0;
  const w=pixels(svg.getAttribute('width')),h=pixels(svg.getAttribute('height'));
  if(!w||!h)throw Error('SVG 缺少有效 viewBox 或像素宽高，请选择其他图标');
  box=[0,0,w,h];svg.setAttribute('viewBox',box.join(' '));
 }
 const size=iconRasterSize(box[2],box[3],true);
 svg.setAttribute('width',String(size.width));svg.setAttribute('height',String(size.height));
 for(const [key,value] of Object.entries({width:size.width+'px',height:size.height+'px','max-width':'none','max-height':'none','min-width':'0','min-height':'0'}))svg.style.setProperty(key,value,'important');
 doc.querySelectorAll('script,foreignObject,iframe,object,embed').forEach(node=>node.remove());
 return {blob:new Blob([new XMLSerializer().serializeToString(svg)],{type:'image/svg+xml'}),...size};
}
function updateIconPreview(form){
 const input=form.querySelector('[name=icon]'),original=form.querySelector('[name=iconSourceUrl]'),img=form.querySelector('[data-icon-preview]'),status=form.querySelector('.icon-cache-status'),rebuild=form.querySelector('[data-icon-rebuild]');
 if(!img||!input)return;
 const path=input.value.trim();rebuild.hidden=!(isLocalIcon(path)&&safeIconURL(original.value));
 if(!isLocalIcon(path)){img.hidden=true;img.removeAttribute('src');status.textContent='从图标库选择后自动生成高清缓存；小尺寸 PNG 不会通过放大伪造清晰度';return;}
 img.onload=()=>{if(input.value.trim()!==path)return;img.hidden=false;const low=Math.max(img.naturalWidth,img.naturalHeight)<128;status.textContent=`本机缓存 ${img.naturalWidth} × ${img.naturalHeight} 像素。`+(low?(original.value?'清晰度偏低，可重新获取原图或改选 SVG 图标。':'旧缓存没有原图来源，请从图标库重新选择。'):'保存站点后生效；后续显示不依赖图标源。');};
 img.onerror=()=>{if(input.value.trim()===path){img.hidden=true;status.textContent='本地图标读取失败，请从图标库重新选择。';}};
 img.src=path;
}
// Fetch in the browser, without source credentials; the server accepts only PNG.
async function cacheSelectedIcon(url){
 if(isLocalIcon(url))return url;
 if(!safeIconURL(url))throw Error('本地缓存需要可跨域读取的 HTTPS 图片地址');
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),20000);
 let objectURL;
 try{
  const response=await fetch(url,{credentials:'omit',referrerPolicy:'no-referrer',signal:controller.signal});
  if(!response.ok)throw Error('读取图标失败：HTTP '+response.status);
  const type=(response.headers.get('content-type')||'').split(';')[0].trim();
  if(!['image/svg+xml','image/png','image/jpeg','image/webp','image/gif','image/x-icon','image/vnd.microsoft.icon'].includes(type))throw Error('图标源没有返回支持的图片类型');
  const reader=response.body.getReader(),chunks=[];let size=0;
  while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>2*1024*1024){await reader.cancel();throw Error('原始图标超过 2 MiB');}chunks.push(value);}
  let blob=new Blob(chunks,{type});
  if(type==='image/svg+xml')blob=highResolutionSVG(await blob.text()).blob;
  objectURL=URL.createObjectURL(blob);
  const img=new Image();
  await new Promise((resolve,reject)=>{const timeout=setTimeout(()=>reject(Error('图标解码超时')),10000);img.onload=()=>{clearTimeout(timeout);resolve();};img.onerror=()=>{clearTimeout(timeout);reject(Error('图标无法解码'));};img.src=objectURL;});
  if(!img.naturalWidth||!img.naturalHeight||img.naturalWidth>4096||img.naturalHeight>4096)throw Error('图标尺寸无效或过大');
  const canvas=document.createElement('canvas'),raster=iconRasterSize(img.naturalWidth,img.naturalHeight);
  canvas.width=raster.width;canvas.height=raster.height;
  canvas.getContext('2d').drawImage(img,0,0,canvas.width,canvas.height);
  const png=await new Promise(resolve=>canvas.toBlob(resolve,'image/png'));if(!png)throw Error('无法转换图标');
  const saved=await fetch('/api/icons/upload',{method:'POST',headers:{'X-LinkNest-Request':'1','Content-Type':'image/png'},credentials:'same-origin',body:png,signal:controller.signal});
  const data=await saved.json();if(!saved.ok)throw Error(data.error||'保存图标失败');return data.url;
 }catch(error){if(error.name==='AbortError')throw Error('缓存图标超时，请重试');if(error.message==='Failed to fetch')throw Error('缓存失败：请检查网络或图标源的 CORS 设置，尚未保存到本地');throw error;}
 finally{clearTimeout(timer);if(objectURL)URL.revokeObjectURL(objectURL);}
}
async function chooseCachedIcon(button,url){
 const form=button.closest('form'),input=form?.querySelector('[name=icon]'),status=form?.querySelector('.icon-cache-status');
 if(!input||form.dataset.iconBusy==='1')return;
 form.dataset.iconBusy='1';const submits=[...form.querySelectorAll('[type=submit]')];submits.forEach(b=>b.disabled=true);button.disabled=true;
 if(status)status.textContent='正在保存图标到本地…';
 try{const path=await cacheSelectedIcon(url);if(!form.isConnected)return;input.value=path;input.dispatchEvent(new Event('input',{bubbles:true}));const original=form.querySelector('[name=iconSourceUrl]');if(original&&safeIconURL(url))original.value=url;if(status)status.textContent='已缓存到持久数据卷，保存站点后生效';updateIconPreview(form);const library=form.querySelector('.icon-library');if(library)library.hidden=true;form.querySelector('[data-icon-library]')?.setAttribute('aria-expanded','false');input.focus({preventScroll:true});input.scrollIntoView({block:'nearest'});toast('图标已保存到本地并填入地址');}
 catch(error){if(status)status.textContent=error.message;toast(error.message);}
 finally{delete form.dataset.iconBusy;submits.forEach(b=>b.disabled=false);button.disabled=false;}
}
document.addEventListener('click',e=>{
 const open=e.target.closest('[data-icon-library]');if(open){const library=open.closest('form').querySelector('.icon-library');library.hidden=!library.hidden;open.setAttribute('aria-expanded',String(!library.hidden));if(!library.hidden)library.querySelector('[data-icon-query]').focus();return;}
 const close=e.target.closest('[data-icon-library-close]');if(close){const form=close.closest('form');close.closest('.icon-library').hidden=true;const trigger=form.querySelector('[data-icon-library]');trigger.setAttribute('aria-expanded','false');trigger.focus();return;}
 const search=e.target.closest('[data-icon-search]');if(search){searchIconLibrary(search);return;}
 const choice=e.target.closest('[data-icon-url]');if(choice){chooseCachedIcon(choice,choice.dataset.iconUrl);return;}
 const rebuild=e.target.closest('[data-icon-rebuild]');if(rebuild){const form=rebuild.closest('form');chooseCachedIcon(rebuild,form.querySelector('[name=iconSourceUrl]').value);return;}
 const cache=e.target.closest('[data-icon-cache]');if(cache){const form=cache.closest('form'),value=form.querySelector('[name=icon]').value.trim();if(isLocalIcon(value)){updateIconPreview(form);toast('这是本机缓存；请重新选择原图，或使用“重新生成高清缓存”');return;}chooseCachedIcon(cache,value);}
});
document.addEventListener('input',e=>{if(e.target.id==='site-icon-url'){const form=e.target.closest('form');form.querySelector('[name=iconSourceUrl]').value='';updateIconPreview(form);}});
document.addEventListener('keydown',e=>{if(e.key==='Enter'&&e.target.matches('[data-icon-query]')){e.preventDefault();searchIconLibrary(e.target.closest('.icon-library').querySelector('[data-icon-search]'));}});
