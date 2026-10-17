// Optional real-browser regression. Uses only static local assets and fake rules.
const assert=require('node:assert/strict'),fs=require('node:fs'),http=require('node:http'),path=require('node:path');
const {chromium}=require('playwright');
(async()=>{
 let upnpDelay=0,upnpFailure=false;
 const root=path.resolve(__dirname,'../web'),server=http.createServer((req,res)=>{
  if(req.url.startsWith('/api/upnp/state')){setTimeout(()=>{res.setHeader('Content-Type','application/json');if(upnpFailure){res.statusCode=503;res.end(JSON.stringify({error:'QA refresh failed'}));return;}res.end(JSON.stringify({config:{enabled:true,writePolicy:'service',descriptionUrl:'http://192.168.1.1:5351/rootDesc.xml',interface:'br-lan',lanZone:'lan',blacklist:[{id:'qa',name:'Blocked device',address:'192.168.1.20/32',enabled:true}]},mappings:[{description:'Sample device',protocol:'TCP',externalPort:6881,internalIP:'192.168.1.2',internalPort:6881,enabled:true,leaseSeconds:3600}],policyPending:true}));},upnpDelay);return;}
  if(req.url.startsWith('/api/state')){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({version:'test',interfaces:[{name:'br-lan'}],config:{rules:[],sshHosts:[]}}));return;}
  if(req.url.startsWith('/api/')){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({initialized:true,authenticated:false}));return;}
  const file=path.resolve(root,'.'+decodeURIComponent(req.url.split('?')[0]==='/'?'/index.html':req.url.split('?')[0]));
  if(!file.startsWith(root+path.sep)){res.writeHead(403).end();return;}
  try{res.setHeader('Content-Type',file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':file.endsWith('.svg')?'image/svg+xml':'text/html');res.end(fs.readFileSync(file));}catch{res.writeHead(404).end();}
 });
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 let browser;
 try{
  browser=await chromium.launch({headless:true,...(process.env.EDGE_PATH?{executablePath:process.env.EDGE_PATH}:{})});
  for(const viewport of [{width:1440,height:900},{width:900,height:800},{width:390,height:844}]){
   const page=await browser.newPage({viewport});const errors=[];page.on('pageerror',e=>errors.push(e.message));
   await page.goto(`http://127.0.0.1:${server.address().port}/`);await page.locator('#auth-form').waitFor();
   for(const backend of ['proxy','bookmarks','wol']){
    await page.evaluate(backend=>{state={config:{rules:[{id:'qa',routes:[{id:'sub',name:'Test',backend,enabled:true,target:'http://127.0.0.1:18890',domains:['example.test']}]}]}};editRoute('qa','sub');},backend);
    const result=await page.evaluate(()=>{
     const hidden=[...document.querySelectorAll('#modal .conditional[hidden]')];
     const row=document.querySelector('[name=enabled]').closest('.switch-row'),last=document.querySelector('[name=skipTlsVerify]').closest('.switch-row');
     const box=document.querySelector('#modal').getBoundingClientRect(),body=document.querySelector('.modal-content');
     return {hidden:hidden.map(x=>x.getBoundingClientRect().height),gap:row.getBoundingClientRect().top-last.getBoundingClientRect().bottom,overflow:body.scrollWidth-body.clientWidth,left:box.left,right:box.right};
    });
    assert.ok(result.hidden.length);assert.ok(result.hidden.every(h=>h===0));assert.ok(result.left>=0&&result.right<=viewport.width);
    assert.ok(result.overflow<=1,JSON.stringify(result));if(backend==='proxy')assert.ok(result.gap>=0&&result.gap<=12,JSON.stringify(result));
    await page.evaluate(()=>closeModal());await page.waitForFunction(()=>!document.querySelector('#dialog-form'));
   }
   await page.evaluate(()=>{noticeAction('notice-mute:'+encodeURIComponent('停止该监听会断开相关业务连接。'));state={config:{rules:[{id:'qa',enabled:true}]}};action('toggle:qa');});
   await page.locator('.action-note').waitFor();assert.equal(await page.locator('#modal .notice-actions').count(),0);assert.match(await page.locator('.action-note').innerText(),/断开/);
   await page.evaluate(()=>closeModal());await page.waitForFunction(()=>!document.querySelector('#dialog-form'));
   await page.evaluate(()=>{loggedIn=true;state={version:'test',interfaces:[{name:'br-lan'}],config:{rules:[],sshHosts:[]}};location.hash='#/forwards/upnp';page='forwards';render();});
   await page.locator('.upnp-mapping').first().waitFor();
   assert.equal(await page.locator('#upnp-ports').count(),0);
   const stackGaps=await page.locator('#upnp-status').evaluate(el=>[...el.children].slice(1).map((child,i)=>child.getBoundingClientRect().top-el.children[i].getBoundingClientRect().bottom));
   assert.ok(stackGaps.every(g=>g>=15),JSON.stringify(stackGaps));
   if(process.env.LINKNEST_QA_OUTPUT)await page.screenshot({path:path.join(process.env.LINKNEST_QA_OUTPUT,`upnp-${viewport.width}.png`),fullPage:true});assert.equal(await page.locator('[data-action="add:forwards"]').count(),0);
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
   upnpDelay=300;
   await page.evaluate(()=>{window.qaMappings=document.querySelector('#upnp-mappings');window.qaMapRow=qaMappings.firstElementChild;window.qaHeight=document.querySelector('.upnp-page').getBoundingClientRect().height;window.qaLoadingSeen=false;window.qaObserver=new MutationObserver(()=>{if(document.querySelector('.upnp-page')?.textContent.includes('正在读取'))window.qaLoadingSeen=true;});qaObserver.observe(document.querySelector('#page-content'),{subtree:true,childList:true,characterData:true});});
   await page.evaluate(()=>refresh());
   await page.evaluate(()=>{window.qaRefresh=refresh(true);});
   await page.waitForFunction(()=>upnpRefreshing);
   assert.equal(await page.evaluate(()=>qaMappings===document.querySelector('#upnp-mappings')&&qaMapRow===qaMappings.firstElementChild&&qaHeight===document.querySelector('.upnp-page').getBoundingClientRect().height),true);
   await page.evaluate(()=>qaRefresh);
   assert.equal(await page.evaluate(()=>!qaLoadingSeen&&qaMapRow===document.querySelector('#upnp-mappings').firstElementChild),true);
   upnpFailure=true;await page.evaluate(()=>refreshUPnP());
   assert.equal(await page.evaluate(()=>qaMapRow===document.querySelector('#upnp-mappings').firstElementChild),true);
   assert.match(await page.locator('#upnp-status').innerText(),/上次读取结果/);
   upnpFailure=false;upnpDelay=0;await page.evaluate(()=>refreshUPnP());
   await page.evaluate(()=>{render();});
   assert.doesNotMatch(await page.locator('.upnp-page').innerText(),/正在读取/);
   await page.waitForFunction(()=>!upnpRefreshing);await page.evaluate(()=>qaObserver.disconnect());
   await page.locator('[data-action="upnp-edit:0"]').click();await page.locator('#dialog-form [name=externalPort]').waitFor();
   assert.ok(await page.evaluate(()=>{const e=document.querySelector('#modal');return e.getBoundingClientRect().right<=innerWidth&&e.scrollWidth<=e.clientWidth;}));
   await page.evaluate(()=>closeModal());await page.waitForFunction(()=>!document.querySelector('#dialog-form'));
   await page.evaluate(()=>{state.upnpPorts={managementEnabled:true,enabled:true,pending:true,forwardPorts:[3389,6881],protectedPorts:[3389]};state.config.rules=[];state.config.sshHosts=[{id:'router',name:'Router',username:'root',address:'192.168.1.1:22',fingerprint:'verified'}];resetUPnPState();location.hash='#/forwards/rules';render();});
   await page.locator('#upnp-ports').waitFor();
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
   assert.equal(await page.locator('#upnp-ports .notice-actions').count(),0);
   const portGaps=await page.locator('#upnp-ports').evaluate(el=>[...el.children].slice(1).map((child,i)=>child.getBoundingClientRect().top-el.children[i].getBoundingClientRect().bottom));
   assert.ok(portGaps.every(g=>g>=15),JSON.stringify(portGaps));
   if(process.env.LINKNEST_QA_OUTPUT)await page.screenshot({path:path.join(process.env.LINKNEST_QA_OUTPUT,`ports-${viewport.width}.png`),fullPage:true});
   await page.locator('[data-action="upnp-ports-sync"]').click();await page.locator('#dialog-form [name=adminPassword]').waitFor();
   assert.match(await page.locator('#modal').innerText(),/3389、6881/);
   assert.deepEqual(errors,[]);await page.close();
  }
  console.log('Desktop/mobile dialog conditional spacing, bounds and non-dismissible operation notes passed.');
 }finally{await browser?.close();await new Promise(r=>server.close(r));}
})().catch(e=>{console.error(e);process.exitCode=1;});
