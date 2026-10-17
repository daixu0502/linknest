// Optional real-browser regression. Uses only static local assets and fake rules.
const assert=require('node:assert/strict'),fs=require('node:fs'),http=require('node:http'),path=require('node:path');
const {chromium}=require('playwright');
(async()=>{
 const root=path.resolve(__dirname,'../web'),server=http.createServer((req,res)=>{
  if(req.url.startsWith('/api/upnp/state')){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({config:{enabled:true,writePolicy:'service',descriptionUrl:'http://192.168.1.1:5351/rootDesc.xml',interface:'br-lan',lanZone:'lan',blacklist:[{id:'qa',name:'Blocked device',address:'192.168.1.20/32',enabled:true}]},mappings:[{description:'Sample device',protocol:'TCP',externalPort:6881,internalIP:'192.168.1.2',internalPort:6881,enabled:true,leaseSeconds:3600}],policyPending:true}));return;}
  if(req.url.startsWith('/api/')){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({initialized:true,authenticated:false}));return;}
  const file=path.resolve(root,'.'+decodeURIComponent(req.url.split('?')[0]==='/'?'/index.html':req.url.split('?')[0]));
  if(!file.startsWith(root+path.sep)){res.writeHead(403).end();return;}
  try{res.setHeader('Content-Type',file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':file.endsWith('.svg')?'image/svg+xml':'text/html');res.end(fs.readFileSync(file));}catch{res.writeHead(404).end();}
 });
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 let browser;
 try{
  browser=await chromium.launch({headless:true,...(process.env.EDGE_PATH?{executablePath:process.env.EDGE_PATH}:{})});
  for(const viewport of [{width:1440,height:900},{width:390,height:844}]){
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
   await page.locator('.upnp-mapping').first().waitFor();assert.equal(await page.locator('[data-action="add:forwards"]').count(),0);
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
   await page.locator('[data-action="upnp-edit:0"]').click();await page.locator('#dialog-form [name=externalPort]').waitFor();
   assert.ok(await page.evaluate(()=>{const e=document.querySelector('#modal');return e.getBoundingClientRect().right<=innerWidth&&e.scrollWidth<=e.clientWidth;}));
   assert.deepEqual(errors,[]);await page.close();
  }
  console.log('Desktop/mobile dialog conditional spacing, bounds and non-dismissible operation notes passed.');
 }finally{await browser?.close();await new Promise(r=>server.close(r));}
})().catch(e=>{console.error(e);process.exitCode=1;});
