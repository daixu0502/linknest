'use strict';
let navY=0;
function openNav(){
 if(!matchMedia('(max-width:900px)').matches)return;
 navY=scrollY;document.body.classList.add('nav-open');document.body.style.position='fixed';document.body.style.top=`-${navY}px`;document.body.style.width='100%';
 $('.nav-toggle')?.setAttribute('aria-expanded','true');$('.main').inert=true;
 $('#main-sidebar')?.setAttribute('role','dialog');$('#main-sidebar')?.setAttribute('aria-modal','true');
 $('.drawer-close')?.focus();
}
function closeNav(focus=true){
 if(!document.body.classList.contains('nav-open'))return;
 document.body.classList.remove('nav-open');document.body.style.position='';document.body.style.top='';document.body.style.width='';window.scrollTo(0,navY);
 if($('.main'))$('.main').inert=false;
 $('#main-sidebar')?.removeAttribute('role');$('#main-sidebar')?.removeAttribute('aria-modal');$('.nav-toggle')?.setAttribute('aria-expanded','false');
 if(focus)$('.nav-toggle')?.focus();
}
document.addEventListener('keydown',e=>{
 if(!document.body.classList.contains('nav-open'))return;
 if(e.key==='Escape'){e.preventDefault();closeNav();}
 if(e.key==='Tab'){const els=$$('button:not([disabled]),a[href]',$('#main-sidebar')).filter(x=>x.getClientRects().length);const first=els[0],last=els[els.length-1];if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}}
});
matchMedia('(max-width:900px)').addEventListener('change',()=>closeNav(false));
