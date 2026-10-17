'use strict';
// Only these two keys belong to the help controls; never clear other UI preferences.
const noticeSessionKey='linknest-help-session-v1', noticePermanentKey='linknest-help-hidden-v1';
function readNoticeSet(storageName,key){try{const v=JSON.parse(window[storageName].getItem(key)||'[]');return new Set(Array.isArray(v)?v.filter(x=>typeof x==='string'):[]);}catch{return new Set();}}
let hiddenNotices=readNoticeSet('sessionStorage',noticeSessionKey), mutedNotices=readNoticeSet('localStorage',noticePermanentKey);
// Operation details must survive help dismissal, including previously muted text.
function actionNote(text,warning=false){return `<div class="action-note${warning?' warning':''}" role="${warning?'alert':'note'}">${icon('info')}<span>${esc(text)}</span></div>`;}
function notice(text,warning=false,id=''){
 if(warning)return `<div class="notice warning" role="alert">${icon('info')}<span>${esc(text)}</span></div>`;
 const key=id||text;
 if(hiddenNotices.has(key)||mutedNotices.has(key))return '';
 const action=esc(encodeURIComponent(key));
 return `<div class="notice dismissible-notice">${icon('info')}<span class="notice-text">${esc(text)}</span><div class="notice-actions"><button type="button" data-action="notice-hide:${action}" title="本次浏览器会话隐藏">隐藏</button><button type="button" data-action="notice-mute:${action}" title="此浏览器不再显示，可在设置中恢复">不再提示</button></div></div>`;
}
function noticeAction(action,button){
 if(action==='notice-restore'){
  hiddenNotices.clear();mutedNotices.clear();let saved=true;
  for(const [storage,key] of [['sessionStorage',noticeSessionKey],['localStorage',noticePermanentKey]])try{window[storage].removeItem(key);}catch{saved=false;}
  render();toast(saved?'已恢复此浏览器的说明提示':'已恢复当前页面提示；浏览器存储不可用');return true;
 }
 const persistent=action.startsWith('notice-mute:');
 if(!persistent&&!action.startsWith('notice-hide:'))return false;
 let key;try{key=decodeURIComponent(action.slice(action.indexOf(':')+1));}catch{return true;}
 const set=persistent?mutedNotices:hiddenNotices;set.add(key);
 try{window[persistent?'localStorage':'sessionStorage'].setItem(persistent?noticePermanentKey:noticeSessionKey,JSON.stringify([...set]));}catch{toast('浏览器存储不可用，仅本次页面生效');}
 const box=button?.closest('.dismissible-notice'), parent=box?.parentElement;box?.remove();
 if(parent?.classList.contains('notice-only')&&!parent.children.length)parent.remove();
 return true;
}
