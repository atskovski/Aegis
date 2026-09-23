'use strict';
const electron=require('electron');
function createElectronChromiumAdapter(){
 const {WebContentsView,session,protocol,net}=electron;
 const wc=(view)=>view?.webContents||view;
 return Object.freeze({
  name:()=> 'chromium-electron',
  version:()=>String(process.versions.chrome||'unknown'),
  capabilities:()=>({views:true,sessions:true,protocols:true,networkInterception:true,permissions:true,devicePermissions:true,proxy:true,downloads:true,devtoolsProtocol:true,isolatedWorlds:true,certificatePolicy:true,navigationPolicy:true,rendererLifecycle:true}),
  getRuntimeVersions:()=>({chromium:String(process.versions.chrome||''),electron:String(process.versions.electron||''),node:String(process.versions.node||'')}),
  createSession:(partition,options={cache:false})=>session.fromPartition(partition,options),
  createView:(webPreferences)=>new WebContentsView({webPreferences}),
  attachView:(window,view)=>window.contentView.addChildView(view),
  detachView:(window,view)=>{try{window.contentView.removeChildView(view);}catch{}},
  destroyView:(view)=>{try{const x=wc(view);if(x&&!x.isDestroyed())x.close();}catch{}},
  registerProtocol:(targetProtocol,scheme,handler)=>{if(!targetProtocol.isProtocolHandled(scheme))targetProtocol.handle(scheme,handler);},
  protocolForSession:(ses)=>ses?.protocol||protocol,
  fetch:(url,options={})=>net.fetch(url,options),
  installPermissionHandlers:(ses,{request,check})=>{ses.setPermissionRequestHandler(request);ses.setPermissionCheckHandler(check);return true;},
  installDevicePermissionHandlers:(ses)=>{ses.setDevicePermissionHandler(()=>false);const denyHid=(e,_d,cb)=>{e.preventDefault();cb();},denySerial=(e,_p,_w,cb)=>{e.preventDefault();cb('');},denyUsb=(e,_d,cb)=>{e.preventDefault();cb();};ses.on('select-hid-device',denyHid);ses.on('select-serial-port',denySerial);ses.on('select-usb-device',denyUsb);return ()=>{ses.removeListener('select-hid-device',denyHid);ses.removeListener('select-serial-port',denySerial);ses.removeListener('select-usb-device',denyUsb);};},
  onDownload:(ses,handler)=>{ses.on('will-download',handler);return ()=>ses.removeListener('will-download',handler);},
  isDebuggerAttached:(view)=>Boolean(wc(view)?.debugger?.isAttached()),
  onDebuggerMessage:(view,handler)=>{const d=wc(view)?.debugger;if(!d)return ()=>{};d.on('message',handler);return ()=>d.removeListener('message',handler);},
  attachDebugger:(view,version='1.3')=>{const d=wc(view)?.debugger;if(!d)throw new Error('DevTools protocol unavailable');if(!d.isAttached())d.attach(version);return true;},
  detachDebugger:(view)=>{const d=wc(view)?.debugger;try{if(d?.isAttached())d.detach();}catch{}},
  debuggerCommand:(view,method,params={})=>{const d=wc(view)?.debugger;if(!d?.isAttached())throw new Error('DevTools protocol not attached');return d.sendCommand(method,params);},
  executeJavaScript:(view,source,userGesture=true)=>wc(view).executeJavaScript(source,userGesture),
  executeIsolatedWorld:(view,worldId,scripts,userGesture=false)=>wc(view).executeJavaScriptInIsolatedWorld(worldId,scripts,userGesture),
  insertCSS:(view,css,options={})=>wc(view).insertCSS(css,options),
  setWindowOpenPolicy:(view,handler)=>wc(view).setWindowOpenHandler(handler),
  onCertificateError:(view,handler)=>{const x=wc(view);x.on('certificate-error',handler);return ()=>x.removeListener('certificate-error',handler);},
  isDestroyed:(view)=>Boolean(wc(view)?.isDestroyed()),
  loadURL:(view,url,options)=>wc(view).loadURL(url,options),
  getURL:(view)=>wc(view).getURL(),
  on:(view,event,handler)=>{const x=wc(view);x.on(event,handler);return ()=>x.removeListener(event,handler);},
  reload:(view)=>wc(view).reload(), stop:(view)=>wc(view).stop(), focus:(view)=>wc(view).focus(), setZoomMode:(view,mode)=>{const x=wc(view);if(typeof x.setZoomMode==='function')x.setZoomMode(mode);}, setBounds:(view,bounds)=>view.setBounds(bounds), getBounds:(view)=>view.getBounds(), setVisible:(view,visible)=>view.setVisible(Boolean(visible)),
  navigationHistory:(view)=>wc(view).navigationHistory,
  sessionOf:(view)=>wc(view).session,
  clearSessionData:(ses,options)=>ses.clearData(options), clearSessionCache:(ses)=>ses.clearCache(), closeSessionConnections:(ses)=>ses.closeAllConnections(),
  removeInsertedCSS:(view,key)=>wc(view).removeInsertedCSS(key),
  closeView:(view)=>{const x=wc(view);if(x&&!x.isDestroyed())x.close();}
 });
}
module.exports={createElectronChromiumAdapter};
