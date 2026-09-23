'use strict';
const electron=require('electron');
function createElectronChromiumAdapter(){
 const {WebContentsView,session,protocol,net}=electron;
 return Object.freeze({
  name:()=> 'chromium-electron',
  version:()=>String(process.versions.chrome||'unknown'),
  capabilities:()=>({views:true,sessions:true,protocols:true,networkInterception:true,permissions:true,proxy:true,downloads:true,devtoolsProtocol:true,isolatedWorlds:true,certificatePolicy:true}),
  getRuntimeVersions:()=>({chromium:String(process.versions.chrome||''),electron:String(process.versions.electron||''),node:String(process.versions.node||'')}),
  createSession:(partition,options={cache:false})=>session.fromPartition(partition,options),
  createView:(webPreferences)=>new WebContentsView({webPreferences}),
  attachView:(window,view)=>window.contentView.addChildView(view),
  detachView:(window,view)=>{try{window.contentView.removeChildView(view);}catch{}},
  destroyView:(view)=>{try{if(!view.webContents.isDestroyed())view.webContents.close();}catch{}},
  registerProtocol:(targetProtocol,scheme,handler)=>{if(!targetProtocol.isProtocolHandled(scheme))targetProtocol.handle(scheme,handler);},
  protocolForSession:(ses)=>ses?.protocol||protocol,
  fetch:(url,options={})=>net.fetch(url,options)
 });
}
module.exports={createElectronChromiumAdapter};
