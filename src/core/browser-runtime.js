'use strict';
const {assertEngineAdapter,engineEvidence}=require('./engine-contract');
function createBrowserRuntime(engine){
 assertEngineAdapter(engine);
 return Object.freeze({
  evidence:()=>engineEvidence(engine),
  session:(partition,options)=>engine.createSession(partition,options),
  view:(prefs)=>engine.createView(prefs),
  mount:(window,view)=>engine.attachView(window,view),
  unmount:(window,view)=>engine.detachView(window,view),
  destroy:(view)=>engine.destroyView(view),
  protocol:(target,scheme,handler)=>engine.registerProtocol(target,scheme,handler),
  fetch:(url,options)=>engine.fetch(url,options),
  permissions:(ses,handlers)=>engine.installPermissionHandlers(ses,handlers),
  devicePermissions:(ses)=>engine.installDevicePermissionHandlers(ses),
  downloads:(ses,handler)=>engine.onDownload(ses,handler),
  inspectorAttached:(view)=>engine.isDebuggerAttached(view), onInspectorMessage:(view,handler)=>engine.onDebuggerMessage(view,handler), attachInspector:(view,version)=>engine.attachDebugger(view,version),
  detachInspector:(view)=>engine.detachDebugger(view),
  command:(view,method,params)=>engine.debuggerCommand(view,method,params),
  evaluate:(view,source,userGesture)=>engine.executeJavaScript(view,source,userGesture),
  evaluateIsolated:(view,worldId,scripts,userGesture)=>engine.executeIsolatedWorld(view,worldId,scripts,userGesture),
  css:(view,source,options)=>engine.insertCSS(view,source,options),
  windows:(view,handler)=>engine.setWindowOpenPolicy(view,handler),
  certificates:(view,handler)=>engine.onCertificateError(view,handler),
  destroyed:(view)=>engine.isDestroyed(view), load:(view,url,options)=>engine.loadURL(view,url,options), url:(view)=>engine.getURL(view), on:(view,event,handler)=>engine.on(view,event,handler),
  reload:(view)=>engine.reload(view), stop:(view)=>engine.stop(view), focus:(view)=>engine.focus(view), zoomMode:(view,mode)=>engine.setZoomMode(view,mode), bounds:(view,bounds)=>engine.setBounds(view,bounds), getBounds:(view)=>engine.getBounds(view), visible:(view,value)=>engine.setVisible(view,value), history:(view)=>engine.navigationHistory(view), sessionOf:(view)=>engine.sessionOf(view),
  clearData:(ses,options)=>engine.clearSessionData(ses,options), clearCache:(ses)=>engine.clearSessionCache(ses), closeConnections:(ses)=>engine.closeSessionConnections(ses),
  removeCSS:(view,key)=>engine.removeInsertedCSS(view,key), close:(view)=>engine.closeView(view)
 });
}
module.exports={createBrowserRuntime};
