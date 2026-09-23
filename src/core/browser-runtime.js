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
  downloads:(ses,handler)=>engine.onDownload(ses,handler),
  attachInspector:(view,version)=>engine.attachDebugger(view,version),
  detachInspector:(view)=>engine.detachDebugger(view),
  command:(view,method,params)=>engine.debuggerCommand(view,method,params),
  evaluate:(view,source,userGesture)=>engine.executeJavaScript(view,source,userGesture),
  evaluateIsolated:(view,worldId,scripts,userGesture)=>engine.executeIsolatedWorld(view,worldId,scripts,userGesture),
  css:(view,source,options)=>engine.insertCSS(view,source,options),
  windows:(view,handler)=>engine.setWindowOpenPolicy(view,handler),
  certificates:(view,handler)=>engine.onCertificateError(view,handler)
 });
}
module.exports={createBrowserRuntime};
