'use strict';
const ENGINE_CAPABILITIES=Object.freeze([
 'views','sessions','protocols','networkInterception','permissions','devicePermissions','proxy','downloads',
 'devtoolsProtocol','isolatedWorlds','certificatePolicy','navigationPolicy','rendererLifecycle'
]);
const REQUIRED=Object.freeze([
 'name','version','capabilities','createSession','createView','attachView','detachView','destroyView',
 'registerProtocol','fetch','getRuntimeVersions','installPermissionHandlers','onDownload',
 'attachDebugger','detachDebugger','debuggerCommand','executeJavaScript','executeIsolatedWorld',
 'insertCSS','setWindowOpenPolicy','onCertificateError','isDestroyed','loadURL','getURL','on','reload','stop','focus','navigationHistory','sessionOf','clearSessionData','clearSessionCache','closeSessionConnections','removeInsertedCSS','closeView','installDevicePermissionHandlers','isDebuggerAttached','onDebuggerMessage','setZoomMode','setBounds','getBounds','setVisible'
]);
function assertEngineAdapter(engine){
 if(!engine||typeof engine!=='object')throw new TypeError('Browser engine adapter is required.');
 for(const name of REQUIRED)if(typeof engine[name]!=='function')throw new TypeError('Engine adapter missing '+name+'().');
 const caps=engine.capabilities();for(const k of ENGINE_CAPABILITIES)if(typeof caps[k]!=='boolean')throw new TypeError('Engine capability '+k+' must be boolean.');
 return engine;
}
function engineEvidence(engine){assertEngineAdapter(engine);return {name:engine.name(),version:engine.version(),capabilities:{...engine.capabilities()},runtime:{...engine.getRuntimeVersions()}};}
module.exports={ENGINE_CAPABILITIES,REQUIRED,assertEngineAdapter,engineEvidence};
