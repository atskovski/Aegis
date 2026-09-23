'use strict';
function createNavigationController({runtime,kernel,normalize=(u)=>u,clean=(u)=>u,allowed=()=>true}){
 if(!runtime||!kernel)throw new TypeError('runtime and kernel are required');
 async function navigate(tab,input,{replace=false}={}){const original=normalize(input),url=clean(original,tab);if(!url||!allowed(url))return {ok:false,reason:'invalid-navigation'};const verdict=kernel.navigate({url,tab});if(!verdict.allow)return {ok:false,reason:verdict.reason,verdict};await runtime.load(tab.view,url,replace?{replaceEntry:true}:undefined);return {ok:true,url,cleaned:url!==original,verdict}}
 function back(tab){const h=runtime.history(tab.view);return h?.canGoBack?.()?(h.goBack(),true):false}
 function forward(tab){const h=runtime.history(tab.view);return h?.canGoForward?.()?(h.goForward(),true):false}
 function reload(tab){runtime.reload(tab.view);return true}
 function stop(tab){runtime.stop(tab.view);return true}
 return Object.freeze({navigate,back,forward,reload,stop});
}
module.exports={createNavigationController};
