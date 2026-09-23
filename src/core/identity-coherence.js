'use strict';
function evaluateIdentityCoherence(snapshot={},policy={}){
 const mismatches=[];const eq=(k,a,b)=>{if(b!=null&&a!=null&&String(a)!==String(b))mismatches.push({surface:k,observed:a,expected:b})};
 eq('timezone',snapshot.timezone,policy.timezone);eq('language',snapshot.language,policy.locale);eq('hardwareConcurrency',snapshot.hardwareConcurrency,policy.cores);eq('deviceMemory',snapshot.deviceMemory,policy.memory);eq('devicePixelRatio',snapshot.devicePixelRatio,policy.dpr);
 if(policy.screen&&snapshot.screen){const exp=policy.screen.slice(0,2),obs=[snapshot.screen.width,snapshot.screen.height];if(obs[0]!==exp[0]||obs[1]!==exp[1])mismatches.push({surface:'screen',observed:obs,expected:exp})}
 if(policy.webrtc==='blocked'&&snapshot.webrtc?.available)mismatches.push({surface:'webrtc',observed:'available',expected:'blocked'});
 return {ok:mismatches.length===0,status:mismatches.length?'fail':'pass',mismatches};
}
module.exports={evaluateIdentityCoherence};
