'use strict';
const COHORTS=Object.freeze({
 standard:{timezone:null,locale:null,screen:null,cores:null,memory:null,dpr:null,webgl:'native',canvas:'native',audio:'native',timers:'native'},
 strict:{timezone:'UTC',locale:'en-US',screen:[1440,900,1440,860,24],cores:4,memory:8,dpr:1,webgl:'normalized',canvas:'cohort',audio:'cohort',timers:'2ms'},
 maximum:{timezone:'UTC',locale:'en-US',screen:[1440,900,1440,860,24],cores:4,memory:8,dpr:1,webgl:'blocked',canvas:'blank',audio:'cohort',timers:'10ms'}
});
function policyFor({profile='strict',anonymousMode=false,disableWebRtc=false,chromiumMajor='152'}={}){
 const name=anonymousMode?'maximum':(COHORTS[profile]?profile:'strict'),base=COHORTS[name];
 return Object.freeze({...base,name,cohortVersion:'aegis-cohort-v2',uaMajor:String(chromiumMajor).split('.')[0],webrtc:(anonymousMode||disableWebRtc)?'blocked':'proxied-only',localFonts:name==='standard'?'native':'blocked',plugins:name==='standard'?'native':'empty',clientHints:name==='standard'?'native':'normalized',highEntropyApis:name==='standard'?'native':'reduced'});
}
function policyEvidence(p){return {cohortVersion:p.cohortVersion,profile:p.name,timezone:p.timezone,locale:p.locale,screen:p.screen,cores:p.cores,memory:p.memory,dpr:p.dpr,webgl:p.webgl,canvas:p.canvas,audio:p.audio,webrtc:p.webrtc,localFonts:p.localFonts,plugins:p.plugins,clientHints:p.clientHints,timers:p.timers};}
module.exports={COHORTS,policyFor,policyEvidence};
