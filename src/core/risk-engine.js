'use strict';
const WEIGHTS=Object.freeze({fingerprint:18,'private-network':35,phishing:35,malware:45,tracker:5,'third-party':2,permission:10,download:12,'tls-error':35,'managed-policy':40,extension:15});
function createRiskEngine({halfLifeMs=120000,limit=300}={}){
 const events=[];
 function add(kind,{severity=1,tabId=null,host='',blocked=false,detail={}}={}){if(!WEIGHTS[kind])return null;const e={at:Date.now(),kind,severity:Math.max(.25,Math.min(3,Number(severity)||1)),tabId,host:String(host||''),blocked:Boolean(blocked),detail};events.push(e);if(events.length>limit)events.splice(0,events.length-limit);return e}
 function score({tabId=null,host='',now=Date.now()}={}){let raw=0;const contributing=[];for(const e of events){if(tabId!=null&&e.tabId!=null&&e.tabId!==tabId)continue;if(host&&e.host&&e.host!==host)continue;const age=Math.max(0,now-e.at),decay=Math.pow(.5,age/halfLifeMs),points=WEIGHTS[e.kind]*e.severity*decay*(e.blocked?.35:1);if(points>=.5){raw+=points;contributing.push({kind:e.kind,points:Math.round(points),blocked:e.blocked})}}const value=Math.max(0,Math.min(100,Math.round(raw)));return {score:value,level:value>=70?'critical':value>=45?'high':value>=20?'elevated':'low',contributing:contributing.sort((a,b)=>b.points-a.points).slice(0,8)}}
 return Object.freeze({add,score,clear(){events.length=0}});
}
module.exports={WEIGHTS,createRiskEngine};
