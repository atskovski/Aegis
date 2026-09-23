'use strict';
function createSecurityEventLedger(limit=500){
  const items=[]; const max=Math.max(50,Math.min(5000,Number(limit)||500));
  return {
    add(type,severity='info',detail={},tabId=null){
      const e={id:require('node:crypto').randomUUID(),at:new Date().toISOString(),type:String(type||'event'),severity:['info','warning','danger','success'].includes(severity)?severity:'info',tabId:tabId==null?null:Number(tabId),detail:detail&&typeof detail==='object'?detail:{message:String(detail||'')}};
      items.unshift(e); if(items.length>max)items.length=max; return e;
    },
    list(tabId=null){return items.filter(x=>tabId==null||x.tabId===Number(tabId)).map(x=>({...x,detail:{...x.detail}}));},
    clear(){items.length=0;}
  };
}
module.exports={createSecurityEventLedger};
