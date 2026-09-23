'use strict';
function createTabStore({maxTabs=200}={}){
 const tabs=new Map();let activeId=null,nextId=1;
 function create(seed={}){if(tabs.size>=maxTabs)throw new Error('Tab limit reached');const id=seed.id??nextId++,tab={id,title:'New Tab',url:'',loading:false,pinned:false,muted:false,crashed:false,createdAt:Date.now(),lastActiveAt:Date.now(),...seed};tabs.set(id,tab);if(activeId==null)activeId=id;return tab}
 function close(id){const existed=tabs.delete(id);if(activeId===id)activeId=tabs.keys().next().value??null;return existed}
 function activate(id){const tab=tabs.get(id);if(!tab)return null;activeId=id;tab.lastActiveAt=Date.now();return tab}
 function update(id,patch={}){const tab=tabs.get(id);if(!tab)return null;Object.assign(tab,patch);return tab}
 return Object.freeze({create,close,activate,update,get:id=>tabs.get(id)||null,active:()=>tabs.get(activeId)||null,list:()=>[...tabs.values()],activeId:()=>activeId,size:()=>tabs.size});
}
module.exports={createTabStore};
