'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
function source(file){let mode=null;return fs.readFileSync(path.join(__dirname,'../../internal/dashboard',file),'utf8').split('\n').filter(line=>{const start=line.match(/^\s*(?:<!--|\/\/|\/\*)MODE:(cluster|standalone)(?:-->|\*\/)?\s*$/);if(start){mode=start[1];return false;}if(/^\s*(?:<!--|\/\/|\/\*)MODE:end(?:-->|\*\/)?\s*$/.test(line)){mode=null;return false;}return mode!=='cluster';}).join('\n');}
function fn(file,name){const s=source(file);let start=s.indexOf('function '+name+'(');assert(start>=0,name);if(s.slice(start-6,start)==='async ')start-=6;const end=s.indexOf('\n}',start);assert(end>start,name);return s.slice(start,end+2);}
const flush=()=>new Promise(resolve=>setImmediate(resolve));
test('Safety Net refresh replaces clean drafts, preserves edits, and resets after save',async()=>{
 let policy={default_monthly_usd:100,default_monthly_tokens:1000,enforced:true,allowed_over_limit_models:['A']};
 const elements={'safety-net-meta':{textContent:''},'safety-limit':{value:'',disabled:false},'safety-token-limit':{value:'',disabled:false},'safety-enforced':{checked:true,disabled:false}};
 elements['safety-net-body']={querySelectorAll:()=>[],set innerHTML(html){this.html=html;for(const [id,node]of Object.entries(elements)){if(!('value'in node))continue;const match=html.match(new RegExp('id="'+id+'"[^>]*value="([^"]*)"'));if(match)node.value=match[1];}},get innerHTML(){return this.html;}};
 const ctx=vm.createContext({document:{getElementById:id=>elements[id]},fetchJSON:async url=>url.endsWith('/models')?[]:structuredClone(policy),esc:String,fmtTokens:String});
 vm.runInContext('var safetyNetPolicy=null,safetyNetModels=[],safetyNetDraft=null,safetyNetModelLabels={},safetyNetGeneration=0,safetyNetDraftFresh=false,safetyNetDraftDirty=false,safetyNetSaving=false,safetyNetSaveReleasePending=false,safetyNetSaveReleaseGeneration=0,safetyNetResetPending=false;'+fn('admin.html','loadSafetyNet')+'\n'+fn('admin.html','renderSafetyNet'),ctx);
 async function load(reset=false){vm.runInContext('loadSafetyNet('+reset+')',ctx);await flush();await flush();}
 await load();assert.equal(elements['safety-limit'].value,'100');
 policy.default_monthly_usd=200;policy.allowed_over_limit_models=['B'];await load();
 assert.equal(elements['safety-limit'].value,'200');assert.deepEqual(Array.from(ctx.safetyNetDraft.allowed_over_limit_models),['B']);
 elements['safety-limit'].value='300';elements['safety-net-body'].oninput();
 policy.default_monthly_usd=400;policy.allowed_over_limit_models=['C'];await load();
 assert.equal(elements['safety-limit'].value,'300');assert.deepEqual(Array.from(ctx.safetyNetDraft.allowed_over_limit_models),['B']);
 await load(true);assert.equal(elements['safety-limit'].value,'400');assert.deepEqual(Array.from(ctx.safetyNetDraft.allowed_over_limit_models),['C']);
});
test('standalone requests time out through body decoding and allow another request',async()=>{
 let delay,bodySignal;
 const ctx=vm.createContext({AbortController,setTimeout:(f,ms)=>{delay=ms;return setTimeout(f,1);},clearTimeout,fetch:async(_url,opts)=>({ok:true,json:()=>new Promise((_resolve,reject)=>{bodySignal=opts.signal;opts.signal.addEventListener('abort',()=>reject(new Error('deadline')));})})});
 vm.runInContext(fn('dashboard.html','api'),ctx);
 await assert.rejects(vm.runInContext("api('/hung')",ctx),/deadline/);assert.equal(delay,30000);assert.equal(bodySignal.aborted,true);
 ctx.fetch=async()=>({ok:true,json:async()=>({ok:true})});assert.equal((await vm.runInContext("api('/retry')",ctx)).ok,true);
});
test('standalone self tiles sum the same rows displayed in the table',()=>{
 const nodes=Object.fromEntries(['kSpend','kSpendS','kSpendL'].map(id=>[id,{textContent:''}]));
 const ctx=vm.createContext({rows:[{cost_usd:2,total_tokens:100,requests:3},{cost_usd:4,total_tokens:200,requests:5}],document:{getElementById:id=>nodes[id]},fmt$:n=>'$'+n,fmtTok:String});
 vm.runInContext(fn('manager.html','renderSelfSpend')+'\nrenderSelfSpend();',ctx);
 assert.equal(nodes.kSpend.textContent,'$6');assert.equal(nodes.kSpendS.textContent,'300 tokens · 8 requests this window');assert.equal(nodes.kSpendL.textContent,'My spend');
});
test('successful access PATCH reconciles from the next server read even if values changed',async()=>{
 const role={value:'admin',removeAttribute(){}},manager={value:'manager'},feedback={style:{}};
 const row={getAttribute:name=>({'data-user-id':'user','data-manager-user-id':'manager','data-confirmed-role':'user'})[name],querySelector:selector=>selector==='.partner-role'?role:selector==='.partner-manager'?manager:feedback,querySelectorAll:()=>[role,manager]};
 let loads=0;
 const ctx=vm.createContext({encodeURIComponent,partnerUsersAccessErrors:new Map(),partnerUsersPendingAccess:new Map(),updateJSON:async()=>({}),loadPartnerUsers:()=>loads++,showToast(){},select:{closest:()=>row}});
 vm.runInContext(fn('admin.html','updatePartnerAccess')+'\nupdatePartnerAccess(select);',ctx);await flush();
 assert.equal(ctx.partnerUsersPendingAccess.get('user').reconcile,true);assert.equal(loads,1);
});
test('identity-less self fallback uses personal usage without admin endpoints',async()=>{
 const nodes=Object.fromEntries(['rows','kSpend','kSpendS','kSpendL','chartsError','tlPanel'].map(id=>[id,{textContent:'',style:{}}]));
 const calls=[],ov={total_cost_usd:3,total_tokens:90,total_requests:2,saved_usd:4};
 let rendered=0,saved;
 const ctx=vm.createContext({Error,encodeURIComponent,me:{user:'outsider',display_name:'Outside User'},document:{getElementById:id=>nodes[id]},fmt$:n=>'$'+n,fmtTok:String,esc:String,
  chartJSON:async url=>{calls.push(url);if(url.startsWith('/api/v1/org/usage'))throw new Error('HTTP 403');if(url.startsWith('/api/v1/me/usage/summary'))return {overview:ov,quota:{limit_usd:20,spent_usd:3,enforced:true}};if(url.startsWith('/api/v1/me/usage/models'))return [{model:'own-model'}];throw new Error('unexpected admin request '+url);},
  renderRows:()=>rendered++,renderSavedKPI:value=>saved=value,renderPies(){},loadCharts(){throw new Error('org charts must not run');},chartFailure:error=>{throw error;}});
 vm.runInContext('var rows=[],range="mtd",savingsRef="reference",usageGeneration=0,chartsGeneration=0,selfCharts=false,chartsCache=null;'+fn('manager.html','loadSelf')+'\n'+fn('manager.html','loadSelfCharts')+'\n'+fn('manager.html','renderSelfSpend'),ctx);
 await vm.runInContext('loadSelf()',ctx);
 assert.equal(rendered,1);assert.equal(ctx.rows.length,1);assert.equal(ctx.rows[0].username,'outsider');assert.equal(ctx.rows[0].slug,'');assert.equal(ctx.rows[0].cost_usd,3);assert.equal(ctx.rows[0].quota_usd,20);
 assert.equal(ctx.selfCharts,true);assert.equal(nodes.kSpend.textContent,'$3');assert.equal(nodes.tlPanel.style.display,'none');assert.equal(ctx.chartsCache.users[0].username,'outsider');assert.equal(saved.saved_usd,4);
 assert(calls.every(url=>!url.includes('/dashboard/')));
});
test('partner identity self view keeps the existing org flow',async()=>{
 let charts=0,renders=0;const expected=[{username:'member',cost_usd:5}],calls=[];
 const ctx=vm.createContext({Error,rows:[],range:'mtd',usageGeneration:0,selfCharts:true,chartJSON:async url=>{calls.push(url);return expected;},renderRows:()=>renders++,renderSelfSpend(){},loadCharts:async()=>charts++});
 vm.runInContext(fn('manager.html','loadSelf'),ctx);await vm.runInContext('loadSelf()',ctx);
 assert.deepEqual(calls,['/api/v1/org/usage?range=mtd']);assert.equal(ctx.rows,expected);assert.equal(ctx.selfCharts,false);assert.equal(charts,1);assert.equal(renders,1);
});
test('malformed personal summary reports failure without replacing the table',async()=>{
 const node={innerHTML:''};let renders=0;
 const ctx=vm.createContext({Error,encodeURIComponent,range:'mtd',savingsRef:'ref',usageGeneration:0,rows:[{username:'previous'}],chartJSON:async url=>{if(url.startsWith('/api/v1/org/'))throw new Error('HTTP 403');return {};},document:{getElementById:()=>node},esc:String,renderRows:()=>renders++,renderSelfSpend(){},loadSelfCharts:async()=>{}});
 vm.runInContext(fn('manager.html','loadSelf'),ctx);await vm.runInContext('loadSelf()',ctx);
 assert.equal(renders,0);assert.equal(ctx.rows[0].username,'previous');assert.match(node.innerHTML,/usage failed/);
});
