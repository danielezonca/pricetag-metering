'use strict';
// Deterministic overlap regressions for the standalone allowance editor.
// Run with NODE_PATH pointing at a Playwright installation.
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const dir=path.join(__dirname,'../../internal/dashboard');
const fragments=['users','keys','budgets','prices'].map(name=>fs.readFileSync(path.join(dir,'management-admin-'+name+'.html'),'utf8')).join('');
const controls=['management-key-controls.js','management-table-controls.js'].map(name=>fs.readFileSync(path.join(dir,name),'utf8')).join('\n');
const script=fs.readFileSync(path.join(dir,'management-admin-script.html'),'utf8').replace('/* KEY_CONTROLS */',controls);
const html='<html><body>'+fragments+'<p id="status"></p><script>const activeTab="people",partnerUsersAll=[];function showToast(){}function loadPartnerUsers(){}</script>'+script+'</body></html>';
(async()=>{
 const browser=await chromium.launch({headless:true});
 try{
  const page=await browser.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  let users=0,releaseInitial,failAllowance=false,saves=0;
  await page.route('https://fixture.invalid/**',async route=>{
   const u=new URL(route.request().url()),method=route.request().method();
   if(u.pathname==='/admin')return route.fulfill({contentType:'text/html',body:html});
   if(u.pathname.endsWith('/users')){
    if(++users===1)await new Promise(resolve=>releaseInitial=resolve);
    return route.fulfill({json:{data:[{logins:['alice'],active:true,tags:{first_name:'Alice'}}],has_more:false}});
   }
   if(u.pathname.endsWith('/budgets')){
    if(method==='PUT'){saves++;return route.fulfill({json:{}});}
    if(u.searchParams.has('subject')&&failAllowance)return route.fulfill({status:503,body:'allowance unavailable'});
    return route.fulfill({json:{data:[],has_more:false,default_monthly_usd:5}});
   }
   return route.fulfill({json:[]});
  });
  await page.goto('https://fixture.invalid/admin');
  const deadline=Date.now()+10000;while(!releaseInitial){if(Date.now()>deadline)throw new Error('bootstrap request not held');await new Promise(resolve=>setTimeout(resolve,10));}
  await page.evaluate(()=>window.refreshManagedUsers());
  const input=page.locator('#budget input[name="monthly_usd"]'),save=page.locator('#budget').getByRole('button',{name:'Set override'});
  await input.fill('73');
  const oldResponse=page.waitForResponse(r=>r.url().includes('/management/users'));
  releaseInitial();await oldResponse;
  await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
  assert.equal(await input.inputValue(),'73','late bootstrap response must preserve the newer draft');
  failAllowance=true;
  await save.click();
  await page.waitForFunction(()=>document.getElementById('status').textContent==='allowance unavailable');
  assert.equal(await input.isDisabled(),true);
  assert.equal(await save.isDisabled(),true,'failed post-save load must keep Save disabled');
  assert.equal(saves,1);
  failAllowance=false;
  await page.locator('#budget select[name="subject"]').dispatchEvent('change');
  await page.waitForFunction(()=>!document.querySelector('#budget input[name="monthly_usd"]').disabled);
  assert.equal(await save.isEnabled(),true,'successful reload must allow a new save');
  assert.deepEqual(errors,[]);
  console.log('PASS: superseded bootstrap preserves draft; failed allowance reload keeps Save disabled; successful reload enables retry');
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
