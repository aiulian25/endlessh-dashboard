import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
const require = createRequire(import.meta.url);
// Optional offline module path; normal installs use the exactly pinned dev dependency.
const playwrightPath = process.env.UI_PLAYWRIGHT_MODULE || 'playwright';
const { chromium } = require(playwrightPath);
assert.equal(require(playwrightPath + '/package.json').version, '1.62.1');
const webRoot = resolve(process.env.UI_WEB_ROOT || fileURLToPath(new URL('../web', import.meta.url)));
const machine = (id) => ({ id, name: `Fixture ${id}`, host: '192.0.2.1', port: 2112, metrics_path: '/metrics', enabled: true, status: 'ok', trapped_now: 2, consecutive_failures: 0, activity: [], colour: 'm0' });
const pageData = (ip = '192.0.2.2', extra = {}) => ({ total: 2, distinct_ips: 2, page: 1, per_page: 50, rows: [{ ip, machine_id: 1, machine_name: 'Fixture 1', connections: 2, trapped_seconds: 3, status: 'trapped' }], ...extra });
const series = (value) => ({ from: '2026-11-06T00:00:00Z', to: '2026-11-07T00:00:00Z', bucket_seconds: 86400, series: [{machine_id: 1, name:'Fixture 1', points:[{t:'2026-11-06T00:00:00Z', opens:value, trapped_seconds:value, bytes_sent:0}]}] });
function deferred() { let resolve; const promise = new Promise(r => {resolve=r;}); return {promise,resolve}; }

async function fixture(t, hash = '#/overview', options = {}) {
  const held = [];
  const requests = [];
  const pending = [];
  const server = createServer(async (req,res) => {
    try {
      const url = new URL(req.url,'http://fixture');
      if (url.pathname.startsWith('/api/')) {
        url.method=req.method;url.requestId=req.headers['x-ui-test-request'];requests.push(url);
        if(held.some(h=>h.transportFailure&&h.id===url.requestId)){res.destroy();return;}
        const match = held.find(h => !h.taken && h.match(url));
        if (match) {
          match.taken=true;match.id=req.headers['x-ui-test-request'];match.seen.resolve(); pending.push(match);
          const result=await match.response.promise;
          if(result.networkError){match.transportFailure=true;res.destroy();return;}
          res.writeHead(result.status || 200, {'Content-Type':'application/json'});res.end(JSON.stringify(result.body));return;
        }
        let body;
        switch(url.pathname) {
          case '/api/login': case '/api/session': body={username:'fixture',csrf_token:'fixture-token',must_change_password:false};break;
          case '/api/machines': body=[machine(1),{...machine(2),...(options.disabled?{enabled:false,status:'disabled'}:{})}];break;
          case '/api/machines/test': body=options.probe;break;
          case '/api/settings': body={scrape_interval_seconds:300,...options.settings};break;
          case '/api/overview': body={unique_attackers: 2,countries:1,machine_count:2,trapped_now:2};break;
          case '/api/ports': body={collection_started_at:options.portRows?'2026-11-06T00:00:00Z':null,available:Boolean(options.portRows),rows:options.portRows || []};break;
          case '/api/timeseries': body=options.portRows ? series(url.searchParams.get('port')==='22'?30:url.searchParams.get('port')==='2222'?70:url.searchParams.has('port')?0:100) : series(url.searchParams.get('machines')==='1'?333:url.searchParams.get('window')==='7d'?222:111);break;
          case '/api/attackers': body=pageData('192.0.2.2',{total:options.total??2,page:Number(url.searchParams.get('page'))||1});break;
          case '/api/attackers/countries': body=[{country:'Germany',country_key:'code:DE',country_code:'DE',count:2}];break;
          case '/api/geo/points': case '/api/geo/countries': case '/api/backups': body=[];break;
          case '/api/logout': body={};break;
          default: res.writeHead(404);res.end();return;
        }
        if(options.portRows && url.pathname==='/api/timeseries') {for(const entry of body.series)for(const point of entry.points)point.bytes_sent=point.opens*10;}
        if(options.portRows && url.pathname==='/api/timeseries' && url.searchParams.has('port') && !options.portRows.some(row=>row.port===url.searchParams.get('port'))) {for(const entry of body.series)for(const point of entry.points){point.available=false;point.opens=null;point.trapped_seconds=null;point.bytes_sent=null;}}
        res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(body));return;
      }
      const name = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
      const path=resolve(webRoot,name);if(!path.startsWith(webRoot+'/')) {res.writeHead(403);res.end();return;}
      const content=await readFile(path);
      res.writeHead(200,{'Content-Type':({'.html':'text/html','.js':'text/javascript','.css':'text/css','.png':'image/png'})[extname(path)] || 'text/plain'});res.end(content);
    } catch { if(!res.headersSent)res.writeHead(500);res.end(); }
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  t.after(async()=>{for(const p of pending)p.response.resolve({body:{}});server.closeAllConnections();await new Promise(r=>server.close(r));});
  const browser=await chromium.launch({headless:true});t.after(()=>browser.close());
  const context=await browser.newContext({colorScheme:options.theme || 'dark',reducedMotion:'reduce',viewport:options.viewport || {width:1280,height:720}});const page=await context.newPage();
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.addInitScript(()=>{
    window.__unhandled=[];addEventListener('unhandledrejection',e=>window.__unhandled.push(String(e.reason)));
    // Simulate a transport that cannot cancel: generation/signal checks must
    // still reject stale completed successes, errors and 401s.
    const nativeFetch=window.fetch;let id=0;window.__responses=[];
    window.fetch=async(input,init={})=>{
      const requestId=String(++id);
      try {
        const response=await nativeFetch(input,{...init,signal:undefined,headers:{...init.headers,'X-UI-Test-Request':requestId}});
        await response.clone().text();
        return response;
      } finally { window.__responses.push(requestId); }
    };
  });
  const origin=`http://127.0.0.1:${server.address().port}`;
  await context.route('**/*',route=>new URL(route.request().url()).origin===origin ? route.continue() : route.abort());
  function hold(match){const item={match,seen:deferred(),response:deferred()};held.push(item);return item;}
  async function start(){await page.goto(origin+'/'+hash);}
  async function respond(item,result){
    item.response.resolve(result);
    await page.waitForFunction(id=>window.__responses.includes(id),item.id);
    await page.evaluate(()=>new Promise(r=>requestAnimationFrame(r)));
  }
  async function clean(){assert.deepEqual(errors,[]);assert.deepEqual(await page.evaluate(()=>window.__unhandled),[]);}
  async function tick(){await page.evaluate(()=>{document.activeElement?.blur();document.dispatchEvent(new Event('visibilitychange'));});}
  return {page,start,hold,requests,clean,respond,tick};
}

test('overview: newest range and labels survive an older success', {timeout:20000}, async t=>{
  const f=await fixture(t);const a=f.hold(u=>u.pathname==='/api/timeseries'&&u.searchParams.get('window')==='24h');
  await f.start();await a.seen.promise;
  await f.page.locator('#ov-range [data-window="7d"]').click();
  await f.page.waitForFunction(()=>document.querySelector('#ov-stats')?.textContent.includes('222'));
  await f.respond(a,{body:series(111)});

  const text=await f.page.locator('#ov-stats').textContent();assert.match(text,/222/);assert.match(text,/last 7d/);assert.doesNotMatch(text,/111/);
  await f.clean();
});

test('machine selection disposes the older overview batch', {timeout:20000}, async t=>{
 const f=await fixture(t);const a=f.hold(u=>u.pathname==='/api/timeseries'&&u.searchParams.get('machines')==='1,2');await f.start();await a.seen.promise;
 await f.page.locator('.mcard-check[value="2"]').uncheck();
 await f.page.waitForFunction(()=>document.querySelector('#ov-stats')?.textContent.includes('333'));
 await f.respond(a,{body:series(111)});
 assert.match(await f.page.locator('#ov-stats').textContent(),/333/);await f.clean();
});

test('attackers: reverse filter, sort and page responses without mislabeling', {timeout:20000}, async t=>{
  const f=await fixture(t,'#/attackers');await f.start();await f.page.locator('#attackers-table tbody tr').waitFor();
  const a=f.hold(u=>u.pathname==='/api/attackers'&&u.searchParams.get('status')==='gave_up');
  await f.page.locator('#attackers-status').selectOption('gave_up');await a.seen.promise;
  await f.page.locator('#attackers-status').selectOption('trapped');
  await f.page.waitForFunction(()=>document.querySelector('#attackers-status').value==='trapped');
  await f.respond(a,{body:pageData('192.0.2.99')});
  assert.doesNotMatch(await f.page.locator('#attackers-card').textContent(),/192\.0\.2\.99/);
  const sortA=f.hold(u=>u.pathname==='/api/attackers'&&u.searchParams.get('sort')==='connections');
  await f.page.locator('[data-sort="connections"]').click();await sortA.seen.promise;
  await f.page.locator('[data-sort="last_seen"]').click();
  await f.page.waitForFunction(()=>document.querySelector('#attackers-note').textContent.includes('last observed'));
  await f.respond(sortA,{body:pageData('192.0.2.77')});
  assert.doesNotMatch(await f.page.locator('#attackers-card').textContent(),/192\.0\.2\.77/);
  // Use a count big enough for a next page, then hold page 2 and supersede it.
  const b=f.hold(u=>u.pathname==='/api/attackers'&&u.searchParams.get('page')==='2');
  await f.page.evaluate(async()=>{const app=await import('/app.js');app.navigate('#/attackers');});
  await f.page.locator('#attackers-table tbody tr').waitFor();
  // Fixture page size in the UI is 50; override total through one held load.
  const c=f.hold(u=>u.pathname==='/api/attackers'&&u.searchParams.get('q')==='pages');
  await f.page.locator('#attackers-q').fill('pages');await c.seen.promise;await f.respond(c,{body:pageData('192.0.2.3',{total:150})});
  await f.page.locator('[data-next]:not([disabled])').waitFor();await f.page.locator('[data-next]').click();await b.seen.promise;
  await f.page.locator('#attackers-status').selectOption('unknown');
  await f.page.waitForFunction(()=>document.querySelector('[data-next]')?.disabled);
  await f.respond(b,{body:pageData('192.0.2.88',{page:2,total:150})});
  assert.doesNotMatch(await f.page.locator('#attackers-card').textContent(),/192\.0\.2\.88/);
  await f.clean();
});

test('country summaries reject an older time-basis response', {timeout:20000}, async t=>{
 const f=await fixture(t,'#/attackers');const a=f.hold(u=>u.pathname==='/api/attackers/countries'&&u.searchParams.get('basis')==='activity');
 const b=f.hold(u=>u.pathname==='/api/attackers/countries'&&u.searchParams.get('basis')==='observed');
 await f.start();await a.seen.promise;await f.page.locator('#attackers-basis').selectOption('observed');await b.seen.promise;
 await f.respond(b,{body:[{country:'United States',country_key:'code:US',country_code:'US',count:2}]});
 await f.page.locator('#attackers-country option[value="code:US"]').waitFor({state:'attached'});
 await f.respond(a,{body:[{country:'Germany',country_key:'code:DE',country_code:'DE',count:99}]});
 assert.match(await f.page.locator('#attackers-chips').textContent(),/United States/);assert.doesNotMatch(await f.page.locator('#attackers-chips').textContent(),/Germany/);await f.clean();
});

test('typing invalidates an older row response before the debounce fires', {timeout:20000}, async t=>{
 const f=await fixture(t,'#/attackers');await f.start();await f.page.locator('#attackers-table tbody tr').waitFor();
 const a=f.hold(u=>u.pathname==='/api/attackers'&&u.searchParams.get('status')==='gave_up'&&!u.searchParams.get('q'));
 await f.page.locator('#attackers-status').selectOption('gave_up');await a.seen.promise;
 await f.page.locator('#attackers-q').fill('latest');await f.respond(a,{body:pageData('192.0.2.66')});
 assert.doesNotMatch(await f.page.locator('#attackers-card').textContent(),/192\.0\.2\.66/);
 const b=f.hold(u=>u.pathname==='/api/attackers'&&u.searchParams.get('status')==='unknown'&&u.searchParams.get('q')==='latest');
 await f.page.locator('#attackers-status').selectOption('unknown');await b.seen.promise;
 await f.respond(b,{body:pageData('192.0.2.44')});await f.page.waitForFunction(()=>document.querySelector('#attackers-card').textContent.includes('192.0.2.44'));
 await f.clean();
});

for (const status of [200,500]) test(`route disposal: old detail ${status} never mutates a detached view`, {timeout:20000}, async t=>{
  const f=await fixture(t,'#/machines/1');const a=f.hold(u=>u.pathname==='/api/timeseries'&&u.searchParams.get('machines')==='1');await f.start();await a.seen.promise;
  await f.page.evaluate(()=>{const old=document.querySelector('#view > div');window.__oldMutations=0;new MutationObserver(()=>window.__oldMutations++).observe(old,{childList:true,subtree:true,characterData:true});location.hash='#/machines/2';});
  await f.page.waitForFunction(()=>document.querySelector('#view h1')?.textContent.includes('Fixture 2'));
  await f.respond(a,{status,body:status===200?series(999):{error:'obsolete failure'}});
  assert.match(await f.page.locator('#view h1').textContent(),/Fixture 2/);assert.equal(await f.page.evaluate(()=>window.__oldMutations),0);await f.clean();
});

test('logout and a later login ignore old 401s and canceled debounces', {timeout:20000}, async t=>{
 const f=await fixture(t,'#/attackers');const a=f.hold(u=>u.pathname==='/api/attackers');await f.start();await a.seen.promise;
 await f.page.locator('#attackers-q').fill('obsolete');await f.page.locator('#logout-btn').click();await f.page.locator('#login-user').waitFor({state:'visible'});
 await f.page.waitForTimeout(400);assert.equal(f.requests.some(u=>u.searchParams.get('q')==='obsolete'),false);
 await f.page.locator('#login-user').fill('fixture');await f.page.locator('#login-pass').fill('fixture-password');await f.page.locator('#login-form button[type=submit]').click();
 await f.page.locator('#attackers-table tbody tr').waitFor();
 await f.respond(a,{status:401,body:{error:'old session'}});await f.page.waitForTimeout(400);
 assert.equal(await f.page.locator('#app').isVisible(),true);await f.clean();
});

test('a startup settings response cannot sign out a later session', {timeout:20000}, async t=>{
 const f=await fixture(t);const a=f.hold(u=>u.pathname==='/api/settings');await f.start();await a.seen.promise;
 await f.page.locator('#ov-stats .stat-value').first().waitFor();await f.page.locator('#logout-btn').click();await f.page.locator('#login-user').waitFor({state:'visible'});
 await f.page.locator('#login-user').fill('fixture');await f.page.locator('#login-pass').fill('fixture-password');await f.page.locator('#login-form button[type=submit]').click();
 await f.page.locator('#ov-stats .stat-value').first().waitFor();await f.respond(a,{status:401,body:{error:'old settings session'}});
 assert.equal(await f.page.locator('#app').isVisible(),true);await f.clean();
});

test('refresh rounds await async callbacks, isolate rejection and never overlap', {timeout:20000}, async t=>{
 const f=await fixture(t);await f.start();await f.page.locator('#ov-stats .stat-value').first().waitFor();
 await f.page.evaluate(async()=>{
  document.activeElement?.blur();const app=await import('/app.js');window.__starts=0;window.__peers=0;
  app.onRefresh(async()=>{window.__starts++;await new Promise(r=>window.__release=r);});
  app.onRefresh(async()=>{throw Error('intentional fixture rejection');});app.onRefresh(()=>window.__peers++);
  document.dispatchEvent(new Event('visibilitychange'));document.dispatchEvent(new Event('visibilitychange'));
 });
 await f.page.waitForFunction(()=>window.__starts===1&&window.__peers===1);
 await f.page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));await f.page.waitForTimeout(50);assert.equal(await f.page.evaluate(()=>window.__starts),1);
 await f.page.evaluate(()=>window.__release());await f.page.waitForTimeout(50);
 await f.page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));await f.page.waitForFunction(()=>window.__starts===2);await f.page.evaluate(()=>window.__release());await f.clean();
});


test('partial failure: first map error never claims geography is unconfigured', {timeout:20000}, async t=>{
 const f=await fixture(t);const a=f.hold(u=>u.pathname==='/api/geo/points');await f.start();await a.seen.promise;
 await f.respond(a,{status:503,body:{error:'Map request unavailable'}});
 await f.page.waitForFunction(()=>document.querySelector('#ov-stats')?.textContent.includes('111'));
 assert.equal(await f.page.locator('#ov-geo-off').isVisible(),false);
 assert.match(await f.page.locator('#ov-map-state').textContent(),/refresh failed.*No successful data yet/s);
 assert.equal(await f.page.locator('#ov-top-table').isVisible(),true);
 if(process.env.UI_SCREENSHOT_PATH)await f.page.screenshot({path:process.env.UI_SCREENSHOT_PATH,fullPage:true});
 await f.clean();
});

test('partial failure: map retains data through repeated errors and retries only its GET', {timeout:20000}, async t=>{
 const f=await fixture(t);const seed=f.hold(u=>u.pathname==='/api/geo/points');await f.start();await seed.seen.promise;
 await f.respond(seed,{body:[{lat:50,lon:10,country:'Germany',country_code:'DE',country_key:'code:DE',attackers:2,connections:20}]});
 await f.page.locator('#ov-map svg').waitFor();const original=await f.page.locator('#ov-map').innerHTML();
 const fail=f.hold(u=>u.pathname==='/api/geo/points');await f.tick();await fail.seen.promise;await f.respond(fail,{status:503,body:{error:'Request timed out'}});
 assert.equal(await f.page.locator('#ov-map').innerHTML(),original);assert.match(await f.page.locator('#ov-map-state').textContent(),/last successful.*updated.*ago/s);
 const again=f.hold(u=>u.pathname==='/api/geo/points');let before=f.requests.length;await f.page.locator('#ov-map-state button').click();await again.seen.promise;await f.respond(again,{networkError:true});
 assert.deepEqual([...new Map(f.requests.slice(before).map(u=>[u.requestId,[u.pathname,u.method]])).values()],[['/api/geo/points','GET']]);assert.equal(await f.page.locator('#ov-map').innerHTML(),original);
 const recover=f.hold(u=>u.pathname==='/api/geo/points');await f.page.locator('#ov-map-state button').click();await recover.seen.promise;await f.respond(recover,{body:[]});
 assert.equal(await f.page.locator('#ov-map-state').isVisible(),false);await f.page.locator('#ov-geo-off').waitFor({state:'visible'});await f.clean();
});

test('partial failure: primary summary preserves cards and controls while healthy chart updates', {timeout:20000}, async t=>{
 const f=await fixture(t);await f.start();await f.page.waitForFunction(()=>document.querySelector('#ov-stats')?.textContent.includes('111'));
 const original=await f.page.locator('#ov-stats').innerHTML();const fail=f.hold(u=>u.pathname==='/api/overview');const chart=f.hold(u=>u.pathname==='/api/timeseries');await f.tick();await Promise.all([fail.seen.promise,chart.seen.promise]);
 await f.respond(fail,{status:500,body:{error:'Summary unavailable'}});await f.respond(chart,{body:series(777)});
 assert.equal(await f.page.locator('#ov-stats').innerHTML(),original);assert.match(await f.page.locator('#ov-summary-state').textContent(),/refresh failed.*last successful/s);
 assert.equal(await f.page.locator('#ov-range button').count(),4);assert.match(await f.page.locator('#ov-chart').textContent(),/12m 57s/);
 const before=f.requests.length;await f.page.locator('#ov-summary-state button').click();await f.page.locator('#ov-summary-state').waitFor({state:'hidden'});
 assert.deepEqual(f.requests.slice(before).map(u=>u.pathname).sort(),['/api/overview','/api/timeseries']);
 const nextFail=f.hold(u=>u.pathname==='/api/overview');await f.tick();await nextFail.seen.promise;await f.respond(nextFail,{status:500,body:{error:'Again'}});await f.tick();
 await f.page.locator('#ov-summary-state').waitFor({state:'hidden'});await f.clean();
});

test('partial failure: country and row retries preserve filters and last data', {timeout:20000}, async t=>{
 const f=await fixture(t,'#/attackers');await f.start();await f.page.locator('#attackers-country option[value="code:DE"]').waitFor({state:'attached'});
 await f.page.locator('#attackers-country').selectOption('code:DE');await f.page.locator('#attackers-status').selectOption('trapped');
 const search=f.hold(u=>u.pathname==='/api/attackers'&&u.searchParams.get('q')==='investigate');await f.page.locator('#attackers-q').fill('investigate');await search.seen.promise;await f.respond(search,{body:pageData('192.0.2.12')});
 const choices=await f.page.locator('#attackers-country').innerHTML();const fail=f.hold(u=>u.pathname==='/api/attackers/countries');await f.tick();await fail.seen.promise;await f.respond(fail,{status:500,body:{error:'Countries unavailable'}});
 assert.equal(await f.page.locator('#attackers-country').innerHTML(),choices);assert.equal(await f.page.locator('#attackers-country').inputValue(),'code:DE');assert.match(await f.page.locator('#attackers-country-state').textContent(),/last successful.*updated/s);
 let before=f.requests.length;await f.page.locator('#attackers-country-state button').click();await f.page.locator('#attackers-country-state').waitFor({state:'hidden'});
 assert.deepEqual(f.requests.slice(before).map(u=>[u.pathname,u.method]),[['/api/attackers/countries','GET']]);
 const oldRows=await f.page.locator('#attackers-card').innerHTML();const rowFail=f.hold(u=>u.pathname==='/api/attackers');await f.tick();await rowFail.seen.promise;await f.respond(rowFail,{status:500,body:{error:'Rows unavailable'}});
 assert.equal(await f.page.locator('#attackers-card').innerHTML(),oldRows);assert.equal(await f.page.locator('#attackers-q').inputValue(),'investigate');assert.equal(await f.page.locator('#attackers-status').inputValue(),'trapped');
 before=f.requests.length;await f.page.locator('#attackers-row-state button').click();await f.page.locator('#attackers-row-state').waitFor({state:'hidden'});
 const retried=f.requests.slice(before);assert.equal(retried.length,1);assert.equal(retried[0].method,'GET');assert.equal(retried[0].searchParams.get('country_key'),'code:DE');assert.equal(retried[0].searchParams.get('q'),'investigate');
 const empty=f.hold(u=>u.pathname==='/api/attackers/countries'&&u.searchParams.get('basis')==='observed');await f.page.locator('#attackers-basis').selectOption('observed');await empty.seen.promise;await f.respond(empty,{body:[]});
 assert.equal(await f.page.locator('#attackers-country').inputValue(),'code:DE');assert.equal(await f.page.locator('#attackers-country-empty').isVisible(),true);await f.clean();
});

for(const first of [false,true])test(`partial failure: machine cache failure first=${first} is visible and recovers`,{timeout:20000},async t=>{
 const f=await fixture(t);let fail;
 if(first)fail=f.hold(u=>u.pathname==='/api/machines');
 await f.start();
 if(!first){await f.page.waitForFunction(()=>document.querySelector('#ov-stats')?.textContent.includes('111'));fail=f.hold(u=>u.pathname==='/api/machines');await f.tick();}
 await fail.seen.promise;await f.respond(fail,{status:503,body:{error:'Fleet metadata unavailable'}});
 await f.page.waitForFunction(()=>document.querySelector('#ov-stats')?.textContent.includes('111'));
 assert.match(await f.page.locator('#side-refresh-state').textContent(),first?/No successful data yet/:/last successful.*updated/s);
 if(!first)assert.equal(await f.page.locator('.mcard').count(),2);
 await f.page.locator('#side-refresh-state button').click();await f.page.locator('#side-refresh-state').waitFor({state:'hidden'});assert.equal(await f.page.locator('.mcard').count(),2);await f.clean();
});


test('partial failure: an old empty machine list does not hide healthy overview data', {timeout:20000}, async t=>{
 const f=await fixture(t);const empty=f.hold(u=>u.pathname==='/api/machines');await f.start();await empty.seen.promise;await f.respond(empty,{body:[]});
 await f.page.locator('#view').getByText('No machines registered yet',{exact:true}).waitFor();
 const fail=f.hold(u=>u.pathname==='/api/machines');await f.tick();await fail.seen.promise;await f.respond(fail,{status:503,body:{error:'Machine list unavailable'}});
 await f.page.waitForFunction(()=>document.querySelector('#ov-stats')?.textContent.includes('111'));
 assert.match(await f.page.locator('#side-refresh-state').textContent(),/last successful.*updated/s);await f.clean();
});


test('partial failure: a first summary failure leaves healthy panels and range controls usable', {timeout:20000}, async t=>{
 const f=await fixture(t);const fail=f.hold(u=>u.pathname==='/api/overview');await f.start();await fail.seen.promise;await f.respond(fail,{status:503,body:{error:'Summary unavailable'}});
 await f.page.locator('#ov-chart svg').waitFor();assert.match(await f.page.locator('#ov-summary-state').textContent(),/No successful data yet/);
 await f.page.locator('#ov-range [data-window="7d"]').click();await f.page.waitForFunction(()=>document.querySelector('#ov-stats')?.textContent.includes('222'));
 assert.equal(await f.page.locator('#ov-summary-state').isVisible(),false);await f.clean();
});

test('partial failure: an active geography 401 still returns to login', {timeout:20000}, async t=>{
 const f=await fixture(t);await f.start();await f.page.waitForFunction(()=>document.querySelector('#ov-stats')?.textContent.includes('111'));
 const fail=f.hold(u=>u.pathname==='/api/geo/points');await f.tick();await fail.seen.promise;await f.respond(fail,{status:401,body:{error:'Session expired'}});
 await f.page.locator('#login-user').waitFor({state:'visible'});assert.equal(await f.page.locator('#app').isVisible(),false);await f.clean();
});


test('navigation: default and All include disabled history; None sends no machines', {timeout:20000}, async t=>{
 const f=await fixture(t,'#/overview',{disabled:true});await f.start();await f.page.waitForFunction(()=>document.querySelector('#ov-stats')?.textContent.includes('111'));
 assert.equal(await f.page.locator('.mcard-check:checked').count(),2);
 assert.equal(f.requests.find(u=>u.pathname==='/api/overview').searchParams.get('machines'),'1,2');
 assert.match(await f.page.locator('.mcard-check[value="2"]').getAttribute('aria-label'),/disabled history/);
 await f.page.locator('#side-none').click();await f.page.waitForFunction(()=>location.hash.includes('overview'));
 await f.page.waitForFunction(()=>document.querySelectorAll('.mcard-check:checked').length===0);
 await f.page.waitForTimeout(60);assert.equal(f.requests.filter(u=>u.pathname==='/api/overview').at(-1).searchParams.get('machines'),'0');
 await f.page.locator('#side-all').click();await f.page.waitForFunction(()=>document.querySelectorAll('.mcard-check:checked').length===2);
 await f.page.waitForTimeout(60);assert.equal(f.requests.filter(u=>u.pathname==='/api/overview').at(-1).searchParams.get('machines'),'1,2');await f.clean();
});

test('navigation: filters survive scope changes and Back; detail View all carries scope and range', {timeout:20000}, async t=>{
 const f=await fixture(t,'#/attackers?window=7d',{disabled:true,total:150});await f.start();await f.page.locator('#attackers-country option[value="code:DE"]').waitFor({state:'attached'});
 await f.page.locator('#attackers-country').selectOption('code:DE');await f.page.locator('#attackers-status').selectOption('trapped');await f.page.locator('#attackers-q').fill('trace');
 await f.page.locator('[data-sort="connections"]').click();await f.page.waitForFunction(()=>location.hash.includes('sort=connections'));
 await f.page.locator('[data-next]:not([disabled])').click();await f.page.waitForFunction(()=>location.hash.includes('page=2'));
 await f.page.locator('#side-all').click();await f.page.locator('#attackers-q').waitFor();
 await f.page.waitForFunction(()=>location.hash.includes('page=2'));
 const saved=await f.page.evaluate(()=>location.hash);
 await f.page.locator('.mcard-link[href="#/machines/2"]').click();await f.page.locator('#view h1').waitFor();
 await f.page.goBack();await f.page.locator('#attackers-q').waitFor();
 assert.equal(await f.page.locator('#attackers-q').inputValue(),'trace');assert.equal(await f.page.locator('#attackers-status').inputValue(),'trapped');
 await f.page.locator('#attackers-country option[value="code:DE"]').waitFor({state:'attached'});assert.equal(await f.page.locator('#attackers-country').inputValue(),'code:DE');
 assert.equal(await f.page.evaluate(()=>location.hash),saved);
 await f.page.locator('.mcard-check[value="1"]').uncheck();await f.page.waitForFunction(()=>location.hash.includes('machines=2')&&location.hash.includes('page=1'));
 assert.equal(await f.page.locator('#attackers-q').inputValue(),'trace');assert.match(await f.page.locator('#attackers-scope').textContent(),/Fixture 2.*disabled history.*7d/);
 await f.page.locator('.mcard-link[href="#/machines/2"]').click();await f.page.locator('#view h1').waitFor();
 await f.page.locator('#view a[href^="#/attackers?"]').click();await f.page.locator('#attackers-scope').waitFor();
 assert.equal(await f.page.locator('.mcard-check:checked').count(),1);assert.equal(await f.page.locator('.mcard-check[value="2"]').isChecked(),true);
 const last=f.requests.filter(u=>u.pathname==='/api/attackers').at(-1);assert.equal(last.searchParams.get('machines'),'2');assert.equal(last.searchParams.get('window'),'7d');await f.clean();
});

test('navigation: an unknown route scope remains None instead of falling back to all', {timeout:20000},async t=>{
 const f=await fixture(t,'#/attackers?machines=999&sort=bad&page=-1');await f.start();await f.page.locator('#attackers-scope').waitFor();
 assert.equal(await f.page.locator('.mcard-check:checked').count(),0);assert.match(await f.page.locator('#attackers-scope').textContent(),/no machines selected/);
 const last=f.requests.filter(u=>u.pathname==='/api/attackers').at(-1);assert.equal(last.searchParams.get('machines'),'0');assert.equal(last.searchParams.get('sort'),'trapped_seconds');assert.equal(last.searchParams.get('page'),'1');await f.clean();
});

test('accessibility: refresh preserves pagination and sidebar focus without stopping data', {timeout:20000}, async t=>{
 const f=await fixture(t,'#/attackers',{total:150});await f.start();await f.page.locator('[data-next]:not([disabled])').waitFor();
 await f.page.locator('[data-next]').focus();
 const a=f.hold(u=>u.pathname==='/api/attackers');
 await f.page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));await a.seen.promise;
 await f.respond(a,{body:pageData('192.0.2.55',{total:150})});
 assert.match(await f.page.locator('#attackers-card').textContent(),/192\.0\.2\.55/);
 assert.equal(await f.page.evaluate(()=>document.activeElement.hasAttribute('data-next')),true);
 await f.page.locator('.mcard-link[href="#/machines/1"]').focus();
 const b=f.hold(u=>u.pathname==='/api/attackers');
 await f.page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));await b.seen.promise;
 await f.respond(b,{body:pageData('192.0.2.56',{total:150})});
 assert.equal(await f.page.evaluate(()=>document.activeElement.getAttribute('href')),'#/machines/1');
 await f.page.keyboard.press('Enter');await f.page.waitForFunction(()=>document.activeElement.matches('#view h1')&&document.activeElement.textContent.includes('Fixture 1'));
 const headingRefresh=f.hold(u=>u.pathname==='/api/timeseries');
 await f.page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));await headingRefresh.seen.promise;await f.respond(headingRefresh,{body:series(333)});
 assert.equal(await f.page.evaluate(()=>document.activeElement.matches('#view h1')),true);
 const c=f.hold(u=>u.pathname==='/api/timeseries');await f.page.locator('#md-range [data-window="7d"]').click();await c.seen.promise;
 await f.respond(c,{body:series(222)});assert.equal(await f.page.evaluate(()=>document.activeElement.dataset.window),'7d');await f.clean();
});

test('accessibility: inspecting a chart defers only its paint and retains its accessible table', {timeout:20000}, async t=>{
 const f=await fixture(t);await f.start();await f.page.locator('.chart-hit').waitFor();
 await f.page.locator('.chart-hit').focus();await f.page.keyboard.press('ArrowRight');
 await f.page.evaluate(()=>window.__inspected=document.activeElement);
 const a=f.hold(u=>u.pathname==='/api/timeseries');
 await f.page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));await a.seen.promise;
 await f.respond(a,{body:series(444)});
 assert.match(await f.page.locator('#ov-stats').textContent(),/444/);
 assert.equal(await f.page.evaluate(()=>document.activeElement===window.__inspected&&window.__inspected.isConnected),true);
 assert.ok(await f.page.locator('#ov-chart table').count());
 await f.page.keyboard.press('Tab');await f.page.waitForFunction(()=>!window.__inspected.isConnected);await f.clean();
});

for(const width of [900,520]) test(`accessibility: ${width}px drawer keyboard boundary, return and route context`,{timeout:20000},async t=>{
 const f=await fixture(t,'#/overview',{viewport:{width,height:800}});await f.start();await f.page.locator('.chart-hit').waitFor();
 await f.page.locator('#drawer-btn').focus();await f.page.keyboard.press('Enter');
 assert.equal(await f.page.evaluate(()=>document.activeElement.id),'drawer-close');
 assert.equal(await f.page.locator('#sidebar').getAttribute('aria-modal'),'true');
 assert.equal(await f.page.evaluate(()=>document.querySelector('#view').inert&&document.querySelector('.topbar').inert),true);
 const first=await f.page.evaluate(()=>[...document.querySelectorAll('#sidebar button,#sidebar a[href],#sidebar input,#sidebar [tabindex="0"]')].filter(n=>!n.disabled&&n.getClientRects().length)[0].id);
 await f.page.locator('#'+first).focus();await f.page.keyboard.press('Shift+Tab');
 assert.equal(await f.page.evaluate(()=>document.querySelector('#sidebar').contains(document.activeElement)),true);
 await f.page.keyboard.press('Tab');assert.equal(await f.page.evaluate(()=>document.activeElement.id),first);
 await f.page.keyboard.press('Escape');assert.equal(await f.page.evaluate(()=>document.activeElement.id),'drawer-btn');
 await f.page.keyboard.press('Enter');await f.page.locator('#drawer-close').press('Enter');assert.equal(await f.page.evaluate(()=>document.activeElement.id),'drawer-btn');
 await f.page.keyboard.press('Enter');await f.page.locator('.mcard-link[href="#/machines/1"]').focus();await f.page.keyboard.press('Enter');
 await f.page.waitForFunction(()=>document.activeElement.matches('#view h1')&&document.activeElement.textContent.includes('Fixture 1'));
 assert.equal(await f.page.evaluate(()=>document.querySelector('#view').inert),false);
 await f.page.locator('#drawer-btn').press('Enter');await f.page.setViewportSize({width:1280,height:800});
 await f.page.waitForFunction(()=>!document.querySelector('#sidebar').hasAttribute('aria-modal'));
 assert.equal(await f.page.locator('#sidebar').getAttribute('aria-modal'),null);
 assert.equal(await f.page.evaluate(()=>document.activeElement.id),'side-all');await f.clean();
});

for(const theme of ['dark','light']) test(`accessibility: ${theme} search focus, rendered contrast and long content at 200% CSS zoom`,{timeout:20000},async t=>{
 const f=await fixture(t,'#/attackers',{theme,viewport:{width:1040,height:900}});
 const a=f.hold(u=>u.pathname==='/api/attackers');await f.start();await a.seen.promise;
 const long='A very long country and organisation name '.repeat(6);
 await f.respond(a,{body:pageData('2001:0db8:1234:5678:90ab:cdef:1234:5678',{rows:[{...pageData().rows[0],ip:'2001:0db8:1234:5678:90ab:cdef:1234:5678',country:long,country_code:'DE',city:long,isp:long}]})});
 const columns=await f.page.locator('#attackers-table th').count();
 await f.page.evaluate(()=>document.body.style.zoom='2');await f.page.locator('#attackers-q').focus();
 const measured=await f.page.evaluate(()=>{
   const input=document.querySelector('#attackers-q'),box=input.closest('.search'),style=getComputedStyle(box),tokens=getComputedStyle(document.documentElement);
   const lum=hex=>{const rgb=hex.trim().slice(1).match(/../g).map(v=>parseInt(v,16)/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4);return rgb[0]*.2126+rgb[1]*.7152+rgb[2]*.0722;};
   const ratio=(a,b)=>{a=lum(tokens.getPropertyValue(a));b=lum(tokens.getPropertyValue(b));return (Math.max(a,b)+.05)/(Math.min(a,b)+.05);};
   return {outline:style.outlineWidth,focus:ratio('--primary','--card'),text:ratio('--ink','--card'),muted:ratio('--muted','--card'),columns:[...document.querySelectorAll('#attackers-table th')].filter(n=>getComputedStyle(n).display!=='none').length,scrollable:document.querySelector('#attackers-table .table-wrap').scrollWidth>document.querySelector('#attackers-table .table-wrap').clientWidth,reduced:matchMedia('(prefers-reduced-motion: reduce)').matches};
 });
 assert.equal(measured.outline,'2px');assert.ok(measured.focus>=3);assert.ok(measured.text>=4.5);assert.ok(measured.muted>=4.5);assert.equal(measured.columns,columns);assert.equal(measured.scrollable,true);assert.equal(measured.reduced,true);
 console.log('FIX-025 contrast',theme,JSON.stringify(measured));await f.clean();
});

test('accessibility: map focus survives refresh and long error retry returns to a heading',{timeout:20000},async t=>{
 const f=await fixture(t);const a=f.hold(u=>u.pathname==='/api/geo/points');await f.start();await a.seen.promise;
 const point={lat:50,lon:10,country:'Germany',country_code:'DE',country_key:'code:DE',attackers:2,connections:20};
 await f.respond(a,{body:[point]});await f.page.locator('.map-bubble').focus();
 assert.ok(await f.page.locator('#ov-map table caption').count());
 await f.page.evaluate(()=>window.__bubble=document.activeElement);
 const b=f.hold(u=>u.pathname==='/api/geo/points');await f.page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));await b.seen.promise;
 await f.respond(b,{body:[{...point,connections:99}]});assert.equal(await f.page.evaluate(()=>document.activeElement===window.__bubble),true);
 await f.page.keyboard.press('Tab');await f.page.waitForFunction(()=>!window.__bubble.isConnected);
 assert.match(await f.page.locator('#ov-map table').textContent(),/99/);
 const c=f.hold(u=>u.pathname==='/api/geo/points');await f.tick();await c.seen.promise;
 await f.respond(c,{status:503,body:{error:'A long provider error message '.repeat(30)}});
 const d=f.hold(u=>u.pathname==='/api/geo/points');await f.page.locator('#ov-map-state button').focus();await f.page.keyboard.press('Enter');await d.seen.promise;
 await f.respond(d,{body:[point]});assert.equal(await f.page.evaluate(()=>document.activeElement.matches('h1,h2,[data-focus-heading]')),true);await f.clean();
});

for (const [host,scheme,enabled] of [['ip-api.com','http',true],['geo.internal:8443','https',true],['192.168.1.8:8080','http',false]]) test(`provider disclosure: ${host} ${scheme} enabled=${enabled}`,{timeout:20000},async t=>{
 const f=await fixture(t,'#/settings',{settings:{geoip_online_enabled:enabled,geoip_online_rate_per_minute:40,geoip_online_provider_host:host,geoip_online_scheme:scheme}});
 await f.start();const card=f.page.locator('.card').filter({has:f.page.getByRole('heading',{name:'Geography',exact:true})});await card.waitFor();
 const text=await card.textContent();assert.ok(text.includes(host));assert.ok(text.includes(scheme==='https'?'HTTPS (encrypted in transit)':'HTTP (unencrypted)'));
 assert.ok(text.includes(enabled?'Online lookups are on':'Online lookups are off'));
 assert.doesNotMatch(text,/third party/);if(host!=='ip-api.com')assert.doesNotMatch(text,/ip-api\.com/);
 if(!enabled)assert.ok(text.includes('no online lookup requests are sent'));
 await f.clean();
});

for (const state of ['inconclusive','partial','compatible']) test(`connection evidence: ${state} feedback keeps registration available`,{timeout:20000},async t=>{
 const probe={reachable:true,exposition_valid:true,endlessh_evidence:state,message:state==='inconclusive'?'Reachable metrics endpoint. No Endlessh samples yet; result is inconclusive.':'Supported Endlessh metric samples found.',metric_families:state==='inconclusive'?[]:[{name:'endlessh_client_open_count_total',type:'counter',samples:1}]};
 const f=await fixture(t,'#/machines',{probe});await f.start();await f.page.locator('#add-machine').click();
 await f.page.locator('#mf-name').fill('Fixture candidate');await f.page.locator('#mf-host').fill('192.0.2.8');
 await f.page.getByRole('button',{name:'Test connection',exact:true}).click();
 await f.page.waitForFunction(message=>document.querySelector('[data-probe-result]')?.textContent.includes(message),probe.message);
 const result=f.page.locator('[data-probe-result]');assert.match(await result.getAttribute('class'),state==='compatible'?/\bok\b/:/inconclusive/);
 assert.equal(await result.getAttribute('role'),'status');assert.ok((await result.textContent()).includes(probe.message));
 if(state!=='inconclusive')assert.match(await result.textContent(),/endlessh_client_open_count_total \(counter, 1 samples\)/);
 const save=f.hold(u=>u.pathname==='/api/machines'&&u.method==='POST');await f.page.locator('dialog button[type="submit"]').click();await save.seen.promise;
 await f.respond(save,{body:{id:3,name:'Fixture candidate'}});await f.page.locator('dialog').waitFor({state:'hidden'});await f.clean();
});

const portRows = [{port:'22',opens:30,closes:3,bytes_sent:300,trapped_seconds:30,observed_seconds:60,samples:2},{port:'2222',opens:70,closes:7,bytes_sent:700,trapped_seconds:70,observed_seconds:60,samples:2}];
test('port detail: selection scopes chart and totals, preserves context and ignores stale responses',{timeout:20000},async t=>{
 const f=await fixture(t,'#/machines/1',{portRows});await f.start();await f.page.locator('#md-port').waitFor();
 assert.match(await f.page.locator('#md-port-totals').textContent(),/100/);assert.equal(await f.page.locator('#md-ports tbody tr').count(),2);
 const old=f.hold(u=>u.pathname==='/api/timeseries'&&u.searchParams.get('port')==='22');
 await f.page.locator('#md-port').selectOption('22');await old.seen.promise;
 await f.page.locator('#md-port').selectOption('2222');await f.page.waitForFunction(()=>document.querySelector('#md-port-totals')?.textContent.includes('70'));
 await f.respond(old,{body:series(999)});assert.equal(await f.page.locator('#md-port').inputValue(),'2222');assert.doesNotMatch(await f.page.locator('#md-port-totals').textContent(),/999/);
 assert.match(await f.page.locator('#md-chart table').textContent(),/1m 10s recorded/);assert.match(await f.page.locator('#md-port-totals').textContent(),/700 B/);assert.match(await f.page.locator('#view h1').textContent(),/Fixture 1/);
 assert.equal(await f.page.evaluate(()=>location.hash),'#/machines/1?port=2222');
 await f.page.locator('#md-range [data-window="7d"]').click();await f.page.waitForFunction(()=>document.querySelector('#md-range [data-window="7d"]')?.getAttribute('aria-pressed')==='true');
 assert.equal(await f.page.locator('#md-port').inputValue(),'2222');
 const last=f.requests.filter(u=>u.pathname==='/api/timeseries').at(-1);assert.equal(last.searchParams.get('machines'),'1');assert.equal(last.searchParams.get('window'),'7d');assert.equal(last.searchParams.get('port'),'2222');assert.equal(f.requests.filter(u=>u.pathname==='/api/ports').at(-1).searchParams.get('as_of'),last.searchParams.get('as_of'));
 assert.ok(f.requests.filter(u=>u.pathname==='/api/attackers').every(u=>!u.searchParams.has('port')));
 if(process.env.UI_PORT_SCREENSHOT_PATH){await f.page.evaluate(()=>window.scrollTo(0,0));await f.page.screenshot({path:process.env.UI_PORT_SCREENSHOT_PATH+'-desktop.png',fullPage:true});}await f.clean();
});
test('port detail: unknown URL selection stays selected and displays unavailable at narrow width',{timeout:20000},async t=>{
 const f=await fixture(t,'#/machines/1?port=65535',{portRows,viewport:{width:520,height:900}});await f.start();await f.page.locator('#md-port').waitFor();
 assert.equal(await f.page.locator('#md-port').inputValue(),'65535');assert.match(await f.page.locator('#md-port-totals').textContent(),/Unavailable/);
 assert.match(await f.page.locator('#md-chart table').textContent(),/Unavailable/);assert.equal(await f.page.locator('#md-ports th[scope="col"]').count(),6);
 if(process.env.UI_PORT_SCREENSHOT_PATH)await f.page.screenshot({path:process.env.UI_PORT_SCREENSHOT_PATH+'-mobile.png',fullPage:true});
 await f.page.locator('#md-port').focus();await f.page.locator('#md-port').selectOption('22');await f.page.waitForFunction(()=>document.querySelector('#md-port-totals')?.textContent.includes('30'));
 assert.equal(await f.page.evaluate(()=>document.activeElement.id),'md-port');await f.clean();
});
