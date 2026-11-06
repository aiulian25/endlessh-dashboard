import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';

async function chartFixture() {
 const source=process.env.CHART_TEST_SOURCE || new URL('./chart.js',import.meta.url);
 const chart=new vm.SourceTextModule(await readFile(source,'utf8'));
 const range=new vm.SourceTextModule(await readFile(new URL('./time-range.js',import.meta.url),'utf8'));
 const notes=new vm.SourceTextModule(await readFile(new URL('./metric-notes.js',import.meta.url),'utf8'));
 const app=new vm.SyntheticModule(['esc','fmtDuration','machineColour'],function(){this.setExport('esc',v=>String(v??''));this.setExport('fmtDuration',v=>String(v));this.setExport('machineColour',()=> 's-1')});
 await chart.link(name=>name==='./app.js'?app:name==='./metric-notes.js'?notes:range);await chart.evaluate();
 const elements=Object.fromEntries(['.chart-plot','.chart-hit','.chart-tip','.chart-cursor'].map(key=>[key,{style:{},handlers:{},clientWidth:390,offsetWidth:220,addEventListener(name,fn){this.handlers[name]=fn},setAttribute(){}}]));
 const host={innerHTML:'',querySelector:key=>elements[key]};return {render:chart.namespace.renderChart,host,elements};
}
const point=(minute,coverage,value=0,extra={})=>({t:`2026-11-05T12:0${minute}:00Z`,to:`2026-11-05T12:0${minute+1}:00Z`,coverage,trapped_seconds:value,...extra});
const data=(points)=>({from:points[0].t,to:points.at(-1).to,series:[{machine_id:1,machine_name:'one',points}]});

test('successful zero stays distinct from missing samples and partial recovery',async()=>{
 const {render,host,elements}=await chartFixture();
 render(host,data([point(0,'complete'),point(1,'unknown'),point(2,'incomplete',300,{uncertain_from:'2026-11-05T12:00:15Z',uncertain_to:'2026-11-05T12:02:30Z'})]));
 assert.equal((host.innerHTML.match(/class="coverage-gap"/g)||[]).length,2);
 assert.match(host.innerHTML,/Observed at expected cadence/);assert.match(host.innerHTML,/Observation coverage unknown/);assert.match(host.innerHTML,/300 recorded; Incomplete observation coverage/);
 const hit=elements['.chart-hit'];hit.handlers.keydown({key:'Home',preventDefault(){}});
 assert.doesNotMatch(elements['.chart-tip'].innerHTML,/— \(recorded 0\)/);
 hit.handlers.keydown({key:'ArrowRight',preventDefault(){}});assert.match(elements['.chart-tip'].innerHTML,/— \(recorded 0\)/);
 hit.handlers.keydown({key:'End',preventDefault(){}});assert.match(elements['.chart-tip'].innerHTML,/timing uncertain: 2026-11-05T12:00:15Z/);assert.match(elements['.chart-tip'].innerHTML,/>300</);
});

test('a missing selected machine marks the stack incomplete without hiding known growth',async()=>{
 const {render,host}=await chartFixture();const input=data([point(0,'complete',50),point(1,'complete',10)]);
 input.series.push({machine_id:2,machine_name:'offline',points:[point(0,'unknown'),point(1,'unknown')]});render(host,input);
 assert.equal((host.innerHTML.match(/class="coverage-gap"/g)||[]).length,2);assert.match(host.innerHTML,/50 recorded; Observed at expected cadence/);assert.match(host.innerHTML,/offline/);
});
