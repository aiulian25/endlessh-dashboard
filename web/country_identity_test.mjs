import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { countrySummaryLabel } from './country.js';

test('country labels distinguish conflicting codes and name-only groups', () => {
 assert.equal(countrySummaryLabel({country:'Germany',country_code:'DE',country_key:'code:DE'}),'Germany (DE)');
 assert.equal(countrySummaryLabel({country:'Germany',country_code:'FR',country_key:'code:FR'}),'Germany (FR)');
 assert.equal(countrySummaryLabel({country:'Germany',country_key:'name:germany'}),'Germany (name only)');
 assert.equal(countrySummaryLabel({country_code:'US',country_key:'code:US'}),'US');
});

test('country chip and select submit the stable key rather than the display name', async () => {
 const modules = {};
 for (const file of ['attackers','metric-notes','time-range','country','requests','panel-state','navigation','focus']) modules[`./${file}.js`] = new vm.SourceTextModule(await readFile(new URL(`./${file}.js`,import.meta.url),'utf8'));
 const calls=[];
 const country={country:'Deutschland',country_code:'DE',country_key:'code:DE',count:2};
 const names=['api','qs','esc','icon','onRefresh','renderError','emptyState','fmtDuration','fmtNumber','fmtRelative','fmtDateTime','machinesParam','getWindow','currentMachines','ATTACKER_TRAPPED'];
 const app=new vm.SyntheticModule(names,function(){for(const name of names)this.setExport(name, name==='api'?async(path)=>{
 calls.push(path);return path.startsWith('/attackers/countries')?[country]:{rows:[],total:0,distinct_ips:0,page:1,per_page:50};
 }:name==='qs'?(v)=>'?'+new URLSearchParams(v):name==='currentMachines'?()=>[]:name==='getWindow'?()=> '24h':name==='renderError'?(_,error)=>{throw error;}:name==='ATTACKER_TRAPPED'?'trapped':(v)=>String(v??''));});
 await modules['./attackers.js'].link((name)=>name==='./app.js'?app:modules[name]);await modules['./attackers.js'].evaluate();
 class Element {
  constructor(){this.children=new Map();this.listeners={};this.value='';this.dataset={};this.html='';}
  set innerHTML(v){this.html=v;if(v.includes('data-country=')){this.chip=new Element();this.chip.dataset.country=v.match(/data-country="([^"]+)"/)[1];}}
  get innerHTML(){return this.html;}
  querySelector(s){if(!this.children.has(s))this.children.set(s,new Element());return this.children.get(s);}
  querySelectorAll(s){return s==='[data-country]'&&this.chip?[this.chip]:[];}
  addEventListener(name,fn){this.listeners[name]=fn;}
 }
 const mount=new Element();await modules['./attackers.js'].namespace.render(mount);
 const select=mount.querySelector('#attackers-country');const chips=mount.querySelector('#attackers-chips');
 assert.match(select.innerHTML,/value="code:DE"/);assert.match(chips.innerHTML,/Deutschland \(DE\)/);
 chips.chip.listeners.click();await new Promise(setImmediate);
 assert.equal(new URL(calls.at(-1),'http://test').searchParams.get('country_key'),'code:DE');assert.equal(select.value,'code:DE');
 select.value='name:germany';select.listeners.change();await new Promise(setImmediate);
 assert.equal(new URL(calls.at(-1),'http://test').searchParams.get('country_key'),'name:germany');
 assert.equal(new URL(calls.at(-1),'http://test').searchParams.has('country'),false);
});
