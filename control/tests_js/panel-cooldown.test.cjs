const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const assert = require('node:assert/strict');
const test = require('node:test');
const source = fs.readFileSync(path.join(__dirname, '../static/control/panel-cooldown.js'), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));
const value = (enabled = true, revision = 0, can_change = true) => ({ok:true, policy:{enabled,revision}, can_change});
function fixture(getJson, postJson = async () => value(false, 1)) {
  const events = new Map(), timers = new Set(), cards = [], toasts = [];
  const label = () => ({textContent:'', classList:{add(){},remove(){}}});
  const document = {
    hidden:false,
    querySelector: () => ({dataset:{cooldownUrl:'/policy/'}}),
    addEventListener: (key, fn) => events.set(`document:${key}`, fn),
    removeEventListener: key => events.delete(`document:${key}`),
    createElement() {
      const strong = label(), feedback = label();
      const button = {disabled:true, attrs:{}, setAttribute(k,v){this.attrs[k]=v;}, querySelector(){return strong;}, addEventListener(k,v){this[k]=v;}};
      const card = {isConnected:true, button,strong,feedback,querySelector(k){return k === 'button' ? button : feedback;}};
      cards.push(card); return card;
    },
  };
  const window = {addEventListener:(key,fn)=>events.set(`window:${key}`,fn),removeEventListener:key=>events.delete(`window:${key}`)};
  const context = vm.createContext({window,document,setInterval:fn=>{timers.add(fn);return fn;},clearInterval:fn=>timers.delete(fn)});
  vm.runInContext(source, context);
  const mount = () => {
    cards.forEach(c => {c.isConnected=false;});
    window.ProxyCooldown.mount({querySelector:()=>({insertAdjacentElement(){}})}, {getJson,postJson,toast:(...args)=>toasts.push(args)});
    return cards.at(-1);
  };
  return {mount, events,timers,toasts,document};
}
test('verified default ON, save OFF and reconcile server state', async () => {
  let server = value(), body;
  const f = fixture(async()=>server, async(_url, payload)=>{body=payload;server=value(false,1);return server;});
  const card = f.mount(); await tick();
  assert.equal(card.strong.textContent,'ON'); assert.equal(card.button.disabled,false);
  await card.button.click();
  assert.equal(body.enabled,false); assert.equal(body.expected_revision,0);
  assert.equal(card.strong.textContent,'OFF'); assert.equal(card.button.attrs['aria-checked'],'false');
  assert.match(f.toasts[0][0],/OFF.*OPTIX and Dollar/);
});
test('read-only and unavailable states cannot change policy', async () => {
  let calls=0;
  const f=fixture(async()=>value(true,0,false),async()=>{calls++;});
  const card=f.mount(); await tick(); await card.button.click();
  assert.equal(card.button.disabled,true); assert.equal(calls,0);
  const fail=fixture(async()=>{throw new Error('service offline');});
  const failed=fail.mount(); await tick();
  assert.equal(failed.button.disabled,true); assert.equal(failed.strong.textContent,'Unavailable');
  assert.match(failed.feedback.textContent,/service offline/);
});
test('a failed or conflicting save does not show success and reloads authoritative value', async () => {
  let reads=0;
  const f=fixture(async()=>{reads++;return value(true,4);},async()=>{throw new Error('Policy changed');});
  const card=f.mount(); await tick(); await card.button.click();
  assert.equal(card.strong.textContent,'ON'); assert.equal(reads,2);
  assert.equal(f.toasts.length,1); assert.equal(f.toasts[0][1],true);
});
test('save is single-flight and old reads cannot overwrite newer state', async () => {
  let resolveRead,resolveSave,reads=0,saves=0,server=value();
  const f=fixture(()=>{if(++reads===2)return new Promise(r=>resolveRead=r);return Promise.resolve(server);},()=>{saves++;return new Promise(r=>resolveSave=r);});
  const card=f.mount(); await tick();
  f.events.get('window:focus')();
  const saving=card.button.click(); await card.button.click();
  assert.equal(saves,1); assert.equal(card.strong.textContent,'Saving…');
  server=value(false,1); resolveSave(server); await saving;
  resolveRead(value(true)); await tick();
  assert.equal(card.strong.textContent,'OFF');
});
test('focus synchronizes the other panel and route changes dispose polling', async () => {
  let server=value();
  const f=fixture(async()=>server); const first=f.mount(); await tick();
  server=value(false,1); f.events.get('window:focus')(); await tick();
  assert.equal(first.strong.textContent,'OFF');
  const second=f.mount(); await tick(); assert.equal(f.timers.size,1);
  second.isConnected=false; [...f.timers][0]();
  assert.equal(f.timers.size,0); assert.equal(f.events.size,0);
});
test('malformed success responses are not accepted', async () => {
  const f=fixture(async()=>({ok:true,policy:{enabled:'false',revision:0}}));
  const card=f.mount(); await tick();
  assert.equal(card.button.disabled,true); assert.equal(card.strong.textContent,'Unavailable');
});
