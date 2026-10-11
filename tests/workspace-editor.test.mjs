import test from 'node:test';
import assert from 'node:assert/strict';
import { mountEditor } from '../frontend/workspace-editor.mjs';

async function fixture(t, { failSave = false, waitOpen = false } = {}) {
  const previous = new Map();
  const install = (key,value) => { previous.set(key,Object.getOwnPropertyDescriptor(globalThis,key)); Object.defineProperty(globalThis,key,{value,configurable:true}); };
  const target = new EventTarget(), frames = [], calls = [], storage = new Map();
  let child, epoch, readyResolve, openResolve;
  const ready = new Promise(resolve => {readyResolve=resolve});
  let graph = {nodes:[],links:[]};
  install('window',target);
  install('location',{origin:'https://studio.invalid'});
  install('sessionStorage',{getItem:key=>storage.get(key),setItem:(key,value)=>storage.set(key,value)});
  install('MutationObserver',class {observe(){} disconnect(){}});
  install('navigator',{locks:{request:async (_key,_options,fn)=>fn({})}});
  install('document',{documentElement:{dataset:{theme:'light'}},createElement(){
    const frame = {hidden:true,inert:false,setAttribute(){},remove(){this.removed=true},contentWindow:{postMessage(init,_origin,ports){
      child=ports[0];epoch=init.epoch;
      child.onmessage=({data})=>{
        if(data.kind==='workflow')child.postMessage({kind:'workflow-result',epoch,id:data.id,ok:true,value:{workflow:graph}});
      };
      child.postMessage({kind:'event',type:'ready',epoch});
    }}};
    frames.push(frame);return frame;
  }});
  const request = async (action,body,signal) => {
    calls.push({action,body,signal});
    if (action==='open') {
      if(waitOpen) await new Promise(resolve=>{openResolve=resolve});
      return Response.json({session_id:'editor-lease',version:0,graph:{nodes:[],links:[]}});
    }
    if(action==='draft' && failSave) throw Object.assign(Error('offline'),{status:503});
    return Response.json(action==='draft'?{version:1}:{});
  };
  const editor=mountEditor({instanceId:'instance-one',request,assetURL:name=>'/immutable/'+name,
    onStatus:state=>{if(state==='ready')readyResolve()},container:{replaceChildren(frame){
      const event=new Event('message');Object.assign(event,{source:frame.contentWindow,data:{channel:'vf-comfyui',kind:'hello'}});
      target.dispatchEvent(event);
    }}});
  t.after(()=>{editor.dispose();child?.close();for(const [key,descriptor]of previous){if(descriptor)Object.defineProperty(globalThis,key,descriptor);else delete globalThis[key];}});
  if(!waitOpen)await ready;
  else await new Promise(resolve=>setImmediate(resolve));
  return {editor,calls,frames,setGraph:value=>{graph=value},finishOpen:()=>openResolve()};
}

test('App-owned editor saves the latest graph before releasing its lease; never stops the instance',async t=>{
  const f=await fixture(t);
  f.setGraph({nodes:[{id:1,type:'Note'}],links:[]});
  await f.editor.close();
  assert.deepEqual(f.calls.map(call=>call.action),['open','renew','draft','close']);
  assert.equal(f.calls[2].body.graph.nodes[0].type,'Note');
  assert.equal(f.frames[0].removed,true);
  assert.equal(f.frames[0].src,'/immutable/vf-embed.html#parent_origin=https%3A%2F%2Fstudio.invalid');
});

test('failed save vetoes close and keeps the editing frame available',async t=>{
  const f=await fixture(t,{failSave:true});
  f.setGraph({nodes:[{id:1}],links:[]});
  await assert.rejects(f.editor.close(),/offline/);
  assert.equal(f.calls.some(call=>call.action==='close'),false);
  assert.equal(f.frames[0].removed,undefined);
  assert.equal(f.frames[0].inert,false);
});

test('closing during an unfinished open cancels it and a late response cannot mount an editor',async t=>{
  const f=await fixture(t,{waitOpen:true});
  await f.editor.close();
  assert.equal(f.calls[0].signal.aborted,true);
  f.finishOpen();await new Promise(resolve=>setImmediate(resolve));
  assert.equal(f.frames.length,0);
  assert.deepEqual(f.calls.map(call=>call.action),['open']);
});
