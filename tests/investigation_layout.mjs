// Optional real-browser check against the isolated investigation fixture only.
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
const socket = new WebSocket('ws://127.0.0.1:9224/session');
await new Promise((resolve,reject) => {
  socket.addEventListener('open',resolve,{once:true});
  socket.addEventListener('error',reject,{once:true});
});
let sequence=0;
const pending=new Map();
function command(method,params) {
  const id=++sequence;
  return new Promise((resolve,reject) => {
    pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));
  });
}
socket.addEventListener('message',({data}) => {
  const message=JSON.parse(data);
  const callback=pending.get(message.id);
  if(callback) {
    pending.delete(message.id);
    message.type==='error' ? callback.reject(new Error(message.message)) : callback.resolve(message.result);
  } else if(message.method==='network.authRequired') {
    command('network.continueWithAuth',{
      request:message.params.request.request,action:'provideCredentials',
      credentials:{type:'password',username:'netwatch',password:'isolated-browser-fixture-password'},
    }).catch(()=>{});
  }
});
const timer=setTimeout(()=>{socket.close();process.exit(1);},45000);
try {
  await command('session.new',{capabilities:{alwaysMatch:{}}});
  await command('session.subscribe',{events:['network.authRequired']});
  await command('network.addIntercept',{phases:['authRequired']});
  const {context}=await command('browsingContext.create',{type:'tab'});
  const report=[];
  for(const width of [360,390,430,1200]) {
    await command('browsingContext.setViewport',{context,viewport:{width,height:1000}});
    await command('browsingContext.navigate',{
      context,url:'http://127.0.0.1:18765/device/1',wait:'complete',
    });
    const result=await command('script.evaluate',{
      target:{context},awaitPromise:false,
      expression:`JSON.stringify({
        width:innerWidth,scrollWidth:document.documentElement.scrollWidth,
        text:document.querySelector('#investigation').textContent,
        form:document.querySelector('[data-investigation-form]').getAttribute('method'),
        csrf:!!document.querySelector('[data-investigation-form] input[name=csrf_token]').value,
        activeUnchecked:!document.querySelector('[data-investigation-form] input[name=active]').checked,
        button:(()=>{const r=document.querySelector('[data-investigation-form] button').getBoundingClientRect();return {width:r.width,height:r.height,left:r.left,right:r.right};})(),
        reviewAfter:!!(document.querySelector('#investigation').compareDocumentPosition(document.querySelector('#name')) & Node.DOCUMENT_POSITION_FOLLOWING),
        evidenceFits:[...document.querySelectorAll('#investigation dd')].every(e=>e.getBoundingClientRect().right<=innerWidth),
      })`,
    });
    assert.equal(result.type,'success');
    const geometry=JSON.parse(result.result.value);
    assert(geometry.scrollWidth<=geometry.width+1,'No horizontal page overflow');
    assert(geometry.evidenceFits,'Evidence fits the viewport');
    assert(geometry.text.includes('Complete') && geometry.text.includes('Streaming device'));
    assert(geometry.text.includes('Possible match with'));
    assert.equal(geometry.form,'post');assert(geometry.csrf && geometry.reviewAfter && geometry.activeUnchecked);
    if(width <= 700) assert(geometry.button.width>=44 && geometry.button.height>=44);
    assert(geometry.button.left>=0 && geometry.button.right<=geometry.width);
    const {text,...safeGeometry}=geometry;report.push(safeGeometry);
    if(width===390) {
      const shot=await command('browsingContext.captureScreenshot',{context,origin:'document'});
      writeFileSync('data/validation/investigation-mobile.png',Buffer.from(shot.data,'base64'),{mode:0o600});
    }
  }
  writeFileSync('data/validation/investigation-layout.json',JSON.stringify(report,null,2),{mode:0o600});
  console.log('Browser layout passed at 360, 390, 430 and 1200px; forms, evidence and review controls fit.');
} finally {await command('session.end',{}).catch(()=>{});clearTimeout(timer);socket.close();}
