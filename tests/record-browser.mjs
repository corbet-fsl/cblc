// CI-only real cross-origin vault frame. Private fictional witness remains in
// memory; only browser capability observations and timings are retained.
import assert from 'node:assert/strict';
import {createServer} from 'node:https';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {spawn,execFileSync} from 'node:child_process';
import {once} from 'node:events';
import {resolve,join,extname} from 'node:path';
import {tmpdir} from 'node:os';
import {gunzipSync} from 'node:zlib';
import {isolationHeaders,vaultFrameAllow} from '../.g2-vault/hosting/isolation.mjs';

let built;
async function build() {
  if(built)return built;
  if(!process.env.CI)throw new Error('CI only');
  const root=resolve('experiments/private-accounting');
  built=resolve(process.env.CBLC_DIAGNOSTIC_OUTPUT,'record-browser-dist');
  execFileSync(process.execPath,[resolve(root,'node_modules/vite/bin/vite.js'),'build','--outDir',built],
    {cwd:root,env:{...process.env,RECORD_PROOF_BROWSER:'1'},stdio:'inherit',timeout:120000});
  return built;
}
export async function measureRecordBrowser(artifacts,witness) {
  const loaded=await artifacts.loadSetup(false);
  const root=await build(),scratch=await mkdtemp(join(tmpdir(),'record-browser-'));
  const binaries={};
  for(const name of ['barretenberg','barretenberg-threads']){
    const source=await readFile(resolve('node_modules/@aztec/bb.js/dest/browser/barretenberg_wasm/fetch_code/browser',name+'.js'),'utf8');
    const embedded=/^const barretenberg = "data:application\/gzip;base64,([A-Za-z0-9+/]+={0,2})";\s*export default barretenberg;\s*$/.exec(source);
    if(!embedded)throw new Error('Upstream browser Wasm asset layout changed');
    binaries['/'+name+'.wasm']=gunzipSync(Buffer.from(embedded[1],'base64'),{maxOutputLength:128*1024*1024});
  }
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(scratch,'key.pem'),'-out',join(scratch,'cert.pem'),
    '-days','1','-subj','/CN=community.example.test'],{stdio:'ignore',timeout:10000});
  let mode,community,vault,browser,socket;
  const server=createServer({key:await readFile(join(scratch,'key.pem')),cert:await readFile(join(scratch,'cert.pem'))},async(req,res)=>{
    try {
      const isVault=req.headers.host===new URL(vault).host;
      const headers=mode==='fallback'?{}:isolationHeaders(community,vault,{vault:isVault});
      res.writeHead(200,{...headers,'Cache-Control':'no-store','Content-Type':req.url==='/'||req.url==='/record-browser.html'?'text/html':req.url?.endsWith('.wasm')?'application/wasm':req.url?.endsWith('.js')?'text/javascript':'application/octet-stream'});
      if(!isVault){
        res.end(`<!doctype html><iframe id="vault" allow="${vaultFrameAllow}" src="${vault}/record-browser.html"></iframe><script>
          addEventListener('message',event=>{if(event.origin===${JSON.stringify(vault)}&&event.source===document.getElementById('vault').contentWindow)window.result=event.data;});</script>`);return;
      }
      if(req.url==='/input'){
        res.end(JSON.stringify({artifacts:{circuit:artifacts.circuit,circuitKind:artifacts.circuitKind,manifest:artifacts.manifest,limits:artifacts.limits,verificationKey:Array.from(artifacts.verificationKey)},
          witness,threads:mode==='fallback'?8:Number(mode),expectedThreads:mode==='fallback'?1:Number(mode)}));return;
      }
      if(req.url==='/setup/g2.dat'){res.end(loaded.setup['g2.dat']);return;}
      if(req.url===`/setup/g1-${loaded.numPoints}.dat`){res.end(loaded.setup['g1.dat']);return;}
      if(req.url==='/barretenberg.wasm'||req.url==='/barretenberg-threads.wasm'){
        res.end(binaries[req.url]);return;
      }
      const file=resolve(root,'.'+decodeURIComponent(req.url));
      if(!file.startsWith(root+'/')||!['.html','.js','.css'].includes(extname(file)))throw new Error('Route refused');
      res.end(await readFile(file));
    }catch{res.destroy();}
  });
  try {
    server.listen(0,'127.0.0.1');await once(server,'listening');
    const port=server.address().port;
    community=`https://community.example.test:${port}`;vault=`https://vault.community.example.test:${port}`;
    const results=[];
    for(mode of ['1','2','4','8','fallback']) {
      const profile=join(scratch,mode);
      browser=spawn(process.env.BROWSER_BIN??'chromium',['--headless','--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--no-proxy-server',
        '--ignore-certificate-errors','--host-resolver-rules=MAP community.example.test 127.0.0.1, MAP vault.community.example.test 127.0.0.1',
        '--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'],{stdio:['ignore','ignore','pipe']});
      const debug=await new Promise((resolve,reject)=>{
        const timer=setTimeout(()=>reject(new Error('Browser startup timeout')),15000);
        browser.once('exit',()=>{clearTimeout(timer);reject(new Error('Browser startup failed'));});
        browser.stderr.on('data',chunk=>{const found=String(chunk).match(/DevTools listening on (ws:\/\/[^\s]+)/);if(found){clearTimeout(timer);resolve(found[1]);}});
      });
      const endpoint=new URL(debug);
      const page=await (await fetch(`http://${endpoint.host}/json/new?${encodeURIComponent(community)}`,{method:'PUT'})).json();
      socket=new WebSocket(page.webSocketDebuggerUrl);await once(socket,'open');
      let sequence=0;const pending=new Map();
      socket.addEventListener('message',event=>{const response=JSON.parse(event.data);if(response.id){const resolve=pending.get(response.id);pending.delete(response.id);resolve?.(response);}});
      const command=(method,params)=>new Promise(resolve=>{const id=++sequence;pending.set(id,resolve);socket.send(JSON.stringify({id,method,params}));});
      const deadline=Date.now()+180000;let result;
      while(Date.now()<deadline){
        const response=await Promise.race([command('Runtime.evaluate',{expression:'window.result',returnByValue:true}),
          new Promise((_,reject)=>setTimeout(()=>reject(new Error('Browser command timeout')),5000))]);
        result=response.result?.result?.value;
        if(result)break;
        await new Promise(resolve=>setTimeout(resolve,250));
      }
      assert(result?.ok,JSON.stringify(result??{error:'Browser proof timeout'}));
      assert.equal(result.isolated,mode!=='fallback');
      assert.equal(result.sharedArrayBuffer,mode!=='fallback');
      results.push({mode,...result});
      socket.close();socket=undefined;
      const closed=once(browser,'exit');browser.kill('SIGTERM');await closed;browser=undefined;
    }
    return results;
  } finally {
    socket?.close();
    if(browser&&browser.exitCode===null){const closed=once(browser,'exit');browser.kill('SIGKILL');await closed;}
    server.closeAllConnections();await new Promise(resolve=>server.close(resolve));
    await rm(scratch,{recursive:true,force:true});
  }
}
