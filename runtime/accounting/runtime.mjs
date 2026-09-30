// Account policy binding; cryptographic mechanics live in the shared LGPL leaf.
import { loadArtifacts, withPinnedBrowserWasm } from './artifacts.mjs';
import { validateStatement } from './statement.mjs';
import { createVerifier } from '@corbet-labs/czkp/verify';
export async function createAccountVerifier(options) {
  const browser=typeof globalThis.window!=='undefined'||typeof globalThis.WorkerGlobalScope!=='undefined';
  if(browser&&(globalThis.crossOriginIsolated!==true||typeof globalThis.SharedArrayBuffer!=='function')) throw new Error('Cross-origin isolation required');
  const artifacts=await loadArtifacts({...options,loadBrowserWasm:browser,loadPeerReservation:false});
  return createVerifier({artifacts,publicInputs:validateStatement,
    browserFactory:async backendOptions=>{
      const { Barretenberg }=await import('@aztec/bb.js');
      return withPinnedBrowserWasm(artifacts.browserWasm,wasmPath=>Barretenberg.new({...backendOptions,wasmPath}));
    }});
}
