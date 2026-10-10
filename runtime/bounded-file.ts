// Public artifact reads only. Keep allocation bounded even if a file grows.
import {open} from 'node:fs/promises';

export async function boundedFile(path: string, maximum: number): Promise<Uint8Array> {
  if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > 128 * 1024 * 1024) {
    throw new Error('Artifact file bound');
  }
  const file = await open(path, 'r');
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > maximum) throw new Error('Artifact file bound');
    // One sentinel byte detects growth without an unbounded readFile allocation.
    const data = new Uint8Array(stat.size + 1);
    let offset = 0;
    while (offset < data.length) {
      const {bytesRead} = await file.read(data, offset, data.length - offset, null);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    if (offset !== stat.size) throw new Error('Artifact changed while reading');
    return data.slice(0, offset);
  } finally {
    await file.close();
  }
}
