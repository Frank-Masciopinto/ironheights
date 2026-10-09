import { chmod, mkdir, open, rename } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';

/** Write via a temp file in the same directory, then rename. Mode defaults to 0600. */
export async function writeAtomic(filePath: string, data: string, mode = 0o600): Promise<void> {
  const dir = dirname(filePath);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const tmp = join(dir, `.${basename(filePath)}.${process.pid}.${Date.now()}.tmp`);
  const handle = await open(tmp, 'w', mode);
  try {
    await handle.writeFile(data);
    await handle.chmod(mode);
  } finally {
    await handle.close();
  }
  await rename(tmp, filePath);
  await chmod(filePath, mode);
}
