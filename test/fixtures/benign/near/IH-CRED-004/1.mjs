import { chmod, mkdir, writeFile } from 'fs/promises';
const CONFIG_DIR = 'cfg';
const CONFIG_FILE = 'cfg/token.json';
const config = {};
await mkdir(CONFIG_DIR, { recursive: true, mode: 0o700 });
await writeFile(CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });
await chmod(CONFIG_FILE, 0o600).catch(() => {});
