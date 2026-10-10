import { chmod, mkdir, open, rename, rm, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { redactSecrets } from './redact.ts';
import type { AuditEvent, GuardLogOptions } from './types.ts';

/**
 * Append-only JSONL audit log. The current file is only appended until it
 * crosses maxBytes, then it is renamed aside. A user who can write the
 * ironheights home directory can still edit or delete the log. Rotation
 * keeps at most maxFiles files, including the current one.
 */

let queue: Promise<void> = Promise.resolve();

export async function appendAuditEvent(event: AuditEvent, options: GuardLogOptions): Promise<void> {
  const line = `${JSON.stringify(redactEvent(event))}\n`;
  const run = queue.then(() => writeLine(line, options));
  queue = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

export async function readAuditTail(path: string, tail: number): Promise<AuditEvent[]> {
  const text = await readTailText(path, 256 * 1024);
  const events: AuditEvent[] = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line) as unknown;
      if (isAuditEvent(parsed)) events.push(parsed);
    } catch {
      continue;
    }
  }
  if (tail <= 0) return [];
  return events.slice(-tail);
}

export function isAuditEvent(value: unknown): value is AuditEvent {
  if (!value || typeof value !== 'object') return false;
  const record = value as Record<string, unknown>;
  return (
    record.schemaVersion === 1 &&
    typeof record.time === 'string' &&
    (record.kind === 'decision' ||
      record.kind === 'policy-error' ||
      record.kind === 'guard-error') &&
    (record.mode === 'monitor' || record.mode === 'enforce') &&
    (record.action === 'allow' || record.action === 'block') &&
    typeof record.wouldBlock === 'boolean' &&
    typeof record.tool === 'string' &&
    Array.isArray(record.ruleIds) &&
    Array.isArray(record.allowIds) &&
    typeof record.reason === 'string'
  );
}

function redactEvent(event: AuditEvent): AuditEvent {
  return {
    ...event,
    reason: redactSecrets(event.reason),
    ...(event.skill ? { skill: redactSecrets(event.skill) } : {}),
  };
}

async function writeLine(line: string, options: GuardLogOptions): Promise<void> {
  const dir = dirname(options.path);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  try {
    await chmod(dir, 0o700);
  } catch {
    // The directory may be owned in a way chmod cannot change. Keep going.
  }
  const maxBytes = clamp(options.maxBytes, 4096, 50_000_000);
  const maxFiles = clamp(options.maxFiles, 1, 20);
  let size = 0;
  try {
    size = (await stat(options.path)).size;
  } catch {
    size = 0;
  }
  if (size > 0 && size + line.length > maxBytes) {
    await rotate(options.path, maxFiles);
  }
  const handle = await open(options.path, 'a', 0o600);
  try {
    await handle.writeFile(line);
  } finally {
    await handle.close();
  }
  try {
    await chmod(options.path, 0o600);
  } catch {
    // Best effort. The open mode already requested 0600 on create.
  }
}

async function rotate(path: string, maxFiles: number): Promise<void> {
  const archives = maxFiles - 1;
  if (archives <= 0) {
    await rm(path, { force: true });
    return;
  }
  await rm(archivePath(path, archives), { force: true });
  for (let index = archives - 1; index >= 1; index -= 1) {
    await renameIfExists(archivePath(path, index), archivePath(path, index + 1));
  }
  await renameIfExists(path, archivePath(path, 1));
}

function archivePath(path: string, index: number): string {
  const dir = dirname(path);
  const base = path.slice(dir.length + 1).replace(/\.jsonl$/, '');
  return join(dir, `${base}.${index}.jsonl`);
}

async function renameIfExists(from: string, to: string): Promise<void> {
  try {
    await rename(from, to);
  } catch {
    // Missing source is fine. A failed rename leaves the current file in place.
  }
}

async function readTailText(path: string, maxBytes: number): Promise<string> {
  let size = 0;
  try {
    size = (await stat(path)).size;
  } catch {
    return '';
  }
  const start = Math.max(0, size - maxBytes);
  const handle = await open(path, 'r');
  try {
    const length = size - start;
    const buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, start);
    const text = buffer.toString('utf8');
    if (start === 0) return text;
    const newline = text.indexOf('\n');
    return newline === -1 ? '' : text.slice(newline + 1);
  } finally {
    await handle.close();
  }
}

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, Math.floor(value)));
}
