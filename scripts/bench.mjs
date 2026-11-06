// One-command public benchmark. Downloads pinned inputs, checks SHA-256, scans,
// and writes per-sample verdicts plus a summary. Nothing in the skill text is executed.
// The model column is recorded as not-run: this command does not call a model.
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(root, 'dist', 'cli', 'index.js');
const out = join(root, 'bench', 'results', 'public');
const venvPy = join(root, '.venv', 'bin', 'python');
const req = join(root, 'bench', 'msb', 'requirements.txt');

if (!existsSync(cli)) {
  console.error('dist/cli/index.js is missing. Run npm run build first.');
  process.exit(1);
}

if (!existsSync(venvPy)) {
  const made = spawnSync('python3', ['-m', 'venv', join(root, '.venv')], {
    cwd: root,
    stdio: 'inherit',
  });
  if (made.status !== 0) process.exit(made.status ?? 1);
  const pip = spawnSync(
    venvPy,
    ['-m', 'pip', 'install', '--require-hashes', '--only-binary=:all:', '-r', req],
    { cwd: root, stdio: 'inherit' },
  );
  if (pip.status !== 0) process.exit(pip.status ?? 1);
}

const run = spawnSync(venvPy, [join(root, 'scripts', 'benchmark-msb.py'), cli, out], {
  cwd: root,
  stdio: 'inherit',
});
process.exit(run.status ?? 1);
