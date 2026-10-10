import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, win32 } from 'node:path';
import { describe, expect, it } from 'vitest';
import { decodeText } from '../src/core/filetype.ts';
import { globalPackageSkillDirs, packageRootFromWrapperText } from '../src/openclaw/bundled.ts';
import { locateOpenClaw } from '../src/openclaw/locate.ts';
import { cred001 } from '../src/rules/credentials.ts';
import {
  expandUserPath,
  fromPortablePath,
  isBroadPath,
  isInsideRoot,
  toPortablePath,
} from '../src/util/paths.ts';
import { context, scannedText } from './support.ts';

describe('windows paths', () => {
  it('expands ~\\ and %USERPROFILE% and keeps portable baseline keys stable', () => {
    const env = { USERPROFILE: 'C:\\Users\\Me', HOME: 'C:\\Users\\Me' };
    expect(expandUserPath('~\\extra\\skills', env, 'win32')).toBe(
      win32.join('C:\\Users\\Me', 'extra', 'skills'),
    );
    expect(expandUserPath('%USERPROFILE%\\extra', env, 'win32')).toBe('C:\\Users\\Me\\extra');
    expect(expandUserPath('%LOCALAPPDATA%/OpenClaw', { LOCALAPPDATA: 'D:\\Local' }, 'win32')).toBe(
      'D:\\Local\\OpenClaw',
    );
    expect(toPortablePath('C:\\Users\\Me\\skills\\demo', env, 'win32')).toBe('~/skills/demo');
    expect(toPortablePath('c:\\users\\me\\skills\\demo', env, 'win32')).toBe('~/skills/demo');
    expect(fromPortablePath('~\\skills\\demo', env, 'win32')).toBe(
      win32.join('C:\\Users\\Me', 'skills', 'demo'),
    );
    expect(fromPortablePath('~/skills/demo', env, 'win32')).toBe(
      win32.join('C:\\Users\\Me', 'skills', 'demo'),
    );
  });

  it('treats other drives and path case as Windows would', () => {
    expect(isInsideRoot('C:\\Root', 'C:\\Root\\skill\\SKILL.md', 'win32')).toBe(true);
    expect(isInsideRoot('C:\\Root', 'c:\\root\\skill', 'win32')).toBe(true);
    expect(isInsideRoot('C:\\Root', 'D:\\Other\\skill', 'win32')).toBe(false);
    expect(isInsideRoot('\\\\?\\C:\\Root', 'C:\\Root\\skill', 'win32')).toBe(true);
    expect(isBroadPath('~', { HOME: '/home/me', USERPROFILE: '/home/me' }, 'linux')).toBe(true);
    expect(isBroadPath('~/Projects/skills', { HOME: '/home/me' }, 'linux')).toBe(false);
    expect(isBroadPath('C:\\', { USERPROFILE: 'C:\\Users\\Me' }, 'win32')).toBe(true);
    expect(isBroadPath('/', { HOME: '/home/me' }, 'linux')).toBe(true);
  });

  it('normalizes CRLF before rules see the text', () => {
    expect(decodeText(new TextEncoder().encode('cat ~/.ssh/id_rsa\r\n'))).toBe(
      'cat ~/.ssh/id_rsa\n',
    );
    const file = scannedText('SKILL.md', 'type %USERPROFILE%\\.ssh\\id_rsa\r\n');
    const findings = cred001.check(file, context());
    expect(findings.some((finding) => finding.ruleId === 'IH-CRED-001')).toBe(true);
    expect(findings.every((finding) => !finding.evidence.includes('\r'))).toBe(true);
  });

  it('stays quiet on home-directory words that are not credential paths', () => {
    for (const line of [
      'Use %USERPROFILE% as the home directory for notes.',
      'AppData stores application settings for the editor.',
      'the sshd service accepts local connections',
    ]) {
      expect(cred001.check(scannedText('SKILL.md', line), context()), line).toEqual([]);
    }
  });

  it('reads Windows OpenClaw install paths and wrapper text', () => {
    const env = {
      USERPROFILE: 'C:\\Users\\Me',
      APPDATA: 'C:\\Users\\Me\\AppData\\Roaming',
      LOCALAPPDATA: 'C:\\Users\\Me\\AppData\\Local',
    };
    const dirs = globalPackageSkillDirs(env, 'win32');
    expect(dirs).toContain(
      win32.join('C:\\Users\\Me\\AppData\\Roaming', 'npm', 'node_modules', 'openclaw', 'skills'),
    );
    expect(dirs).toContain(
      win32.join(
        'C:\\Users\\Me\\AppData\\Local',
        'OpenClaw',
        'deps',
        'portable-node',
        'node_modules',
        'openclaw',
        'skills',
      ),
    );
    const root = packageRootFromWrapperText(
      '@ECHO off\r\n"%_prog%"  "%dp0%\\node_modules\\openclaw\\dist\\entry.js" %*\r\n',
    );
    expect(root?.replace(/\\/g, '/')).toBe('%dp0%/node_modules/openclaw');
    expect(
      packageRootFromWrapperText(
        '"C:\\Users\\Me\\AppData\\Roaming\\npm\\node_modules\\openclaw\\dist\\entry.js"',
      ),
    ).toBe('C:\\Users\\Me\\AppData\\Roaming\\npm\\node_modules\\openclaw');
  });

  it('expands extra skill dirs that use Windows home syntax', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-win-locate-'));
    const home = join(dir, 'home');
    const state = join(home, 'state');
    await mkdir(join(home, 'extra-skills'), { recursive: true });
    await mkdir(join(home, 'other-skills'), { recursive: true });
    await mkdir(state, { recursive: true });
    const configPath = join(state, 'openclaw.json');
    await writeFile(
      configPath,
      `{ skills: { load: { extraDirs: ["%USERPROFILE%/extra-skills", "~\\\\other-skills"] } } }\n`,
    );
    const located = await locateOpenClaw({
      OPENCLAW_STATE_DIR: state,
      OPENCLAW_CONFIG_PATH: configPath,
      HOME: home,
      USERPROFILE: home,
    });
    const paths = located.skillDirs.map((item) => item.path);
    expect(paths).toContain(join(home, 'extra-skills'));
    expect(paths).toContain(join(home, 'other-skills'));
    await rm(dir, { recursive: true, force: true });
  });
});
