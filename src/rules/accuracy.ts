import type { Finding, Rule, ScannedFile, Severity } from '../core/types.ts';
import { eachLine, fencedLineNumbers } from '../util/text.ts';
import { createFinding, pushUnique } from './helpers.ts';

/**
 * 0.10.0 accuracy rules, built from real ClawHub examples reported on Moltbook.
 * IH-CRED-004 credential file left readable by others, IH-CRED-005 secret in a URL,
 * IH-EXEC-004 switch that turns off confirmations or agent approvals.
 */

const TEST_PATH = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?)\//i;

// ---------------------------------------------------------------- IH-CRED-004

/** Names that point at a file holding a secret. */
const CRED_NAME =
  /(?:token|credential|secret|api[_-]?key|apikey|password|passwd|\.env\b|\.netrc|cookies?\.json|auth[\w.-]*\.json|session[\w-]*\.json|oauth|private[_-]?key)/i;
/** File-writing calls in JS/TS/Python/PowerShell; the target is the first argument. */
const API_WRITE =
  /\b(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|Set-Content|Out-File)\s*\(\s*([^,)\n]{1,200})|\bopen\s*\(\s*([^,)\n]{1,200}),\s*["'](?:w|wb|a|w\+|x)["']|([\w.()"'/~-]{1,200})\.write_(?:text|bytes)\s*\(/;
/** Shell redirect or tee into a path-like target. */
const SHELL_REDIRECT =
  /(?:^|[\s;|&])(?:>{1,2}|tee\s+(?:-a\s+)?)\s*["']?((?:~|\$\{?\w+\}?|\.{0,2}\/|\.)[\w$./{}~-]*|[\w-]+\.(?:json|env|txt|key|pem|token))/;
const SHELL_FILE = /\.(?:sh|bash|zsh|ksh)$/i;
const SECRET_VAR = /\$\{?\w*(?:TOKEN|KEY|SECRET|PASS(?:WORD)?)\w*\}?/;
/** Anything in the file that sets owner-only permissions. */
const PROTECT =
  /0o?[46]00\b|\b0[46]00\b|\bchmod\s+(?:-\w+\s+)?(?:0?[46]00|go-|og-|u=rw,go=|600)|umask\s*\(?\s*(?:0o?)?0?77|\binstall\s+(?:-\w+\s+)*-m\s*0?600|mkstemp|mkdtemp|fchmod|S_IRUSR|S_IWUSR|keyring|keychain|secret[- ]?store/i;
const RENAME =
  /\b(?:renameSync|rename|os\.replace|os\.rename|shutil\.move|Move-Item)\s*\(|^\s*mv\s/;
const ARCHIVE =
  /\b(?:tar|zip|7z|rsync|cp\s+-\w*[rRa]\w*|shutil\.make_archive|tarfile\.open|make_archive|Compress-Archive)\b/;
/** The whole agent home, its credentials, ~/.ssh or a .env as the thing being archived. */
const ARCHIVE_SOURCE =
  /(?:~|\$HOME|\$\{HOME\})\/\.(?:openclaw|clawdbot|moltbot)\/?(?=["'\s]|$)|\s\.(?:openclaw|clawdbot|moltbot)\/?(?=["'\s]|$)|\.(?:openclaw|clawdbot)\/(?:credentials|agents|openclaw\.json)|(?:~|\$HOME)\/\.ssh\b|\/credentials(?:\.json)?(?=["'\s/]|$)/i;

export const cred004: Rule = {
  id: 'IH-CRED-004',
  title: 'Credential file readable by others',
  category: 'credentials',
  severity: 'medium',
  priority: 'P1',
  description:
    'A token, key, or session file written without owner-only permissions (mode 600 / umask 077) is created 644 under the usual umask 022, so other local users and processes can read it. Saving through a temp file and rename resets an earlier chmod 600, and backup archives of ~/.openclaw or credentials made without umask 077 are world-readable.',
  remediation:
    'Create the file owner-only: os.open(path, O_CREAT|O_WRONLY, 0o600) or writeFile(path, data, { mode: 0o600 }) plus chmod for existing files, umask 077 in shell scripts, and mkstemp before an atomic rename.',
  appliesTo: ['script', 'markdown'],
  examples: {
    matches: [
      'with open(TOKEN_CACHE, "w", encoding="utf-8") as f:',
      'echo "$API_KEY" > ~/.config/tool/token',
      'tar czf backup.tgz ~/.openclaw',
    ],
    nonMatches: [
      'await writeFile(CONFIG_FILE, data, { mode: 0o600 });',
      'with open("notes.txt", "w") as f:',
    ],
  },
  check: checkCred004,
};

function checkCred004(file: ScannedFile): Finding[] {
  const findings: Finding[] = [];
  const lines = file.text.split(/\r?\n/);
  const markdown = file.kind === 'markdown';
  if (TEST_PATH.test(file.relativePath)) return findings;
  const fenced = markdown ? fencedLineNumbers(file.text) : undefined;
  // In Markdown each fenced block is its own script; in a script the whole file counts.
  const protectedAt = (lineNumber: number): boolean => {
    if (!markdown) return PROTECT.test(file.text);
    let start = lineNumber;
    while (start > 1 && fenced?.has(start - 1)) start -= 1;
    let end = lineNumber;
    while (end < lines.length && fenced?.has(end + 1)) end += 1;
    return PROTECT.test(lines.slice(start - 1, end).join('\n'));
  };
  let lastProtect = 0;
  let firstCredWrite = 0;
  eachLine(file.text, (line, lineNumber) => {
    if (PROTECT.test(line)) lastProtect = lineNumber;
    if (markdown && !fenced?.has(lineNumber)) return;
    if (/^\s*(?:#|\/\/)/.test(line) && !/^\s*#!/.test(line)) return;
    if (ARCHIVE.test(line) && ARCHIVE_SOURCE.test(line) && !protectedAt(lineNumber)) {
      pushUnique(
        findings,
        createFinding(cred004, file, {
          line: lineNumber,
          evidence: line,
          message:
            'A backup or copy of credentials is made without umask 077 or chmod 600, so the archive is readable by other users.',
          confidence: 'medium',
        }),
      );
      return;
    }
    const shell =
      markdown ||
      SHELL_FILE.test(file.relativePath) ||
      /^#!.*\b(?:ba|z|k)?sh\b/.test(lines[0] ?? '');
    const write = shell ? SHELL_REDIRECT.exec(line) : API_WRITE.exec(line);
    if (!write) return;
    const target = write[1] ?? write[2] ?? write[3] ?? '';
    const command = line.replace(/^.*(?:&&|;)\s*/, '');
    const secretValue = /^\s*(?:echo|printf|cat)\b/.test(command) && SECRET_VAR.test(line);
    if (!CRED_NAME.test(target) && !(secretValue && /[/~]/.test(target))) return;
    if (/\/dev\/null|\.gitignore|\.example\b|\.sample\b/.test(line)) return;
    if (/\b(?:readFile|open\s*\([^)]*["']r)/.test(line)) return;
    if (firstCredWrite === 0) firstCredWrite = lineNumber;
    if (protectedAt(lineNumber)) return;
    pushUnique(
      findings,
      createFinding(cred004, file, {
        line: lineNumber,
        evidence: line,
        message:
          'A credential file is written without mode 600 or umask 077; under the default umask it is created readable by other users.',
        confidence: 'medium',
      }),
    );
  });
  // chmod 600 first, then save through a temp file and rename: the new inode gets the default mode.
  if (!markdown && firstCredWrite > 0 && lastProtect > 0 && findings.length === 0) {
    if (!/mkstemp|fchmod|NamedTemporaryFile|os\.open\s*\([^)]*0o?600/i.test(file.text)) {
      eachLine(file.text, (line, lineNumber) => {
        if (lineNumber <= lastProtect || !RENAME.test(line)) return;
        pushUnique(
          findings,
          createFinding(cred004, file, {
            line: lineNumber,
            evidence: line,
            severity: 'low',
            message:
              'The credential file is saved through a rename after its chmod 600; the renamed file gets the default mode (usually 644), which undoes the chmod.',
            confidence: 'low',
          }),
        );
      });
    }
  }
  return findings;
}

// ---------------------------------------------------------------- IH-CRED-005

const CRED_PARAM = String.raw`(?:key|api[_-]?key|apikey|access[_-]?token|token|auth[_-]?token|auth|secret|client[_-]?secret|password)`;
const CRED_VALUE = String.raw`(?:\$\{?|\{|<|%\(|\{\{\s*)?[\w.]*?(?:key|token|secret|pass)[\w.]*`;
const QUERY_SECRET = new RegExp(String.raw`[?&]${CRED_PARAM}=(${CRED_VALUE})`, 'i');
const USERINFO_SECRET = /\b[a-z][\w+.-]*:\/\/[^\s/:@'"]*:\$\{?\w*(?:TOKEN|KEY|PASS|SECRET)\w*\}?@/i;

export const cred005: Rule = {
  id: 'IH-CRED-005',
  title: 'Secret in a URL',
  category: 'credentials',
  severity: 'low',
  priority: 'P1',
  description:
    'An API key or token placed in a URL query string or in user:token@host lands in shell history, proxy and server logs, error messages, and stored git remotes.',
  remediation:
    'Send the key in a header (Authorization, x-api-key, x-goog-api-key) and use a credential helper instead of a token in a git remote URL.',
  appliesTo: ['markdown', 'script', 'config'],
  examples: {
    matches: [
      'curl "https://api.example.com/v1/data?key=$GEMINI_API_KEY"',
      'git remote add fork https://x-access-token:$GH_TOKEN@github.com/o/r.git',
    ],
    nonMatches: [
      'curl "https://api.example.com/price?token=ETH"',
      'curl -H "x-api-key: $KEY" https://api.example.com',
    ],
  },
  check(file) {
    const findings: Finding[] = [];
    let queryReported = false;
    eachLine(file.text, (line, lineNumber) => {
      const userinfo = USERINFO_SECRET.test(line);
      const query = QUERY_SECRET.exec(line);
      if (!userinfo && !query) return;
      // One query-string note per file is enough; every userinfo URL is its own stored copy.
      if (!userinfo) {
        if (queryReported) return;
        queryReported = true;
      }
      pushUnique(
        findings,
        createFinding(cred005, file, {
          line: lineNumber,
          evidence: line,
          severity: userinfo ? 'medium' : 'low',
          message: userinfo
            ? 'A token is expanded into the user:token@host part of a URL; a git remote stores it in .git/config.'
            : 'A credential is sent in a URL query string, where logs and history keep it.',
          confidence: 'medium',
        }),
      );
    });
    return findings;
  },
};

// ---------------------------------------------------------------- IH-EXEC-004

/** Switches that start a coding agent with approvals or the sandbox off. */
const AGENT_SWITCH =
  /(?:--yolo\b|--dangerously-skip-permissions\b|--dangerously-bypass-approvals-and-sandbox\b|\bbypassPermissions\b|--permission-mode[ =]bypassPermissions)/;
/** Generic confirm-off switches. --force alone is too common to count. */
const CONFIRM_SWITCH =
  /(?:--no-input\b|--non-interactive\b|--yes\b|--assume-yes\b|--auto-approve\b|--auto-confirm\b|\bauto_confirm\b|\bautoConfirm\b|\bauto_approve\b|\bauto_run\b)/;
const PACKAGE_MANAGER =
  /\b(?:apt|apt-get|dnf|yum|zypper|pacman|apk|npx|npm|pnpm|yarn|bun|pip3?|pipx|uv|conda|mamba|brew|choco|winget|scoop|gcloud|sdkmanager|terraform|tofu)\b/;
const RISKY =
  /\b(?:update|upgrade|delete|remove|rm|send|overwrite|publish|push|deploy|destroy|drop|transfer|pay)\b|--(?:all|force)\b/i;
const DELETE_VERB = /\b(?:delete|remove|rm|destroy|drop|purge|wipe|erase|uninstall)\b/i;
/** Prose that asks for confirmation before a destructive step ("confirm with the user before every DELETE"). */
const CONFIRM_RULE =
  /\b(?:confirm\w*|approv\w*|ask (?:the user|first|before)|explicit(?:ly)? (?:ok|consent|yes|approval)|last chance)\b/i;
const GUARD =
  /\b(?:never|do not|don't|dont|avoid|refuse|unless|only (?:when|if)|ask (?:the user|first)|confirm (?:with|first)|not recommended|wrong)\b|(?<!non-)\binteractive(?:ly)?\b/i;

export const exec004: Rule = {
  id: 'IH-EXEC-004',
  title: 'Confirmations or agent approvals switched off',
  category: 'exec',
  severity: 'high',
  priority: 'P1',
  description:
    'Launching a coding agent with --yolo, --dangerously-skip-permissions or bypassPermissions runs it with no approval step. Generic switches such as --no-input, --yes or auto_confirm skip the confirmation for updates, deletes or sends. A guard (never, do not, unless, only when, interactive) within 3 lines lowers the severity.',
  remediation:
    'Keep approvals on, or run the agent in a disposable sandbox or container, and say when the switch is allowed (for example: only in CI, never on the user machine).',
  appliesTo: ['markdown', 'script', 'config'],
  examples: {
    matches: [
      `tmux send-keys -t agent-1 "codex --yolo 'Fix bug X'" Enter`,
      'clawdhub update --all --no-input --force',
    ],
    nonMatches: [
      'npx --yes create-thing',
      'Never pass --yolo on the user machine.',
      'git push --force',
    ],
  },
  check(file) {
    const findings: Finding[] = [];
    const lines = file.text.split(/\r?\n/);
    const testPath = TEST_PATH.test(file.relativePath);
    // A prose line that names the switch together with a guard ("Do not pass `--yes` in an
    // interactive session") is a file-wide policy for that switch (Maton template, 65 skills).
    const fenced = file.kind === 'markdown' ? fencedLineNumbers(file.text) : undefined;
    const policy = new Set<string>();
    lines.forEach((line, index) => {
      if (fenced?.has(index + 1) || !GUARD.test(line)) return;
      const token = AGENT_SWITCH.exec(line)?.[0] ?? confirmSwitch(line);
      if (token) policy.add(token);
    });
    // 0.12.0: docs that tell the agent to confirm before deleting, while their own examples pass
    // --yes, -y or --force to a delete, contradict themselves (Maton template, 65 skills). The
    // example is what the agent copies, so it is a real finding and a prose guard elsewhere does
    // not demote it.
    const confirmDocs =
      policy.size > 0 ||
      lines.some(
        (line, index) =>
          !fenced?.has(index + 1) && CONFIRM_RULE.test(line) && DELETE_VERB.test(line),
      );
    eachLine(file.text, (line, lineNumber) => {
      const agent = AGENT_SWITCH.exec(line);
      const example = fenced?.has(lineNumber) === true;
      let confirm = agent ? undefined : confirmSwitch(line);
      const destructiveExample = !agent && example && confirmDocs && DELETE_VERB.test(line);
      if (!agent && !confirm && destructiveExample) {
        confirm = /(?:^|\s)(-y|--force)(?=\s|$)/.exec(line)?.[1];
      }
      if (!agent && !confirm) return;
      const window = lines.slice(Math.max(0, lineNumber - 4), lineNumber + 3).join('\n');
      const contradicts =
        destructiveExample &&
        !GUARD.test(line) &&
        !/\b(?:after|once) (?:verify|confirm|the user|approv)/i.test(line);
      const guarded = !contradicts && GUARD.test(window);
      let severity: Severity;
      if (agent) {
        // The agent follows SKILL.md commands itself, so fenced docs are not demoted here;
        // a shipped script that launches the agent is one step above any Markdown mention.
        if (guarded || testPath) severity = 'low';
        else severity = file.kind === 'markdown' ? 'medium' : 'high';
      } else {
        if (testPath) severity = 'info';
        else if (contradicts) severity = 'medium';
        else if (guarded) severity = 'info';
        else if (confirm && policy.has(confirm)) severity = 'low';
        else severity = RISKY.test(line) ? 'medium' : 'low';
      }
      pushUnique(
        findings,
        createFinding(exec004, file, {
          line: lineNumber,
          evidence: line,
          severity,
          message: agent
            ? `A coding agent is started with approvals off (${agent[0]}).${guarded ? ' A guard nearby limits when it is used.' : ''}`
            : contradicts
              ? `The docs say to confirm before deleting, but this example skips the confirmation (${confirm}). The agent copies examples.`
              : `A switch turns off confirmation (${confirm}).${guarded ? ' A guard nearby limits when it is used.' : ''}`,
          confidence: guarded ? 'low' : 'medium',
        }),
      );
    });
    return findings;
  },
};

/** Exported for IH-INJ-003, which leaves documented switches to this rule. */
export function confirmSwitch(line: string): string | undefined {
  const match = CONFIRM_SWITCH.exec(line);
  if (!match) return undefined;
  const before = line.slice(0, match.index);
  if (
    /^--(?:yes|assume-yes|non-interactive|no-input)$/.test(match[0]) &&
    PACKAGE_MANAGER.test(before)
  )
    return undefined;
  return match[0];
}

export function hasApprovalSwitch(line: string): boolean {
  return AGENT_SWITCH.test(line) || confirmSwitch(line) !== undefined;
}
