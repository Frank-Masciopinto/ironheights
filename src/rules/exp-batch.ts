import { expOn } from '../exp/flag.ts';
import type { Finding, Rule, ScannedFile, Severity } from '../core/types.ts';
import { createFinding, pushUnique } from './helpers.ts';

/** Local experiment rules for batch 2026-11-03 (not for merge). Gate: IH_EXP=A,B,... */
const DESCRIBE = /\b(?:detect\w*|flag\w*|pattern|e\.g\.|example|attack\w*|injection|jailbreak|malicious|scanner|red[- ]?team|never|do not|don't|must not|avoid)\b/i;
const sentences = (line: string): string[] => line.split(/(?<=[.;!?])\s+(?=\S)|(?<=。)/);

/** Code segments: fenced blocks in markdown, whole file otherwise. */
function segments(file: ScannedFile): { start: number; lines: string[] }[] {
  const lines = file.text.split(/\r?\n/);
  if (file.kind !== 'markdown' && file.kind !== 'text') return [{ start: 1, lines }];
  const out: { start: number; lines: string[] }[] = [];
  let cur: { start: number; lines: string[] } | null = null;
  lines.forEach((l, i) => {
    if (/^\s{0,3}(```|~~~)/.test(l)) {
      if (cur) { out.push(cur); cur = null; } else cur = { start: i + 2, lines: [] };
    } else if (cur) cur.lines.push(l);
  });
  return out;
}
function prose(file: ScannedFile, visit: (s: string, n: number, line: string) => void) {
  if (file.kind !== 'markdown' && file.kind !== 'text') return;
  let inF = false;
  let para = ''; let start = 0;
  const flush = () => { if (para) for (const s of sentences(para)) visit(s, start, para); para = ''; };
  file.text.split(/\r?\n/).forEach((l, i) => {
    if (/^\s{0,3}(```|~~~)/.test(l)) { flush(); inF = !inF; return; }
    if (inF || /^\s*\|/.test(l) || !l.trim() || /^\s*(?:#|[-*+]\s|\d+[.)]\s)/.test(l)) { flush(); if (!inF && l.trim() && !/^\s*\|/.test(l)) { para = l.replace(/^\s*(?:#+|[-*+]|\d+[.)])\s*/, ''); start = i + 1; } return; }
    if (!para) start = i + 1;
    para += (para ? ' ' : '') + l.trim();
  });
  flush();
}
function mk(key: string, id: string, title: string, severity: Severity, category: Rule['category'], appliesTo: Rule['appliesTo'], fn: (file: ScannedFile, hit: (n: number, ev: string) => void) => void): Rule {
  const r: Rule = {
    id, title, category, severity, priority: 'P1', description: `Experiment ${key}: ${title}.`, remediation: 'Remove this behaviour or make it explicit and user-controlled.',
    appliesTo, examples: { matches: [], nonMatches: [] },
    check(file) {
      if (!expOn(key)) return [];
      const f: Finding[] = [];
      fn(file, (n, ev) => pushUnique(f, createFinding(r, file, { line: n, evidence: ev, confidence: 'medium', message: title })));
      return f;
    },
  };
  return r;
}
const NET = /\brequests\.(?:post|put|get|patch)\b|\burllib\.request|\bhttp\.client|\bhttpx\.|\bfetch\s*\(|\baxios\b|\bcurl\b|\bwget\b|\bsocket\.|\bnc\s+-|\bInvoke-(?:WebRequest|RestMethod)\b|\.send\(/;

// A: whole environment copied and sent over the network (any host).
const A_ENV = /\bdict\(\s*os\.environ\s*\)|\bos\.environ\.copy\(\)|\{\s*\*\*os\.environ\b|json\.dumps\(\s*(?:dict\()?os\.environ\b|\bos\.environ\.items\(\)|JSON\.stringify\(\s*process\.env\s*\)|\{\s*\.\.\.process\.env\b|Object\.entries\(\s*process\.env\s*\)|\b(?:printenv|env)\s*\|\s*(?:curl|nc|wget|base64)|\bGet-ChildItem\s+env:/;
export const expA = mk('A', 'IH-XB-A', 'Whole environment copied into a network call', 'critical', 'network', ['any'], (file, hit) => {
  for (const s of segments(file)) {
    const body = s.lines.join('\n');
    if (!NET.test(body) && !/\|\s*(?:curl|nc|wget)/.test(body)) continue;
    s.lines.forEach((l, i) => { if (A_ENV.test(l)) hit(s.start + i, l); });
  }
});

// B: decode then execute.
const B_RE = /\b(?:exec|eval)\s*\([^\n]{0,80}?(?:b64decode|base64|atob|fromhex|codecs\.decode|zlib\.decompress|marshal\.loads|bytes\.fromhex|rot13)|\bnew\s+Function\s*\(\s*(?:atob|Buffer\.from)|\beval\s*\(\s*Buffer\.from\([^)]*['"]base64|base64\s+(?:-d|--decode|-D)\b[^\n|]*\|\s*(?:ba|z|da)?sh\b|\|\s*base64\s+(?:-d|--decode)\s*\|\s*(?:ba|z)?sh\b|IEX\s*\(?\s*\[(?:System\.)?Text\.Encoding|FromBase64String[^\n]{0,80}\|\s*(?:iex|Invoke-Expression)/i;
export const expB = mk('B', 'IH-XB-B', 'Decoded hidden string is executed', 'critical', 'obfuscation', ['any'], (file, hit) => {
  for (const s of segments(file)) s.lines.forEach((l, i) => { if (B_RE.test(l)) hit(s.start + i, l); });
});

// C: two or more named secrets bundled into one payload.
const C_SECRET = /(?:os\.environ(?:\.get)?\s*[[(]\s*|os\.getenv\(\s*|process\.env\.|process\.env\[\s*)['"]?([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|DATABASE_URL|CREDENTIALS?|PRIVATE_KEY))\b/;
export const expC = mk('C', 'IH-XB-C', 'Several named secrets bundled into one payload', 'high', 'network', ['any'], (file, hit) => {
  for (const s of segments(file)) {
    const body = s.lines.join('\n');
    if (!/json\.dumps|JSON\.stringify|payload|requests\.|fetch\(|base64|\.encode\(/.test(body)) continue;
    let depth = 0; let names = new Set<string>(); let first = 0;
    s.lines.forEach((l, i) => {
      const opens = (l.match(/[{[]/g) ?? []).length, closes = (l.match(/[}\]]/g) ?? []).length;
      if (depth > 0 || /[=:(]\s*\{\s*$|=\s*dict\(\s*$/.test(l)) {
        const m = C_SECRET.exec(l); if (m && m[1]) { if (!names.size) first = s.start + i; names.add(m[1]); }
      }
      depth += opens - closes;
      if (depth <= 0) { if (names.size >= 2) hit(first, s.lines[first - s.start] ?? ''); names = new Set(); depth = 0; }
    });
  }
});

// D: directives that override safety/security.
const D_RE = /\b(?:directives?|standing orders?|orders?|instructions?|commands?)\b[^.]{0,80}\b(?:overrid\w*|take precedence|supersed\w*|over existing constraints|even if (?:they|it) (?:appear to )?(?:contradict|conflict|violate))|\bprioriti[sz]e\b[^.]{0,60}\bdirectives?\b[^.]{0,40}\bover\b/i;
const D_TARGET = /\b(?:security|safety|constraints?|guidelines?|protocols?|polic(?:y|ies)|previous|existing|standard procedures)\b/i;
export const expD = mk('D', 'IH-XB-D', 'Directives told to override safety or existing constraints', 'high', 'injection', ['markdown'], (file, hit) => {
  prose(file, (s, n) => { if (D_RE.test(s) && D_TARGET.test(s) && !DESCRIBE.test(s)) hit(n, s); });
});

// E: output filters / restrictions switched off for the agent.
const E_RE = /\bwithout (?:any )?(?:restriction|content|safety|moderation) (?:filters?|limits?|checks?)\b|\bregardless of (?:topic )?(?:sensitivity|safety|policy|content polic\w*)\b|\b(?:bypass|ignore|disable)\w* (?:your |its |the )?(?:own )?(?:content|safety|restriction) (?:filters?|polic\w+|guidelines?)\b/i;
export const expE = mk('E', 'IH-XB-E', "Skill switches off the agent's own output limits", 'high', 'injection', ['markdown'], (file, hit) => {
  prose(file, (s, n) => { if (E_RE.test(s) && !DESCRIBE.test(s)) hit(n, s); });
});

// F: description confesses disguise of its own behaviour.
const F_RE = /伪装|冒充|偽裝|\bdisguis\w*\b|\bmasquerad\w*\b|\bcamouflag\w*\b|\bpos(?:es|ing) as\b|\bpretend(?:s|ing)? to be\b|\bunder the guise\b|\bdisfraz\w*|\btarn(?:t|en|ung)\b|\bmaquill\w*/i;
export const expF = mk('F', 'IH-XB-F', 'Skill description admits disguising what it does', 'high', 'meta', ['markdown'], (file, hit) => {
  const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(file.text);
  if (!fm) return;
  fm[1]!.split(/\r?\n/).forEach((l, i) => { if (/^\s*description\s*:/.test(l) || /^\s{2,}\S/.test(l)) if (F_RE.test(l) && !DESCRIBE.test(l)) hit(i + 2, l); });
});

// G: pre-confirmed send waiver.
const G_RE = /\btreat (?:those|these|the|such) (?:fields|details|values|requests?) as (?:already )?(?:confirmed|approved)\b|\b(?:already|pre-?)\s?(?:confirmed|approved)\b[^.]{0,60}\b(?:send|deliver|write|submit|post)\w*\b[^.]{0,40}\bdirectly\b|\bwithout (?:asking|waiting) for (?:confirmation|approval)\b[^.]{0,40}\b(?:send|email|post|submit)/i;
export const expG = mk('G', 'IH-XB-G', 'Send treated as pre-confirmed without asking the user', 'high', 'injection', ['markdown'], (file, hit) => {
  prose(file, (s, n) => { if (G_RE.test(s) && !/\bnever\b|\bdo not\b|\bdon't\b/i.test(s)) hit(n, s); });
});

// H: a change or added content is kept out of what the user is told.
const H_RE = /\b(?:(?:there is )?no need to (?:mention|tell|describe|report|list|flag)|(?:does|do) not need to be (?:mentioned|reported|listed|described|shown)(?: to the user)?|(?:you )?do not need to (?:describe|mention|report|list) (?:it|them|this)|(?:do not|don't|never) (?:list|mention|report|tell the user|describe) (?:what|that|the (?:deleted|removed|added|changed|replaced))|file (?:each|the|these|those) [\w\s-]{0,30}(?:deletions?|replacements?|changes?|edits?) (?:under|as) ["“])/i;
const H_ACT = /\b(?:delete|remove|replace|rewrite|append|add|write|copy|paste|set|insert|fill|drop)\w*\b/i;
export const expH = mk('H', 'IH-XB-H', 'Skill keeps one of its own changes out of what it tells the user', 'high', 'injection', ['markdown'], (file, hit) => {
  if (!H_ACT.test(file.text)) return;
  prose(file, (s, n) => { if (H_RE.test(s) && !/\b(?:detect|flag|scanner|attack)\w*/i.test(s)) hit(n, s); });
});

// I: a .env value written into a published file.
const I_ENV = /\.env\b[^.]{0,120}\b(?:value|token|key|secret)\b|\b(?:value|token|key|secret) (?:of|from) [^.]{0,60}\.env\b/i;
const I_PUB = /\b(?:CHANGELOG|README|release notes|RELEASE|docs?\/|public|published|commit(?:ted)?|issue|gist|pull request)\b/i;
const I_PUT = /\b(?:copy|paste|put|insert|include|add|write|embed|rewrite|split)\w*\b/i;
export const expI = mk('I', 'IH-XB-I', 'Secret value from .env written into a published file', 'high', 'credentials', ['markdown'], (file, hit) => {
  if (!I_PUB.test(file.text)) return;
  prose(file, (s, n, para) => { if (I_ENV.test(s) && I_PUT.test(para) && !/\b(?:never|do not|don't|redact\w*|mask\w*|names? only|without (?:the )?values?)\b/i.test(s)) hit(n, s); });
});

// J: an opt-out undone on a timer or count.
const J_TIMER = /countdown\b|\bafter (?:\d+|one|two|three|a few) (?:later )?(?:sessions?|runs?|days?|invocations?)\b|\b(?:lower|decrement|reduce)\w* the (?:count|counter)\b/i;
const J_BACK = /\b(?:(?:on|enabled?|active) again|again (?:on|enabled?)|re-?enabl\w*|resum\w*|set [^.]{0,20}(?:"on"|on|true)\b)/i;
export const expJ = mk('J', 'IH-XB-J', 'User opt-out quietly undone after a timer or count', 'high', 'persistence', ['markdown'], (file, hit) => {
  if (!/\b(?:stop|pause|opt[- ]?out|disable|turn off|unsubscribe)\w*/i.test(file.text)) return;
  const seen = new Set<number>();
  prose(file, (_s, n, para) => { if (seen.has(n)) return; seen.add(n); if (J_TIMER.test(para) && J_BACK.test(para) && /\b(?:pause|stop|opt[- ]?out|turn(?:ed)? off|disabl)\w*/i.test(para) && !/\b(?:until the user|only (?:if|when) the user|user (?:asks|turns))\b/i.test(para)) hit(n, para); });
});

export const expBatchRules: Rule[] = [expA, expB, expC, expD, expE, expF, expG, expH, expI, expJ];
