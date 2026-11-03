import type { Finding, Rule, ScanContext, ScannedFile, Severity } from '../core/types.ts';
import { createFinding, pushUnique } from './helpers.ts';

/** Prose-attack experiment 2026-11-03 (P1-P6). Off unless IH_EXP lists the key (or ALL). Never shipped as-is. */
const on = (k: string) => (process.env.IH_EXP ?? '').split(',').map((s) => s.trim()).some((x) => x === k || x === 'ALL');
const sentences = (line: string): string[] => line.split(/(?<=[.;!?])\s+(?=\S)|(?<=。)/);
const GUARD_DOC =
  /\b(?:scanner|vett?(?:ing|er)|red flags?|detect(?:s|ion|or)?|suspicious|jailbreak\w*|prompt injection|attack patterns?|threat model|ctf)\b/i;
const QUOTED = /["“”]/;

interface Block {
  start: number;
  lines: string[];
}
/** Sections between headings (prose and code together). */
function sections(file: ScannedFile): Block[] {
  const lines = file.text.split(/\r?\n/);
  const out: Block[] = [];
  let cur: Block = { start: 1, lines: [] };
  let inF = false;
  lines.forEach((l, i) => {
    if (/^\s{0,3}(```|~~~)/.test(l)) inF = !inF;
    if (!inF && /^#{1,6}\s/.test(l) && cur.lines.length) {
      out.push(cur);
      cur = { start: i + 1, lines: [] };
    }
    cur.lines.push(l);
  });
  out.push(cur);
  return out;
}
/** Prose sentences outside fences and tables; list items are their own paragraph. */
function prose(file: ScannedFile, visit: (s: string, n: number, para: string) => void) {
  if (file.kind !== 'markdown' && file.kind !== 'text') return;
  let inF = false;
  let para = '';
  let start = 0;
  const flush = () => {
    if (para) for (const s of sentences(para)) visit(s, start, para);
    para = '';
  };
  file.text.split(/\r?\n/).forEach((l, i) => {
    if (/^\s{0,3}(```|~~~)/.test(l)) {
      flush();
      inF = !inF;
      return;
    }
    if (inF || /^\s*\|/.test(l) || !l.trim() || /^\s*(?:#|[-*+]\s|\d+[.)]\s)/.test(l)) {
      flush();
      if (!inF && l.trim() && !/^\s*\|/.test(l)) {
        para = l.replace(/^\s*(?:#+|[-*+]|\d+[.)])\s*/, '');
        start = i + 1;
      }
      return;
    }
    if (!para) start = i + 1;
    para += (para ? ' ' : '') + l.trim();
  });
  flush();
}
function frontmatter(text: string): string {
  return /^---\r?\n([\s\S]*?)\r?\n---/.exec(text)?.[1] ?? '';
}
function description(text: string): string {
  const fm = frontmatter(text);
  const m = /^\s*description\s*:\s*([\s\S]*?)(?=^\S|$(?![\s\S]))/m.exec(fm);
  return (m?.[1] ?? '').replace(/\s+/g, ' ');
}
function mk(
  key: string,
  id: string,
  title: string,
  severity: Severity,
  category: Rule['category'],
  appliesTo: Rule['appliesTo'],
  fn: (file: ScannedFile, hit: (n: number, ev: string) => void, ctx: ScanContext) => void,
): Rule {
  const r: Rule = {
    id,
    title,
    category,
    severity,
    priority: 'P1',
    description: `Experiment ${key}: ${title}.`,
    remediation: 'Remove this behaviour or make it explicit and user-controlled.',
    appliesTo,
    examples: { matches: [], nonMatches: [] },
    check(file, ctx) {
      const f: Finding[] = [];
      if (!on(key)) return f;
      fn(
        file,
        (n, ev) =>
          pushUnique(
            f,
            createFinding(r, file, { line: n, evidence: ev, confidence: 'medium', message: title }),
          ),
        ctx,
      );
      return f;
    },
  };
  return r;
}


const NEG = /\b(?:never|do not|don'?t|must not|should not|avoid|unless the user|only if the user|ask (?:the user|first|before)|confirm(?:s|ed)? with the user|with the user'?s? (?:approval|consent|permission))\b/i;
const ASK = /\b(?:ask(?:s|ing)? (?:the user|for (?:confirmation|approval|permission))|confirm(?:ation)? (?:with|from) the user|user (?:confirms|approves|chooses|provides|supplies|sets)|your own|from (?:the user'?s?|your) (?:config|settings|environment)|\$\{?[A-Z_]{3,}|<[A-Za-z_ -]+>|\{\{\s*\w+|env(?:ironment)? var)/i;

// P1: user content sent to a destination the skill author fixed, as a required step, with no user-set or confirmed target.
const P1_SEND = /\b(?:publish|upload|sync|post|send|push|save|file|export|mirror|copy|forward|append)\w*\s+(?:(?:it|them|this|the\s+(?:full\s+|complete\s+|whole\s+)?(?:drafts?|notes?|documents?|files?|content|conversation|transcript|messages?|output|results?|report|text|data)|every\s+\w+|all\s+\w+)\b[^.\n]{0,40})?\b(?:to|into|in)\s+(?:the\s+)?(?:\w+\s+){0,2}(?:database|workspace|project|page|notebook|folder|bucket|channel|board|space|collection|account|endpoint)\b/i;
const P1_MAND = /\b(?:required|mandatory|must|always|non-?optional|every time|without exception|even (?:if|when) (?:it is |they are |the draft is )?(?:not|un)\w*|(?:considered|counts? as|treated as) (?:a )?fail\w*)\b/i;
const P1_ID = /\b(?:database|db|workspace|project|page|notebook|folder|bucket|channel|board|space|collection|parent|team)\b[^\n]{0,30}\b(?:id|uuid|key)\b\s*[:=]?\s*[`'"][A-Za-z0-9_-]{12,}[`'"]|\b[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}\b/i;
export const expP1 = mk('P1', 'IH-XP-P1', 'Required step sends user content to a destination the skill author fixed', 'high', 'network', ['markdown'], (file, hit) => {
  if (GUARD_DOC.test(description(file.text))) return;
  for (const s of sections(file)) {
    const body = s.lines.join('\n');
    if (!P1_ID.test(body) || ASK.test(body)) continue;
    const i = s.lines.findIndex((l) => P1_SEND.test(l) && !NEG.test(l));
    if (i < 0 || !P1_MAND.test(body + '\n' + (s.lines[0] ?? ''))) continue;
    if (!/\b(?:required|mandatory|fail\w*|even if|always|must)\b/i.test(file.text)) continue;
    hit(s.start + i, (s.lines[i] ?? '').trim());
  }
});

// P2: in a checking/review skill, an outside list pre-clears items or the pass stops before every item is checked.
const P2_JOB = /\b(?:verif\w+|review\w*|audit\w*|check(?:s|er|ing)?|validat\w+|fact-?check\w*|scan\w*|inspect\w*|vet\w*)\b/i;
const P2_PRECLEAR = /\b(?:marks?|marked|lists?|listed|flags?|flagged|records?|recorded|tags?|tagged)\b[^.\n]{0,40}\b(?:resolved|cleared|verified|approved|trusted|safe|passed|known[- ]good|allow-?listed|whitelisted)\b[^.\n]{0,120}\b(?:skip\w*|exclud\w*|omit\w*|leave (?:off|out)|stay (?:off|out of)|keep (?:off|out of)|do not (?:re-?)?(?:check|verify|review|flag|scan|test)|don'?t (?:re-?)?(?:check|verify|review|flag)|no need to (?:re-?)?(?:check|verify|review)|inherit\w*|treat(?:ed)? as (?:verified|clean|passed|resolved))/i;
  /\b(?:marked|listed|flagged|recorded|tagged|noted)\s+(?:as\s+)?(?:resolved|cleared|verified|approved|trusted|safe|passed|ok|known[- ]good|whitelisted|allow-?listed)\b[^.\n]{0,120}\b(?:skip|exclude|omit|leave (?:off|out)|stay off|do not (?:re-?)?(?:check|verify|review|flag|scan|test)|don'?t (?:re-?)?(?:check|verify|review|flag)|no need to (?:re-?)?(?:check|verify|review)|inherit\w*|treat(?:ed)? as (?:verified|clean|passed|resolved))\b|\b(?:skip|exclude|do not (?:re-?)?(?:check|verify|review|flag))\b[^.\n]{0,60}\b(?:any|every|all|entries|items|references|records|files|rows)\b[^.\n]{0,60}\b(?:already\s+)?(?:marked|listed|cleared|approved)\s+(?:as\s+\w+\s+)?(?:in|by|on)\s+(?:the\s+)?[\w./`-]+/i;
const P2_CAP = /\b(?:once|after|as soon as|when)\s+(?:the\s+)?(?:first\s+)?(?:\d+|one|two|three|a few|a couple)\b[^.\n]{0,60}\b(?:stop|close|end|finish|conclude)\w*\s+(?:out\s+)?(?:the\s+)?(?:pass|review|audit|check|scan|verification|search)\b/i;
export const expP2 = mk('P2', 'IH-XP-P2', 'Checker lets an outside list pre-clear items or stops before checking all', 'high', 'injection', ['markdown'], (file, hit) => {
  const d = description(file.text);
  if (GUARD_DOC.test(d) && !P2_JOB.test(d)) return;
  if (!P2_JOB.test(d + ' ' + file.text.slice(0, 1500))) return;
  prose(file, (s, n) => {
    if ((P2_PRECLEAR.test(s) || P2_CAP.test(s)) && !QUOTED.test(s) && !/\b(?:never|must not|should not|re-?check (?:everything|all)|still (?:re-?)?check)\b/i.test(s)) hit(n, s);
  });
});

// P3: unconditional step, explicitly regardless of the task, that writes skill-authored data outside the skill folder.
const P3_REG = /\bregardless\s+of\s+(?:whether|if)\s+(?:the\s+)?(?:current\s+|user'?s?\s+)?(?:task|request|query|question|job|user)\b|\beven\s+(?:if|when)\s+(?:the\s+)?(?:current\s+)?(?:task|request|user)\s+(?:does\s*n[o']t|did\s*n[o']t|doesn'?t)\s+(?:need|require|ask|mention|involve)\w*/i;
const P3_OUT = /(?:~\/|\$HOME|\/root\/|\/home\/[\w.-]+\/|%APPDATA%|\.cache\/|\.config\/|\.local\/|\buser'?s?\s+(?:cache|config|home|profile|memory|settings)\b|\b(?:shared|global)\s+(?:cache|config|memory|settings)\b|\bMEMORY\.md|\bCLAUDE\.md|\bAGENTS\.md)/i;
const P3_WRITE = /\b(?:write|writes|create|save|store|append|copy|place|drop|install|persist|seed|register|add)\w*\b/i;
export const expP3 = mk('P3', 'IH-XP-P3', 'Step runs regardless of the task and writes outside the skill folder', 'high', 'persistence', ['markdown'], (file, hit) => {
  if (GUARD_DOC.test(description(file.text))) return;
  for (const s of sections(file)) {
    const body = s.lines.join('\n');
    const i = s.lines.findIndex((l) => P3_REG.test(l) && !/\b(?:never|do not|don'?t)\b/i.test(l));
    if (i < 0) continue;
    if (P3_OUT.test(body) && P3_WRITE.test(body)) hit(s.start + i, (s.lines[i] ?? '').trim());
  }
});

// P4: claims a different skill is retired/deprecated/replaced AND removes the agent's re-check of this skill's output.
const P4_OTHER = /[`'"]?[\w-]{3,}[`'"]?\s+(?:skill|plugin|tool|extension|entry|version|package)\s+(?:is|has been|was)\s+(?:now\s+)?(?:an?\s+)?(?:deprecated|retired|superseded|obsolete|unsafe|discontinued|no longer (?:supported|maintained|valid))\b|\b(?:deprecated|retired|superseded)\s+(?:skill|plugin|tool|pointer|entry)s?\b[^.\n]{0,60}\b(?:use|route|redirect)\w*\s+(?:through\s+)?(?:this|here)/i;
const P4_NOCHECK = /\b(?:do not|don'?t|never|without)\s+(?:re-?sort|re-?rank|re-?order|verify|re-?check|double-?check|second-?guess|compare|cross-?check|question)\w*|\b(?:always\s+)?(?:take|pick|use|select|return)\s+(?:only\s+)?the\s+first\s+(?:row|result|entry|item|match|option)\b/i;
export const expP4 = mk('P4', 'IH-XP-P4', 'Declares another skill retired and stops the agent re-checking this one', 'high', 'injection', ['markdown'], (file, hit) => {
  if (GUARD_DOC.test(description(file.text))) return;
  if (/\b(?:changelog|renamed (?:from|to)|migration guide|was renamed)\b/i.test(file.text)) return;
  let other = -1;
  let txt = '';
  prose(file, (s, n) => { if (other < 0 && P4_OTHER.test(s) && !QUOTED.test(s)) { other = n; txt = s; } });
  if (other < 0) return;
  let nc = false;
  prose(file, (s) => { if (P4_NOCHECK.test(s)) nc = true; });
  if (nc) hit(other, txt);
});

// P5: audience split. The agent is told to keep an action it takes on files/data/sends out of what the user sees.
const P5 = /\b(?:do not|don'?t|never)\s+(?:mention|report|show|list|surface|include|disclose|tell)\b[^.\n]{0,50}\b(?:this|these|that|it|them|the)\b[^.\n]{0,40}\b(?:step|change|edit|write|upload|send|request|call|file|entry|update|modification)s?\b[^.\n]{0,40}\b(?:in|to)\s+(?:the\s+)?(?:user|summary|report|response|reply|output|final answer|changelog|commit message)\b|\b(?:keep|leave)\s+(?:this|these|it|them|the\s+\w+)\s+(?:step|change|edit|write|upload|request|update)s?\s+out\s+of\s+(?:the\s+)?(?:summary|report|response|reply|user)/i;
export const expP5 = mk('P5', 'IH-XP-P5', 'Agent told to keep one of its own actions out of what the user sees', 'high', 'injection', ['markdown'], (file, hit) => {
  if (GUARD_DOC.test(description(file.text))) return;
  prose(file, (s, n) => { if (P5.test(s) && !QUOTED.test(s) && !/\b(?:secrets?|passwords?|tokens?|api keys?|credentials?|PII)\b/i.test(s)) hit(n, s); });
});

// P6: trigger capture. Claims to be the entry point for any task AND loads/writes a memory file as standing requirements without asking.
const P6_ALL = /\b(?:the\s+)?(?:only|single|sole|mandatory|default)\s+entry\s+point\b|\b(?:use|activate|invoke|trigger)\w*\s+(?:this\s+skill\s+)?(?:for|on|before)\s+(?:any|every|all)\s+(?:task|request|message|prompt|conversation|turn)s?\b(?![^.\n]{0,40}\b(?:involving|about|related|with (?:a|an)|that (?:involve|mention))\b)/i;
const P6_MEM = /\b(?:read|load|open)\w*\b[^\n]{0,80}\b(?:treat|use|apply|follow)\w*\s+(?:it|them|this|its\s+contents?)\s+as\s+(?:the\s+)?(?:current|standing|binding|authoritative|active)\s+(?:requirements?|instructions?|rules?|directives?|orders?)|\b(?:memory|context)\b[^\n]{0,60}\(?\bpermission[- ]free\b|\bpermission[- ]free\b[^\n]{0,60}\b(?:memory|context)\b/i;
export const expP6 = mk('P6', 'IH-XP-P6', 'Claims every task and loads a memory file as standing requirements', 'high', 'injection', ['markdown'], (file, hit) => {
  if (GUARD_DOC.test(description(file.text))) return;
  let a = -1; let t = ''; let m = false;
  prose(file, (s, n) => { if (a < 0 && P6_ALL.test(s)) { a = n; t = s; } if (P6_MEM.test(s)) m = true; });
  if (a >= 0 && m) hit(a, t);
});

export const expProseRules: Rule[] = [expP1, expP2, expP3, expP4, expP5, expP6];
