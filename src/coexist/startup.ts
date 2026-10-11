import { detectCoexistence } from './detect.ts';

/**
 * One log line for the OpenClaw plugin at startup. Read-only, no network, no
 * file written. It never throws and gives up after `timeoutMs`.
 */
export async function startupCoexistenceNote(
  env: NodeJS.ProcessEnv = process.env,
  timeoutMs = 3000,
): Promise<string | undefined> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const work = detectCoexistence({ env, skipRepo: true }).then((detection) => {
      const active = detection.tools.filter((tool) => tool.status !== 'disabled');
      if (active.length === 0) return undefined;
      const labels = active.slice(0, 6).map((tool) => {
        const guards = tool.registersBeforeToolCall === 'yes' ? 'tool-call guard' : tool.kind;
        const mode = tool.mode ? `, ${tool.mode}` : '';
        return `${tool.name} (${guards}${mode})`;
      });
      const more =
        active.length > labels.length ? ` and ${active.length - labels.length} more` : '';
      const blockers = active.filter(
        (tool) => tool.registersBeforeToolCall === 'yes' && tool.canBlock !== 'no',
      );
      const advice =
        detection.self.mode === 'enforce' && blockers.length > 0
          ? ' Ironheights is in enforce mode and another guard can also block. Run `ironheights coexist`.'
          : ' Run `ironheights coexist` for details.';
      return `other security tools detected (heuristic): ${labels.join(', ')}${more}.${advice}`;
    });
    const limit = new Promise<undefined>((resolve) => {
      timer = setTimeout(() => resolve(undefined), timeoutMs);
      timer.unref?.();
    });
    return await Promise.race([work, limit]);
  } catch {
    return undefined;
  } finally {
    if (timer) clearTimeout(timer);
  }
}
