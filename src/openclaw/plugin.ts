import { startupCoexistenceNote } from '../coexist/startup.ts';
import { priorityFromConfig } from '../guard/priority.ts';
import { createGuardHook, type GuardHookEvent } from '../guard/hook.ts';
import { GUARD_PLUGIN_ID } from '../guard/types.ts';
import { TOOL_VERSION } from '../version.ts';

/**
 * OpenClaw plugin entry for the runtime guard.
 *
 * Checked against the OpenClaw docs on 10 October 2026:
 * - https://docs.openclaw.ai/plugins/hooks
 * - https://docs.openclaw.ai/plugins/hooks/tool-policy
 * - https://docs.openclaw.ai/plugins/building-plugins
 * - https://docs.openclaw.ai/plugins/manifest
 *
 * `before_tool_call` can block a tool or ask for approval. The loader accepts
 * a default export with `register` (see openclaw `src/plugins/loader.ts`,
 * `resolvePluginModuleExport`). The documented helper is `definePluginEntry`
 * from `openclaw/plugin-sdk/plugin-entry`. This file does not import that
 * helper: ironheights does not depend on the OpenClaw package, and the hook
 * runs only after OpenClaw loads this module. guard-scanner's published plugin
 * uses the same plain `{ id, register }` shape.
 *
 * The hook runs inside the OpenClaw process. It is not a sandbox and not a
 * process outside the agent. See docs/guard.md.
 */

interface PluginLogger {
  info?: (message: string) => void;
  warn?: (message: string) => void;
}

interface PluginApi {
  pluginConfig?: unknown;
  logger?: PluginLogger;
  on: (
    hook: 'before_tool_call',
    handler: (event: GuardHookEvent, ctx: unknown) => Promise<unknown>,
    opts?: { priority?: number },
  ) => void;
}

const plugin = {
  id: GUARD_PLUGIN_ID,
  name: 'Ironheights Guard',
  version: TOOL_VERSION,
  description:
    'Local runtime guard for high-risk OpenClaw tool calls. Logs on this machine. Blocks only in enforce mode.',
  register(api: PluginApi) {
    const handler = createGuardHook({
      ...(api.pluginConfig !== undefined ? { pluginConfig: api.pluginConfig } : {}),
    });
    const priority = priorityFromConfig(api.pluginConfig);
    api.on('before_tool_call', (event) => handler(event), { priority });
    const mode =
      api.pluginConfig &&
      typeof api.pluginConfig === 'object' &&
      'mode' in api.pluginConfig &&
      (api.pluginConfig.mode === 'monitor' || api.pluginConfig.mode === 'enforce')
        ? api.pluginConfig.mode
        : 'policy default';
    api.logger?.info?.(
      `ironheights-guard registered before_tool_call in-process (mode hint: ${mode}, priority ${priority}). This hook is not outside the agent.`,
    );
    // Read-only look at other security tools. It writes nothing and never blocks startup.
    void startupCoexistenceNote()
      .then((note) => {
        if (note) api.logger?.info?.(`ironheights-guard: ${note}`);
      })
      .catch(() => undefined);
  },
};

export default plugin;
