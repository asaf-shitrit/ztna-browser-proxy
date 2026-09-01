/**
 * Build-time defaults. Overridable at runtime from chrome.storage.local so a
 * single build can point at different environments.
 */
export interface ExtensionConfig {
  popApiBase: string;
  oidcIssuer: string;
  oidcClientId: string;
}

/**
 * Defaults target the native runner (`pnpm dev`), which serves the POP as
 * `localhost` so no hosts-file entry is needed. For the Docker stack, point
 * `popApiBase` at https://pop.ztna.test:8445 via setConfig().
 */
const DEFAULTS: ExtensionConfig = {
  popApiBase: 'https://localhost:8445',
  oidcIssuer: 'http://localhost:8080/realms/ztna',
  oidcClientId: 'ztna-extension',
};

export async function getConfig(): Promise<ExtensionConfig> {
  const stored = await chrome.storage.local.get('config');
  return { ...DEFAULTS, ...(stored['config'] as Partial<ExtensionConfig> | undefined) };
}

export async function setConfig(patch: Partial<ExtensionConfig>): Promise<void> {
  const current = await getConfig();
  await chrome.storage.local.set({ config: { ...current, ...patch } });
}
