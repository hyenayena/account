import path from 'node:path';
import type {Logger, ModulePlugin} from '../../../src/api.js';
import {agentDirFor, createAgents, type Agents} from './agent.js';
import {createCommand} from './commands.js';
import {gitSshResolver} from './git.js';
import {createGrants} from './grants.js';
import {createKinds} from './kinds.js';
import {noopLog} from './log.js';
import {inventory, migrate} from './migrate.js';
import {createProvider} from './provider.js';
import {createStore, type Store} from './store.js';

// Private keys never pass through yena's logs, but if one ever reached a log line it is cut out.
const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g;
// Shorter values would also cut ordinary words out of log lines.
const MIN_REDACTED = 6;

export const redactPrivateKeys = (text: string) => text.replace(PRIVATE_KEY, '[private key]');

export function redactValues(values: readonly string[]): (text: string) => string {
	const sorted = [...new Set(values)].filter(v => v.length >= MIN_REDACTED).sort((a, b) => b.length - a.length);
	return text => sorted.reduce((t, v) => t.split(v).join('[secret]'), text);
}

/** The store, with the ssh-agents brought in line after every change that adds, disables or removes a key. */
function withAgents(store: Store, agents: Agents, log: Logger): Store {
	let queue = Promise.resolve();
	const sync = () => {
		queue = queue
			.then(async () => agents.sync(await store.list()))
			.catch(error => log.warn('ssh-agents not in line with the accounts', {err: error}));
		return queue;
	};
	void sync();
	const after =
		<A extends unknown[], R>(fn: (...args: A) => Promise<R>) =>
		async (...args: A): Promise<R> => {
			const result = await fn(...args);
			await sync();
			return result;
		};
	return {...store, add: after(store.add), setDisabled: after(store.setDisabled), remove: after(store.remove)};
}

/** The plugin; `agents: false` leaves ssh-agents alone (tests that load the plugin). */
export function createPlugin(opts: {agents?: boolean} = {}): ModulePlugin {
	return async host => {
		const log = host.log ?? noopLog;
		const raw = createStore(host.dataDir, {log});
		let redactSecrets = redactValues([]);
		log.addRedactor(text => redactSecrets(redactPrivateKeys(raw.vault.redact(text))));
		// Before the agents load keys: what 0.5.0 stored in plaintext is encrypted first.
		await migrate(raw, log);
		const left = await inventory(raw).catch(() => undefined);
		if (left && left.plaintext > 0) log.warn('vault has unencrypted entries', {count: left.plaintext});
		const store =
			opts.agents === false
				? raw
				: withAgents(raw, createAgents({dir: agentDirFor(host.dataDir), configFile: path.join(host.dataDir, 'ssh_config'), privateKey: name => raw.privateKey(name)}), log);
		const refresh = () =>
			void store.allSecretValues().then(
				values => (redactSecrets = redactValues(values)),
				error => log.warn('secrets unreadable for the redactor', {err: error}),
			);
		refresh();
		const kinds = createKinds(host.dataDir);
		const grants = createGrants(host.dataDir, log);
		if (host.build) {
			await grants.prune(host.build.modules.map(m => m.name)).catch(error => log.warn('grants not pruned', {err: error}));
		}
		host.registerGitSsh?.(gitSshResolver(name => store.get(name), host.dataDir));
		host.registerCredentialProvider?.(createProvider({store, kinds, grants, log, onSecretsChanged: refresh}));
		return [createCommand({dataDir: host.dataDir, store, kinds, grants, log, onSecretsChanged: refresh, ...(host.build && {build: host.build})})];
	};
}

export default createPlugin();
