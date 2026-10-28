import type {Logger, ModulePlugin} from '../../../src/api.js';
import {agentDirFor, createAgents, type Agents} from './agent.js';
import {createCommand} from './commands.js';
import {gitSshResolver} from './git.js';
import {createKinds} from './kinds.js';
import {noopLog} from './log.js';
import {createStore, type Store} from './store.js';

// Private keys never pass through yena's code, but if one ever reached a log line it is cut out.
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
	return host => {
		const log = host.log ?? noopLog;
		const raw = createStore(host.dataDir);
		const store = opts.agents === false ? raw : withAgents(raw, createAgents({dir: agentDirFor(host.dataDir), keyPath: name => raw.keyPath(name)}), log);
		let redactSecrets = redactValues([]);
		const refresh = () =>
			void store.allSecretValues().then(
				values => (redactSecrets = redactValues(values)),
				error => log.warn('secrets unreadable for the redactor', {err: error}),
			);
		refresh();
		log.addRedactor(text => redactSecrets(redactPrivateKeys(text)));
		host.registerGitSsh?.(gitSshResolver(name => store.get(name), host.dataDir));
		return [createCommand({dataDir: host.dataDir, store, kinds: createKinds(host.dataDir), log, onSecretsChanged: refresh})];
	};
}

export default createPlugin();
