import type {ModulePlugin} from '../../../src/api.js';
import {createCommand} from './commands.js';
import {gitSshResolver} from './git.js';
import {createKinds} from './kinds.js';
import {noopLog} from './log.js';
import {createStore} from './store.js';

// Private keys never pass through yena's code, but if one ever reached a log line it is cut out.
const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g;
// Shorter values would also cut ordinary words out of log lines.
const MIN_REDACTED = 6;

export const redactPrivateKeys = (text: string) => text.replace(PRIVATE_KEY, '[private key]');

export function redactValues(values: readonly string[]): (text: string) => string {
	const sorted = [...new Set(values)].filter(v => v.length >= MIN_REDACTED).sort((a, b) => b.length - a.length);
	return text => sorted.reduce((t, v) => t.split(v).join('[secret]'), text);
}

const plugin: ModulePlugin = host => {
	const log = host.log ?? noopLog;
	const store = createStore(host.dataDir);
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

export default plugin;
