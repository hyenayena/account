import {PassThrough} from 'node:stream';
import {render} from 'ink';
import type {ReactElement} from 'react';

export const wait = (ms: number) => new Promise(r => setTimeout(r, ms));

export function mount(element: ReactElement, size = {columns: 80, rows: 30}) {
	const stdin = Object.assign(new PassThrough(), {isTTY: true, setRawMode: () => stdin, ref() {}, unref() {}});
	const stdout = Object.assign(new PassThrough(), {isTTY: true, ...size});
	const chunks: string[] = [];
	stdout.on('data', c => chunks.push(String(c)));
	const app = render(element, {
		stdin: stdin as unknown as NodeJS.ReadStream,
		stdout: stdout as unknown as NodeJS.WriteStream,
		stderr: new PassThrough() as unknown as NodeJS.WriteStream,
		debug: true,
		exitOnCtrlC: false,
		patchConsole: false,
	});
	return {
		press: async (keys: string, ms = 40) => {
			stdin.write(keys);
			await wait(ms);
		},
		last: () => chunks.at(-1) ?? '',
		all: () => chunks.join(''),
		unmount: () => app.unmount(),
	};
}
