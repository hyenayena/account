import React, {useRef, useState} from 'react';
import {Box, Text, useInput} from 'ink';
import type {MountControl, UiElement} from '../../../../src/api.js';
import {isManagedKind, missingOf, type Kind, type Kinds} from '../kinds.js';
import {checkFields, NAME, type Account, type Store} from '../store.js';
import {colorEnabled, ListPicker, SecretInput, TextField, useViewHost} from './kit.js';

const tone = (name: string) => (colorEnabled() ? name : undefined);

export type WizardDeps = {store: Store; kinds: Kinds; onSecretsChanged?: () => void};

type Step =
	| {at: 'kind'}
	| {at: 'name'; kind: Kind}
	| {at: 'field'; kind: Kind; name: string; fields: Record<string, string>; index: number}
	| {at: 'ssh'; kind: Kind; name: string; fields: Record<string, string>}
	| {at: 'saving'}
	| {at: 'secret'; kind: Kind; account: Account; index: number; saved: string[]; error?: string; attempt?: number}
	| {at: 'done'; kind: Kind; account: Account; saved: string[]}
	| {at: 'error'; message: string};

const kindSummary = (k: Kind) =>
	[...k.fields.map(f => `${f.key}${f.required ? '!' : ''}${f.secret ? '*' : ''}`), ...(k.ssh ? ['SSH key'] : [])].join(', ');

const problem = (fn: () => unknown): string | undefined => {
	try {
		fn();
		return undefined;
	} catch (error) {
		return (error as Error).message;
	}
};

/**
 * ListPicker calls close() and then onPick() for Enter, but only close() for Esc. The cancel waits a
 * microtask so a pick that follows in the same tick wins.
 */
function picker(onPick: (id: string) => void, onCancel: () => void) {
	let picked = false;
	return {
		onPick: (id: string) => {
			picked = true;
			onPick(id);
		},
		close: () => queueMicrotask(() => !picked && onCancel()),
	};
}

function Done({control, kind, account, saved, missing}: {control: MountControl; kind: Kind; account: Account; saved: string[]; missing: string[]}) {
	const {focused, columns} = useViewHost(control.host);
	const [copied, setCopied] = useState<string | undefined>();
	useInput(
		(input, key) => {
			if (control.host?.isHostKey(input, key)) return;
			if (input === 'c' && account.publicKey && control.copyToClipboard) {
				setCopied(control.copyToClipboard(account.publicKey) ? 'Public key copied' : 'Could not copy');
				return;
			}
			if (key.return || key.escape || (key.ctrl && input === 'c')) control.close();
		},
		{isActive: focused},
	);
	const width = Math.max(1, columns - 1);
	return (
		<Box flexDirection="column" width={width}>
			<Text bold>{`✓ Account "${account.name}" (${kind.name}) created`}</Text>
			{saved.length > 0 && <Text>{`  Secrets saved: ${saved.join(', ')}`}</Text>}
			{account.publicKey && (
				<>
					<Text>{`  Add this public key on GitHub${account.fields.login ? ` (signed in as ${account.fields.login})` : ''}:`}</Text>
					<Text dimColor>  https://github.com/settings/ssh/new</Text>
					<Text wrap="wrap">{account.publicKey}</Text>
				</>
			)}
			{missing.length > 0 && <Text color={tone('yellow')}>{`  Still needed: ${missing.join(', ')} (account secret ${account.name} <field>)`}</Text>}
			{copied && <Text color={tone('green')}>{`  ${copied}`}</Text>}
			<Text dimColor>{account.publicKey && control.copyToClipboard ? 'c copy the public key · Enter close' : 'Enter close'}</Text>
		</Box>
	);
}

function Failed({control, message}: {control: MountControl; message: string}) {
	const {focused} = useViewHost(control.host);
	useInput(
		(input, key) => {
			if (control.host?.isHostKey(input, key)) return;
			if (key.return || key.escape) control.close();
		},
		{isActive: focused},
	);
	return (
		<Box flexDirection="column">
			<Text color={tone('red')}>{`Cannot add the account: ${message}`}</Text>
			<Text dimColor>Enter close</Text>
		</Box>
	);
}

function Wizard({control, deps}: {control: MountControl; deps: WizardDeps}) {
	const {store, kinds} = deps;
	const [step, setStep] = useState<Step>({at: 'kind'});
	// Accounts whose secret only a module sets (claude-login) are not made here.
	const all = useRef(kinds.listSync().filter(k => !isManagedKind(k))).current;
	const cancel = () => control.close();
	const host = control.host ? {host: control.host} : {};

	const afterFields = (kind: Kind, name: string, fields: Record<string, string>) => {
		if (kind.ssh) setStep({at: 'ssh', kind, name, fields});
		else void create(kind, name, fields, false);
	};

	const create = async (kind: Kind, name: string, fields: Record<string, string>, ssh: boolean) => {
		setStep({at: 'saving'});
		try {
			const account = await store.add({name, kind, fields, ssh});
			nextSecret(kind, account, 0, []);
		} catch (error) {
			setStep({at: 'error', message: (error as Error).message});
		}
	};

	const secretFields = (kind: Kind) => kind.fields.filter(f => f.secret && !f.managed);

	const nextSecret = (kind: Kind, account: Account, index: number, saved: string[]) => {
		if (index < secretFields(kind).length) setStep({at: 'secret', kind, account, index, saved});
		else setStep({at: 'done', kind, account, saved});
	};

	switch (step.at) {
		case 'kind': {
			const items = all.map(k => ({id: k.name, label: k.builtin ? `${k.name} (built in)` : k.name, meta: kindSummary(k)}));
			const p = picker(id => {
				const kind = all.find(k => k.name === id);
				if (kind) setStep({at: 'name', kind});
			}, cancel);
			return <ListPicker title="Add an account · what is it for?" empty="No kinds" action="choose" items={items} onPick={p.onPick} close={p.close} {...host} />;
		}
		case 'name':
			return (
				<TextField
					key="name"
					label={`Name of the ${step.kind.name} account`}
					hint="a-z, 0-9, - and _; used in commands, e.g. account use <name>"
					validate={v => (!NAME.test(v) ? 'Use a-z, 0-9, "-" and "_", at most 32 characters' : store.listSync().some(a => a.name === v) ? `"${v}" already exists` : undefined)}
					onSubmit={name => {
						const publicFields = step.kind.fields.filter(f => !f.secret);
						if (publicFields.length > 0) setStep({at: 'field', kind: step.kind, name, fields: {}, index: 0});
						else afterFields(step.kind, name, {});
					}}
					onCancel={cancel}
					{...host}
				/>
			);
		case 'field': {
			const publicFields = step.kind.fields.filter(f => !f.secret);
			const field = publicFields[step.index]!;
			return (
				<TextField
					key={`field:${field.key}`}
					label={`${field.key}${field.required ? '' : ' (optional)'}`}
					hint={`${step.name} · ${step.kind.name} · ${step.index + 1}/${publicFields.length}`}
					optional={!field.required}
					validate={v => problem(() => checkFields(step.kind, {[field.key]: v}))}
					onSubmit={value => {
						const fields = value === '' ? step.fields : {...step.fields, [field.key]: value};
						if (step.index + 1 < publicFields.length) setStep({...step, fields, index: step.index + 1});
						else afterFields(step.kind, step.name, fields);
					}}
					onCancel={cancel}
					{...host}
				/>
			);
		}
		case 'ssh': {
			const items = [
				{id: 'yes', label: 'Generate an SSH key', meta: 'for git push and pull'},
				{id: 'no', label: 'No SSH key', meta: 'a token only, e.g. for the API'},
			];
			const p = picker(id => void create(step.kind, step.name, step.fields, id === 'yes'), cancel);
			return <ListPicker title={`${step.name} · SSH key?`} empty="" action="choose" items={items} onPick={p.onPick} close={p.close} {...host} />;
		}
		case 'saving':
			return <Text dimColor>Creating the account…</Text>;
		case 'secret': {
			const field = secretFields(step.kind)[step.index]!;
			const need = missingOf(step.kind, step.account, step.saved);
			const required = need.some(m => m.split('|').includes(field.key));
			return (
				<>
					{step.error && <Text color={tone('red')}>{step.error}</Text>}
					<SecretInput
						key={`secret:${field.key}:${step.attempt ?? 0}`}
						label={`${field.key} for ${step.account.name}${required ? '' : ' (optional)'} · Esc skips the rest`}
						optional
						onSubmit={value => {
							if (value === '') return nextSecret(step.kind, step.account, step.index + 1, step.saved);
							store.setSecret(step.account.name, field.key, value).then(
								() => {
									deps.onSecretsChanged?.();
									nextSecret(step.kind, step.account, step.index + 1, [...step.saved, field.key]);
								},
								(error: Error) => setStep({...step, error: error.message, attempt: (step.attempt ?? 0) + 1}),
							);
						}}
						onCancel={() => setStep({at: 'done', kind: step.kind, account: step.account, saved: step.saved})}
						{...host}
					/>
				</>
			);
		}
		case 'done':
			return <Done control={control} kind={step.kind} account={step.account} saved={step.saved} missing={missingOf(step.kind, step.account, step.saved)} />;
		case 'error':
			return <Failed control={control} message={step.message} />;
	}
}

export const addWizard = (control: MountControl, deps: WizardDeps): UiElement => <Wizard control={control} deps={deps} />;
