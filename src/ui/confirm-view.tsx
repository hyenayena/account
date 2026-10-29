import React from 'react';
import type {MountControl, UiElement} from '../../../../src/api.js';
import {TextField} from './kit.js';

/** Asks the user to type `word`; anything else is refused in place, Esc cancels. */
export function confirmView(control: MountControl, question: string, word: string, done: (confirmed: boolean) => void): UiElement {
	return (
		<TextField
			label={question}
			hint={`Type ${word} and press Enter · Esc cancel`}
			validate={v => (v === word ? undefined : `Type exactly: ${word}`)}
			onSubmit={() => {
				done(true);
				control.close();
			}}
			onCancel={() => {
				done(false);
				control.close();
			}}
			{...(control.host && {host: control.host})}
		/>
	);
}
