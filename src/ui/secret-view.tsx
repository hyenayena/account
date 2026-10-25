import React from 'react';
import type {MountControl, UiElement} from '../../../../src/api.js';
import {SecretInput} from './kit.js';

/** The hidden input for one secret: the typed value goes to `save` and nowhere else. */
export function secretView(control: MountControl, label: string, save: (value: string) => Promise<void>, done: (saved: boolean, error?: Error) => void): UiElement {
	return (
		<SecretInput
			label={label}
			{...(control.host && {host: control.host})}
			onSubmit={value => {
				save(value).then(
					() => {
						done(true);
						control.close();
					},
					(error: Error) => {
						done(false, error);
						control.close();
					},
				);
			}}
			onCancel={() => {
				done(false);
				control.close();
			}}
		/>
	);
}
