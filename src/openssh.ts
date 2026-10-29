import {createHash, generateKeyPairSync, randomBytes} from 'node:crypto';

const KEY_TYPE = 'ssh-ed25519';
const MAGIC = Buffer.from('openssh-key-v1\0', 'latin1');
const BLOCK = 8;
const LINE = 70;

const uint32 = (n: number): Buffer => {
	const b = Buffer.alloc(4);
	b.writeUInt32BE(n);
	return b;
};
const sshString = (data: Buffer | string): Buffer => {
	const b = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
	return Buffer.concat([uint32(b.length), b]);
};

const publicBlob = (pub: Buffer): Buffer => Buffer.concat([sshString(KEY_TYPE), sshString(pub)]);

export const fingerprintOfBlob = (blob: Buffer): string => `SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;

export function fingerprintOf(publicLine: string): string {
	const b64 = publicLine.trim().split(/\s+/)[1];
	if (!b64) throw new Error('Not an SSH public key');
	return fingerprintOfBlob(Buffer.from(b64, 'base64'));
}

export type GeneratedKey = {
	privateKey: Buffer;
	publicKey: string;
	fingerprint: string;
};

export function generateEd25519(comment: string): GeneratedKey {
	const pair = generateKeyPairSync('ed25519');
	const pub = Buffer.from(pair.publicKey.export({format: 'jwk'}).x ?? '', 'base64url');
	const seed = Buffer.from(pair.privateKey.export({format: 'jwk'}).d ?? '', 'base64url');
	if (pub.length !== 32 || seed.length !== 32) throw new Error('ed25519 key generation failed');
	const blob = publicBlob(pub);
	const check = randomBytes(4);
	const secret = Buffer.concat([seed, pub]);
	const unpadded = Buffer.concat([check, check, sshString(KEY_TYPE), sshString(pub), sshString(secret), sshString(comment)]);
	const padLength = (BLOCK - (unpadded.length % BLOCK)) % BLOCK;
	const padding = Buffer.from(Array.from({length: padLength}, (_, i) => i + 1));
	const section = Buffer.concat([unpadded, padding]);
	const body = Buffer.concat([MAGIC, sshString('none'), sshString('none'), sshString(''), uint32(1), sshString(blob), sshString(section)]);
	const b64 = body.toString('base64');
	const lines: string[] = [];
	for (let i = 0; i < b64.length; i += LINE) lines.push(b64.slice(i, i + LINE));
	const privateKey = Buffer.from(`-----BEGIN OPENSSH PRIVATE KEY-----\n${lines.join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n`, 'utf8');
	for (const b of [seed, secret, unpadded, section, body]) b.fill(0);
	return {privateKey, publicKey: `${KEY_TYPE} ${blob.toString('base64')} ${comment}`, fingerprint: fingerprintOfBlob(blob)};
}
