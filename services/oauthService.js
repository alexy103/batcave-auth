const DEFAULT_GOOGLE_AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const DEFAULT_GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const DEFAULT_GOOGLE_TOKENINFO_ENDPOINT = 'https://oauth2.googleapis.com/tokeninfo';

function toAbsoluteUrl(value, varName) {
	try {
		return new URL(value).toString();
	} catch {
		throw new Error(`Invalid ${varName}: expected an absolute URL`);
	}
}

function getRequiredEnv(name) {
	const value = process.env[name];
	if (!value) {
		throw new Error(`Missing required environment variable: ${name}`);
	}
	return value;
}

function getGoogleAuthUrl(state, codeChallenge, nonce) {
	const endpoint = toAbsoluteUrl(process.env.GOOGLE_AUTH_ENDPOINT || DEFAULT_GOOGLE_AUTH_ENDPOINT, 'GOOGLE_AUTH_ENDPOINT');
	const redirectUri = toAbsoluteUrl(getRequiredEnv('REDIRECT_URI'), 'REDIRECT_URI');
	const clientId = getRequiredEnv('GOOGLE_CLIENT_ID');

	const url = new URL(endpoint);
	url.searchParams.append('client_id', clientId);
	url.searchParams.append('redirect_uri', redirectUri);
	url.searchParams.append('response_type', 'code');
	url.searchParams.append('scope', 'openid profile email');
	url.searchParams.append('state', state);
	if (nonce) {
		url.searchParams.append('nonce', nonce);
	}
	url.searchParams.append('code_challenge', codeChallenge);
	url.searchParams.append('code_challenge_method', 'S256');
	return url.toString();
}

async function exchangeCodeForTokens(code, codeVerifier) {
	const tokenEndpoint = toAbsoluteUrl(process.env.GOOGLE_TOKEN_ENDPOINT || DEFAULT_GOOGLE_TOKEN_ENDPOINT, 'GOOGLE_TOKEN_ENDPOINT');
	const redirectUri = toAbsoluteUrl(getRequiredEnv('REDIRECT_URI'), 'REDIRECT_URI');

	const response = await fetch(tokenEndpoint, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			client_id: getRequiredEnv('GOOGLE_CLIENT_ID'),
			client_secret: getRequiredEnv('GOOGLE_CLIENT_SECRET'),
			code: code,
			grant_type: 'authorization_code',
			redirect_uri: redirectUri,
			code_verifier: codeVerifier,
		}),
	});

	if (!response.ok) {
		const errorData = await response.json();
		throw new Error(JSON.stringify(errorData));
	}

	return response.json();
}

function decodeIdToken(idToken) {
	const payloadBase64 = idToken.split('.')[1];
	return JSON.parse(Buffer.from(payloadBase64, 'base64').toString('utf-8'));
}

async function verifyGoogleIdToken(idToken, expectedNonce) {
	if (!idToken) {
		throw new Error('Missing id_token');
	}

	const tokenInfoEndpoint = toAbsoluteUrl(process.env.GOOGLE_TOKENINFO_ENDPOINT || DEFAULT_GOOGLE_TOKENINFO_ENDPOINT, 'GOOGLE_TOKENINFO_ENDPOINT');
	const url = new URL(tokenInfoEndpoint);
	url.searchParams.append('id_token', idToken);

	const response = await fetch(url.toString(), { method: 'GET' });
	if (!response.ok) {
		throw new Error('Unable to verify Google ID token');
	}

	const payload = await response.json();
	const validIssuers = new Set(['accounts.google.com', 'https://accounts.google.com']);
	if (!payload.sub || payload.aud !== getRequiredEnv('GOOGLE_CLIENT_ID') || !validIssuers.has(payload.iss)) {
		throw new Error('Invalid ID token claims');
	}

	if (expectedNonce && payload.nonce !== expectedNonce) {
		throw new Error('Invalid ID token nonce');
	}

	if (payload.exp && Number(payload.exp) <= Math.floor(Date.now() / 1000)) {
		throw new Error('Expired ID token');
	}

	return payload;
}

module.exports = {
	getGoogleAuthUrl,
	exchangeCodeForTokens,
	decodeIdToken,
	verifyGoogleIdToken,
};
