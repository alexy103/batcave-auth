const DEFAULT_GOOGLE_AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const DEFAULT_GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const DEFAULT_GOOGLE_TOKENINFO_ENDPOINT = 'https://oauth2.googleapis.com/tokeninfo';
const DEFAULT_GITHUB_AUTH_ENDPOINT = 'https://github.com/login/oauth/authorize';
const DEFAULT_GITHUB_TOKEN_ENDPOINT = 'https://github.com/login/oauth/access_token';
const DEFAULT_GITHUB_USERINFO_ENDPOINT = 'https://api.github.com/user';
const DEFAULT_GITHUB_EMAILS_ENDPOINT = 'https://api.github.com/user/emails';
const DEFAULT_FACEBOOK_AUTH_ENDPOINT = 'https://www.facebook.com/v20.0/dialog/oauth';
const DEFAULT_FACEBOOK_TOKEN_ENDPOINT = 'https://graph.facebook.com/v20.0/oauth/access_token';
const DEFAULT_FACEBOOK_USERINFO_ENDPOINT = 'https://graph.facebook.com/me';

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

function getRequiredAnyEnv(names) {
	for (const name of names) {
		if (process.env[name]) return process.env[name];
	}
	throw new Error(`Missing required environment variable: one of ${names.join(', ')}`);
}

function getGoogleRedirectUri() {
	return toAbsoluteUrl(getRequiredAnyEnv(['GOOGLE_REDIRECT_URI', 'REDIRECT_URI']), 'GOOGLE_REDIRECT_URI/REDIRECT_URI');
}

function getGithubRedirectUri() {
	return toAbsoluteUrl(getRequiredAnyEnv(['GITHUB_REDIRECT_URI']), 'GITHUB_REDIRECT_URI');
}

function getFacebookRedirectUri() {
	return toAbsoluteUrl(getRequiredAnyEnv(['FACEBOOK_REDIRECT_URI', 'META_REDIRECT_URI']), 'FACEBOOK_REDIRECT_URI/META_REDIRECT_URI');
}

function getGoogleAuthUrl(state, codeChallenge, nonce) {
	const endpoint = toAbsoluteUrl(process.env.GOOGLE_AUTH_ENDPOINT || DEFAULT_GOOGLE_AUTH_ENDPOINT, 'GOOGLE_AUTH_ENDPOINT');
	const redirectUri = getGoogleRedirectUri();
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

async function exchangeGoogleCodeForTokens(code, codeVerifier) {
	const tokenEndpoint = toAbsoluteUrl(process.env.GOOGLE_TOKEN_ENDPOINT || DEFAULT_GOOGLE_TOKEN_ENDPOINT, 'GOOGLE_TOKEN_ENDPOINT');
	const redirectUri = getGoogleRedirectUri();

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

function getGithubAuthUrl(state, codeChallenge) {
	const endpoint = toAbsoluteUrl(process.env.GITHUB_AUTH_ENDPOINT || DEFAULT_GITHUB_AUTH_ENDPOINT, 'GITHUB_AUTH_ENDPOINT');
	const redirectUri = getGithubRedirectUri();
	const clientId = getRequiredEnv('GITHUB_CLIENT_ID');

	const url = new URL(endpoint);
	url.searchParams.append('client_id', clientId);
	url.searchParams.append('redirect_uri', redirectUri);
	url.searchParams.append('scope', 'read:user user:email');
	url.searchParams.append('state', state);
	url.searchParams.append('code_challenge', codeChallenge);
	url.searchParams.append('code_challenge_method', 'S256');
	return url.toString();
}

async function exchangeGithubCodeForTokens(code, codeVerifier) {
	const tokenEndpoint = toAbsoluteUrl(process.env.GITHUB_TOKEN_ENDPOINT || DEFAULT_GITHUB_TOKEN_ENDPOINT, 'GITHUB_TOKEN_ENDPOINT');
	const redirectUri = getGithubRedirectUri();

	const response = await fetch(tokenEndpoint, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
			Accept: 'application/json',
		},
		body: new URLSearchParams({
			client_id: getRequiredEnv('GITHUB_CLIENT_ID'),
			client_secret: getRequiredEnv('GITHUB_CLIENT_SECRET'),
			code,
			redirect_uri: redirectUri,
			code_verifier: codeVerifier,
		}),
	});

	if (!response.ok) {
		const errorData = await response.text();
		throw new Error(errorData || 'GitHub token exchange failed');
	}

	const tokens = await response.json();
	if (!tokens.access_token) {
		throw new Error('Missing access_token from GitHub token response');
	}

	return tokens;
}

async function fetchGithubUserProfile(accessToken) {
	const userEndpoint = toAbsoluteUrl(process.env.GITHUB_USERINFO_ENDPOINT || DEFAULT_GITHUB_USERINFO_ENDPOINT, 'GITHUB_USERINFO_ENDPOINT');
	const emailsEndpoint = toAbsoluteUrl(process.env.GITHUB_EMAILS_ENDPOINT || DEFAULT_GITHUB_EMAILS_ENDPOINT, 'GITHUB_EMAILS_ENDPOINT');
	const headers = {
		Authorization: `Bearer ${accessToken}`,
		Accept: 'application/json',
		'User-Agent': 'batcave-security',
	};

	const userResponse = await fetch(userEndpoint, { method: 'GET', headers });
	if (!userResponse.ok) {
		throw new Error('Unable to fetch GitHub user profile');
	}
	const user = await userResponse.json();

	let email = user.email || null;
	if (!email) {
		const emailResponse = await fetch(emailsEndpoint, { method: 'GET', headers });
		if (emailResponse.ok) {
			const emails = await emailResponse.json();
			const primary = Array.isArray(emails) ? emails.find((item) => item.primary) : null;
			email = primary?.email || (Array.isArray(emails) && emails[0] ? emails[0].email : null);
		}
	}

	if (!user?.id) {
		throw new Error('Invalid GitHub profile payload');
	}

	return {
		sub: String(user.id),
		name: user.name || user.login || email || `user-${user.id}`,
		email,
		provider: 'github',
	};
}

function getFacebookAuthUrl(state, codeChallenge) {
	const endpoint = toAbsoluteUrl(process.env.FACEBOOK_AUTH_ENDPOINT || process.env.META_AUTH_ENDPOINT || DEFAULT_FACEBOOK_AUTH_ENDPOINT, 'FACEBOOK_AUTH_ENDPOINT/META_AUTH_ENDPOINT');
	const redirectUri = getFacebookRedirectUri();
	const clientId = getRequiredAnyEnv(['FACEBOOK_CLIENT_ID', 'META_CLIENT_ID']);
	const scope = process.env.FACEBOOK_SCOPE || process.env.META_SCOPE || 'public_profile';

	const url = new URL(endpoint);
	url.searchParams.append('client_id', clientId);
	url.searchParams.append('redirect_uri', redirectUri);
	url.searchParams.append('response_type', 'code');
	url.searchParams.append('scope', scope);
	url.searchParams.append('state', state);
	url.searchParams.append('code_challenge', codeChallenge);
	url.searchParams.append('code_challenge_method', 'S256');
	return url.toString();
}

async function exchangeFacebookCodeForTokens(code, codeVerifier) {
	const tokenEndpoint = toAbsoluteUrl(process.env.FACEBOOK_TOKEN_ENDPOINT || process.env.META_TOKEN_ENDPOINT || DEFAULT_FACEBOOK_TOKEN_ENDPOINT, 'FACEBOOK_TOKEN_ENDPOINT/META_TOKEN_ENDPOINT');
	const redirectUri = getFacebookRedirectUri();

	const response = await fetch(tokenEndpoint, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
			Accept: 'application/json',
		},
		body: new URLSearchParams({
			client_id: getRequiredAnyEnv(['FACEBOOK_CLIENT_ID', 'META_CLIENT_ID']),
			client_secret: getRequiredAnyEnv(['FACEBOOK_CLIENT_SECRET', 'META_CLIENT_SECRET']),
			code,
			redirect_uri: redirectUri,
			code_verifier: codeVerifier,
		}),
	});

	if (!response.ok) {
		const errorData = await response.text();
		throw new Error(errorData || 'Facebook token exchange failed');
	}

	const tokens = await response.json();
	if (!tokens.access_token) {
		throw new Error('Missing access_token from Facebook token response');
	}

	return tokens;
}

async function fetchFacebookUserProfile(accessToken) {
	const userEndpoint = toAbsoluteUrl(
		process.env.FACEBOOK_USERINFO_ENDPOINT || process.env.META_USERINFO_ENDPOINT || DEFAULT_FACEBOOK_USERINFO_ENDPOINT,
		'FACEBOOK_USERINFO_ENDPOINT/META_USERINFO_ENDPOINT',
	);
	const url = new URL(userEndpoint);
	url.searchParams.append('fields', 'id,name,email');

	const response = await fetch(url.toString(), {
		method: 'GET',
		headers: {
			Authorization: `Bearer ${accessToken}`,
			Accept: 'application/json',
		},
	});

	if (!response.ok) {
		throw new Error('Unable to fetch Facebook user profile');
	}

	const user = await response.json();
	if (!user?.id) {
		throw new Error('Invalid Facebook profile payload');
	}

	return {
		sub: String(user.id),
		name: user.name || user.email || `user-${user.id}`,
		email: user.email || null,
		provider: 'facebook',
	};
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
	exchangeGoogleCodeForTokens,
	getGithubAuthUrl,
	exchangeGithubCodeForTokens,
	fetchGithubUserProfile,
	getFacebookAuthUrl,
	exchangeFacebookCodeForTokens,
	fetchFacebookUserProfile,
	decodeIdToken,
	verifyGoogleIdToken,
};
