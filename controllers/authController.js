const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const cryptoService = require('../services/cryptoService');
const oauthService = require('../services/oauthService');
const userModel = require('../models/userModel');
const db = require('../config/db');

async function redirectToGoogle(req, res) {
	const state = cryptoService.generateState();
	const codeVerifier = cryptoService.generateCodeVerifier();
	const codeChallenge = cryptoService.generateCodeChallenge(codeVerifier);
	const nonce = cryptoService.generateState();

	// Persistance temporaire de la session PKCE
	userModel.saveOAuthSession(state, codeVerifier, nonce, 'google');

	// Construction de l'URL via le service dédié
	const authUrl = oauthService.getGoogleAuthUrl(state, codeChallenge, nonce);

	res.redirect(authUrl);
}

async function handleGoogleCallback(req, res) {
	const { code, state, error, error_description: errorDescription } = req.query;
	if (error) {
		const params = new URLSearchParams({
			provider: 'google',
			error: String(error),
			description: String(errorDescription || ''),
		});
		return res.redirect(`/oauth-error.html?${params.toString()}`);
	}

	if (!code || !state) {
		const params = new URLSearchParams({
			provider: 'google',
			error: 'invalid_callback',
			description: 'Missing code or state.',
		});
		return res.redirect(`/oauth-error.html?${params.toString()}`);
	}

	const session = userModel.getOAuthSession(state);
	if (!session) {
		const params = new URLSearchParams({
			provider: 'google',
			error: 'invalid_state',
			description: 'Invalid state token. Access denied.',
		});
		return res.redirect(`/oauth-error.html?${params.toString()}`);
	}
	userModel.deleteOAuthSession(state);

	try {
		const tokens = await oauthService.exchangeCodeForTokens(code, session.code_verifier);

		const userProfile = await oauthService.verifyGoogleIdToken(tokens.id_token, session.nonce);
		if (!userProfile?.sub) {
			return res.status(401).send('Invalid ID token payload.');
		}

		const normalizedProfile = {
			sub: userProfile.sub,
			name: userProfile.name || userProfile.email || `user-${userProfile.sub}`,
			provider: session.provider || 'google',
		};
		userModel.upsertUser(normalizedProfile);
		const oauthUser = userModel.getOAuthUserByProviderSub(normalizedProfile.provider, normalizedProfile.sub);
		if (!oauthUser) {
			return res.status(500).send('OAuth user persistence failed.');
		}

		const appUser = userModel.findOrCreateAppUserForOAuth(normalizedProfile.provider, normalizedProfile.sub, normalizedProfile.name, oauthUser.role);

		req.session.userId = normalizedProfile.sub; // On stocke l'ID unique du provider
		req.session.userName = normalizedProfile.name;

		const token = jwt.sign({ id: appUser.id, username: appUser.username, role: appUser.role }, process.env.JWT_SECRET, { expiresIn: '1m' });
		const refreshToken = crypto.randomBytes(40).toString('hex');
		const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

		db.prepare('INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (?, ?, ?)').run(refreshToken, appUser.id, expiresAt);

		res.cookie('bat_identity', token, { httpOnly: true, sameSite: 'strict', maxAge: 60 * 1000 });
		res.cookie('bat_refresh', refreshToken, { httpOnly: true, sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });

		if (String(appUser.role).toUpperCase() === 'ADMIN') {
			return res.redirect('/bat-computer');
		}
		return res.redirect('/');
	} catch (error) {
		console.error(error);
		const params = new URLSearchParams({
			provider: 'google',
			error: 'oauth_flow_failed',
			description: 'Authentication workflow failed.',
		});
		res.redirect(`/oauth-error.html?${params.toString()}`);
	}
}

module.exports = {
	redirectToGoogle,
	handleGoogleCallback,
};
