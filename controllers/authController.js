const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const cryptoService = require('../services/cryptoService');
const oauthService = require('../services/oauthService');
const userModel = require('../models/userModel');
const db = require('../config/db');

const OAUTH_PROVIDER_CONFIG = {
	google: {
		requiresNonce: true,
		buildAuthUrl: ({ state, codeChallenge, nonce }) => oauthService.getGoogleAuthUrl(state, codeChallenge, nonce),
		exchangeTokens: ({ code, codeVerifier }) => oauthService.exchangeGoogleCodeForTokens(code, codeVerifier),
		resolveProfile: ({ tokens, session }) => oauthService.verifyGoogleIdToken(tokens.id_token, session.nonce),
	},
	github: {
		requiresNonce: false,
		buildAuthUrl: ({ state, codeChallenge }) => oauthService.getGithubAuthUrl(state, codeChallenge),
		exchangeTokens: ({ code, codeVerifier }) => oauthService.exchangeGithubCodeForTokens(code, codeVerifier),
		resolveProfile: ({ tokens }) => oauthService.fetchGithubUserProfile(tokens.access_token),
	},
};

function redirectOAuthError(res, provider, error, description) {
	const params = new URLSearchParams({
		provider: String(provider || 'unknown'),
		error: String(error || 'oauth_error'),
		description: String(description || ''),
	});
	return res.redirect(`/oauth-error.html?${params.toString()}`);
}

function issueAppSessionFromOAuth(req, res, profile, role = 'USER') {
	userModel.upsertUser(profile);
	const oauthUser = userModel.getOAuthUserByProviderSub(profile.provider, profile.sub);
	if (!oauthUser) {
		throw new Error('OAuth user persistence failed.');
	}

	const appUser = userModel.findOrCreateAppUserForOAuth(profile.provider, profile.sub, profile.name, role || oauthUser.role);

	req.session.userId = profile.sub;
	req.session.userName = profile.name;

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
}

function normalizeOAuthProfile(rawProfile, fallbackProvider) {
	return {
		sub: rawProfile.sub,
		name: rawProfile.name || rawProfile.email || `user-${rawProfile.sub}`,
		provider: rawProfile.provider || fallbackProvider,
	};
}

async function startOAuthLogin(res, provider) {
	const providerConfig = OAUTH_PROVIDER_CONFIG[provider];
	const state = cryptoService.generateState();
	const codeVerifier = cryptoService.generateCodeVerifier();
	const codeChallenge = cryptoService.generateCodeChallenge(codeVerifier);
	const nonce = providerConfig.requiresNonce ? cryptoService.generateState() : null;

	userModel.saveOAuthSession(state, codeVerifier, nonce, provider);

	const authUrl = providerConfig.buildAuthUrl({ state, codeChallenge, nonce });
	return res.redirect(authUrl);
}

async function completeOAuthCallback(req, res, provider) {
	const providerConfig = OAUTH_PROVIDER_CONFIG[provider];
	const { code, state, error, error_description: errorDescription } = req.query;

	if (error) {
		return redirectOAuthError(res, provider, error, errorDescription);
	}

	if (!code || !state) {
		return redirectOAuthError(res, provider, 'invalid_callback', 'Missing code or state.');
	}

	const session = userModel.getOAuthSession(state);
	if (!session || session.provider !== provider) {
		return redirectOAuthError(res, provider, 'invalid_state', 'Invalid state token. Access denied.');
	}
	userModel.deleteOAuthSession(state);

	try {
		const tokens = await providerConfig.exchangeTokens({ code, codeVerifier: session.code_verifier });
		const rawProfile = await providerConfig.resolveProfile({ tokens, session });

		if (!rawProfile?.sub) {
			return redirectOAuthError(res, provider, 'invalid_profile', 'Provider profile is missing subject identifier.');
		}

		const normalizedProfile = normalizeOAuthProfile(rawProfile, provider);
		return issueAppSessionFromOAuth(req, res, normalizedProfile, 'USER');
	} catch (callbackError) {
		console.error(callbackError);
		return redirectOAuthError(res, provider, 'oauth_flow_failed', 'Authentication workflow failed.');
	}
}

async function redirectToGoogle(req, res) {
	return startOAuthLogin(res, 'google');
}

async function redirectToGithub(req, res) {
	return startOAuthLogin(res, 'github');
}

async function handleGoogleCallback(req, res) {
	return completeOAuthCallback(req, res, 'google');
}

async function handleGithubCallback(req, res) {
	return completeOAuthCallback(req, res, 'github');
}

module.exports = {
	redirectToGoogle,
	handleGoogleCallback,
	redirectToGithub,
	handleGithubCallback,
};
