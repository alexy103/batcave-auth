const db = require('../config/db');

// Sauvegarde la session OAuth temporaire (Anti-CSRF et PKCE)
function saveOAuthSession(state, codeVerifier, nonce, provider) {
	const statement = db.prepare(`
	INSERT INTO oauth_sessions (state, code_verifier, nonce, provider) 
	VALUES (?, ?, ?, ?)
    `);
	return statement.run(state, codeVerifier, nonce, provider);
}

// Récupère les informations de session liées au 'state'
function getOAuthSession(state) {
	const statement = db.prepare(`SELECT code_verifier, nonce, provider FROM oauth_sessions WHERE state = ?`);
	return statement.get(state);
}

// Supprime la session OAuth une fois qu'elle a été consommée
function deleteOAuthSession(state) {
	const statement = db.prepare(`DELETE FROM oauth_sessions WHERE state = ?`);
	return statement.run(state);
}

// Enregistre l'utilisateur s'il n'existe pas, ou met à jour ses données (Upsert)
// Reçoit le payload extrait de l'ID Token d'OpenID Connect
function upsertUser(userProfile) {
	const statement = db.prepare(`
		INSERT INTO oauth_users (sub, username, role, provider) 
        VALUES (?, ?, 'USER', ?)
		ON CONFLICT(provider, sub) DO UPDATE SET 
			username = excluded.username
    `);
	return statement.run(userProfile.sub, userProfile.name, userProfile.provider || 'google');
}

function getOAuthUserByProviderSub(provider, sub) {
	const statement = db.prepare(`
		SELECT id, sub, username, role, provider, created_at
		FROM oauth_users
		WHERE provider = ? AND sub = ?
	`);
	return statement.get(provider, sub);
}

function findOrCreateAppUserForOAuth(provider, sub, displayName, role = 'USER') {
	const oauthBackedUsername = `${provider}_${sub}`;
	const existingUser = db.prepare('SELECT id, username, role FROM users WHERE username = ?').get(oauthBackedUsername);
	if (existingUser) return existingUser;

	db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run(oauthBackedUsername, null, role);
	const created = db.prepare('SELECT id, username, role FROM users WHERE username = ?').get(oauthBackedUsername);
	if (created) {
		return created;
	}

	throw new Error(`Unable to create local user mapping for ${displayName || oauthBackedUsername}`);
}

module.exports = {
	saveOAuthSession,
	getOAuthSession,
	deleteOAuthSession,
	upsertUser,
	getOAuthUserByProviderSub,
	findOrCreateAppUserForOAuth,
};
