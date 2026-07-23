const crypto = require('crypto');

// Génère une chaîne aléatoire sécurisée de caractères (Base64URL safe)
function generateCodeVerifier() {
	return crypto.randomBytes(32).toString('base64url'); // Encodage en Base64URL
}

// Crée le code_challenge à partir du code_verifier (Hachage SHA-256 + Base64URL)
function generateCodeChallenge(verifier) {
	return crypto.createHash('sha256').update(verifier).digest().toString('base64url');
}

module.exports = {
	generateCodeVerifier,
	generateCodeChallenge,
	generateState: generateCodeVerifier, // État aléatoire pour contrer le CSRF
};
