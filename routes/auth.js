const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const db = require('../config/db');
const router = express.Router();

const { checkJWT } = require('../middleware/security');
const { writeConnexionAudit } = require('../middleware/logger');
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{12,}$/;

router.post('/register', async (req, res) => {
	const { username, password, role } = req.body;

	const hash = await bcrypt.hash(password, 10);

	try {
		const insert = db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)');
		insert.run(username, hash, role);
		res.status(201).send('Utilisateur créé avec succès !');
	} catch (err) {
		res.status(409).send("Erreur : l'utilisateur existe déjà.");
	}
});

router.post('/login', async (req, res, next) => {
	const { username, password } = req.body;

	try {
		const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

		if (!user || !(await bcrypt.compare(password, user.password_hash))) {
			return res.status(401).json({ erreur: 'Identifiants incorrects' });
		}

		const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1m' });
		const refreshToken = crypto.randomBytes(40).toString('hex');
		const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

		db.prepare('INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (?, ?, ?)').run(refreshToken, user.id, expiresAt);

		res.cookie('bat_identity', token, { httpOnly: true, sameSite: 'strict', maxAge: 60 * 1000 });
		res.cookie('bat_refresh', refreshToken, { httpOnly: true, sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });

		res.json({ message: 'Connecté !' });
	} catch {
		res.status(500).json({ erreur: 'Erreur lors de la connexion.' });
	}
});

router.post('/logout', checkJWT, (req, res) => {
	const refreshToken = req.headers.cookie
		?.split(';')
		.find((c) => c.trim().startsWith('bat_refresh='))
		?.split('=')[1];

	if (refreshToken) {
		db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(refreshToken);
	}

	res.clearCookie('bat_identity');
	res.clearCookie('bat_refresh');
	res.json({ message: 'Déconnecté !' });
});

router.get('/me', checkJWT, (req, res) => {
	res.json({ id: req.user.id, username: req.user.username, role: req.user.role });
});

router.post('/refresh', (req, res) => {
	const refreshToken = req.headers.cookie
		?.split(';')
		.find((c) => c.trim().startsWith('bat_refresh='))
		?.split('=')[1];
	if (!refreshToken) return res.redirect('/');
	const storedToken = db.prepare('SELECT * FROM refresh_tokens WHERE token = ?').get(refreshToken);

	if (!storedToken || new Date(storedToken.expires_at) < new Date()) {
		return res.redirect('/');
	}

	const user = db.prepare('SELECT * FROM users WHERE id = ?').get(storedToken.user_id);
	if (!user) return res.redirect('/');
	const newToken = jwt.sign({ id: user.id, username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1m' });

	res.cookie('bat_identity', newToken, { httpOnly: true, sameSite: 'strict', maxAge: 60 * 1000 });
	res.json({ message: 'Jeton rafraîchi !' });
});

router.post('/change-password', checkJWT, async (req, res) => {
	const { oldPassword, newPassword } = req.body;
	const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);

	if (!PASSWORD_REGEX.test(newPassword)) {
		return res.status(400).json({
			erreur: 'Le mot de passe doit contenir au moins 12 caractères, 1 majuscule, 1 minuscule, 1 chiffre et 1 caractère spécial.',
		});
	}

	if (!user || !(await bcrypt.compare(oldPassword, user.password_hash))) {
		return res.status(401).json({ erreur: 'Mot de passe actuel incorrect' });
	}
	await db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(await bcrypt.hash(newPassword, 10), req.user.id);
	res.json({ message: 'Mot de passe changé avec succès' });
});

module.exports = router;
