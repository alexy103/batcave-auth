const express = require('express');
const bcrypt = require('bcrypt');

const db = require('../config/db');
const router = express.Router();

const { checkAuth } = require('../middleware/security');

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

	const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
	if (!user || !(await bcrypt.compare(password, user.password_hash))) {
		return res.status(401).json({ erreur: 'username ou mot de passe incorrect' });
	}

	req.session.regenerate((err) => {
		if (err) return next(err);

		req.session.user = {
			id: user.id,
			username: user.username,
			role: user.role,
		};

		req.session.ip = req.ip;
		req.session.userAgent = req.headers['user-agent'];

		req.session.save((err) => {
			if (err) return next(err);

			res.json({
				message: 'Connecté !',
				user: req.session.user,
			});
		});
	});
});

router.post('/logout', (req, res) => {
	req.session.destroy((err) => {
		if (err) {
			return res.status(500).json({ message: 'Erreur lors de la déconnexion.' });
		}
		res.clearCookie('bat_identity');
		res.json({ message: 'Déconnecté !' });
	});
});

router.get('/me', checkAuth, (req, res) => {
	res.json({ id: req.user.id, username: req.user.username, role: req.user.role });
});

module.exports = router;
