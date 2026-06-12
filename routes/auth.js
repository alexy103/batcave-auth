const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');

const db = require('../config/db');
const router = express.Router();

const { checkAuth } = require('../middleware/security');
const { writeAdminLog } = require('../middleware/logger');

router.post('/register', async (req, res) => {
	const { username, password, role } = req.body;

	const hash = await bcrypt.hash(password, 10);

	try {
		const insert = db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)');
		insert.run(username, hash, role);
		res.status(201).send('Utilisateur créé avec succès !');
	} catch (err) {
		res.status(409).send("Erreur : l'utilisateur existe déjà.", err);
	}
});

router.post('/login', checkAuth, (req, res) => {
	res.json({
		user: {
			id: req.user.id,
			username: req.user.username,
			role: req.user.role,
		},
	});
});

// Logged user routes :

router.get('/me', checkAuth, (req, res) => {
	res.json({ id: req.user.id, username: req.user.username, role: req.user.role });
});

module.exports = router;
