const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');

const db = require('../config/db');
const router = express.Router();

const { checkAuth, adminOnly } = require('../middleware/security');
const { writeAdminLog } = require('../middleware/logger');

// BAT-COMPUTER ROUTES
router.get('/', checkAuth, adminOnly, writeAdminLog, (req, res) => {
	res.sendFile(path.resolve(__dirname, '../views/bat-computer.html'));
});

router.get('/secrets', checkAuth, adminOnly, (req, res) => {
	res.json([
		{ name: 'Batarang', desc: 'Arme de jet', icon: 'fa-shuriken' },
		{ name: 'Batmobile', desc: 'Véhicule de patrouille', icon: 'fa-car' },
	]);
});

router.post('/reports', checkAuth, adminOnly, (req, res) => {
	const { content } = req.body;
	const insert = db.prepare('INSERT INTO reports (user_id, content) VALUES (?, ?)');
	insert.run(req.user.id, content);
	res.status(201).send('Rapport envoyé !');
});

// BAT-LOGS ROUTES
router.get('/logs', checkAuth, adminOnly, (req, res) => {
	res.sendFile(path.resolve(__dirname, '../views/bat-logs.html'));
});

router.get('/api/logs', checkAuth, adminOnly, (req, res) => {
	const logs = db.prepare('SELECT * FROM connexions_audit ORDER BY timestamp DESC').all();
	res.json(logs);
});

module.exports = router;
