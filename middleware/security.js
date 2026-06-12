const bcrypt = require('bcrypt');
const db = require('../config/db');

const checkAuth = async (req, res, next) => {
	const authHeader = req.headers.authorization;

	if (!authHeader || !authHeader.startsWith('Basic ')) {
		res.setHeader('WWW-Authenticate', 'Basic realm="Administration"');
		return res.status(401).send('Authentification requise');
	}

	const base64 = authHeader.split(' ')[1];
	const [username, password] = Buffer.from(base64, 'base64').toString().split(':');

	const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
	if (user && (await bcrypt.compare(password, user.password_hash))) {
		req.user = user;
		next();
	} else {
		return res.status(401).send('Identifiants invalides');
	}
};

const adminOnly = (req, res, next) => {
	if (req.user.role != 'ADMIN') return res.status(403).send('Accès refusé.');
	next();
};

module.exports = { checkAuth, adminOnly };
