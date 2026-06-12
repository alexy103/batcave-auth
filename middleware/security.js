const db = require('../config/db');
const { writeConnexionAudit } = require('./logger');

const checkAuth = async (req, res, next) => {
	if (!req.session.user) return res.status(401).redirect('/');

	const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.user.id);

	if (!user) {
		return res.status(401).redirect('/');
	}

	req.user = user;
	next();
};

const adminOnly = (req, res, next) => {
	if (req.user.role != 'ADMIN') return res.status(403).send("Accès refusé, vous n'êtes pas administrateur.");
	next();
};

const checkSessionIntegrity = (req, res, next) => {
	if (!req.session.user) return next();
	if (req.session.ip !== req.ip || req.session.userAgent !== req.headers['user-agent']) {
		writeConnexionAudit(req, req.session.user.username, 'FRAUD');
		return req.session.destroy(() => {
			res.clearCookie('bat_identity');
			return res.status(401).redirect('/');
		});
	} else {
		next();
	}
};

module.exports = { checkAuth, adminOnly, checkSessionIntegrity };
