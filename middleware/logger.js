const db = require('../config/db');

function writeAdminLog(req, res, next) {
	const timestamp = new Date().toString();
	const insert = db.prepare('INSERT INTO logs (username, timestamp) VALUES (?, ?)');
	insert.run(req.user.username, timestamp);

	next();
}

function writeConnexionAudit(req, username, action) {
	const timestamp = new Date().toString();
	const insert = db.prepare('INSERT INTO connexions_audit (username, action, ip_address, user_agent, timestamp) VALUES (?, ?, ?, ?, ?)');
	insert.run(username, action, req.ip, req.headers['user-agent'], timestamp);
}

module.exports = { writeAdminLog, writeConnexionAudit };
