const db = require('../config/db');

function writeAdminLog(req, res, next) {
	const timestamp = new Date().toString();
	const insert = db.prepare('INSERT INTO logs (username, timestamp) VALUES (?, ?)');
	insert.run(req.user.username, timestamp);

	next();
}

module.exports = { writeAdminLog };
