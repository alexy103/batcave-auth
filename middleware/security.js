const db = require('../config/db');
const jwt = require('jsonwebtoken');

const getCookieValue = (cookieHeader, name) => {
	if (!cookieHeader) return null;
	const part = cookieHeader.split(';').find((c) => c.trim().startsWith(name + '='));
	return part ? part.split('=').slice(1).join('=') : null;
};

const checkRefreshToken = async (req, res, next) => {
	if (!process.env.JWT_SECRET) {
		return res.redirect('/');
	}

	const refreshToken = getCookieValue(req.headers.cookie, 'bat_refresh');
	if (!refreshToken) {
		return res.redirect('/');
	}

	const storedToken = db.prepare('SELECT * FROM refresh_tokens WHERE token = ?').get(refreshToken);
	if (!storedToken || new Date(storedToken.expires_at) < new Date()) {
		return res.redirect('/');
	}

	const user = db.prepare('SELECT * FROM users WHERE id = ?').get(storedToken.user_id);
	if (!user) return res.redirect('/');

	const newToken = jwt.sign({ id: user.id, username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1m' });

	res.cookie('bat_identity', newToken, { httpOnly: true, sameSite: 'strict', maxAge: 60 * 1000 });
	req.user = { id: user.id, username: user.username, role: user.role };
	return next();
};

const checkJWT = async (req, res, next) => {
	const token = getCookieValue(req.headers.cookie, 'bat_identity');
	if (!token) {
		return checkRefreshToken(req, res, next);
	}

	try {
		req.user = jwt.verify(token, process.env.JWT_SECRET);
		return next();
	} catch (err) {
		if (err.name === 'TokenExpiredError') {
			return checkRefreshToken(req, res, next);
		}
		return res.redirect('/');
	}
};

const adminOnly = (req, res, next) => {
	if (req.user.role != 'ADMIN') return res.status(403).send("Accès refusé, vous n'êtes pas administrateur.");
	next();
};

module.exports = { checkJWT, adminOnly, checkRefreshToken };
