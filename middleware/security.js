const jwt = require('jsonwebtoken');

const checkJWT = async (req, res, next) => {
	if (!process.env.JWT_SECRET) {
		return res.status(500).send('Configuration serveur invalide: JWT_SECRET manquant.');
	}

	const cookieHeader = req.headers.cookie;
	if (!cookieHeader) return res.status(401).send('Accès refusé, aucun jeton fourni.');

	const tokenCookie = cookieHeader.split(';').find((c) => c.trim().startsWith('bat_identity='));
	if (!tokenCookie) return res.status(401).send('Accès refusé, jeton introuvable.');

	const token = tokenCookie.split('=')[1];

	try {
		const decoded = jwt.verify(token, process.env.JWT_SECRET);

		req.user = decoded;
		next();
	} catch (err) {
		return res.status(401).send('Jeton invalide ou expiré.');
	}
};

const adminOnly = (req, res, next) => {
	if (req.user.role != 'ADMIN') return res.status(403).send("Accès refusé, vous n'êtes pas administrateur.");
	next();
};

module.exports = { checkJWT, adminOnly };
