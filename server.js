const express = require('express');
const bcrypt = require('bcrypt');
const db = require('./db');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const PORT = 3000;
app.listen(PORT, () => {
	console.log(`Serveur démarré sur http://localhost:${PORT}`);
});

app.post('/register', async (req, res) => {
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

// Authenticated

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

app.post('/login', checkAuth, (req, res) => {
	res.json({
		user: {
			id: req.user.id,
			username: req.user.username,
			role: req.user.role,
		},
	});
});

app.get('/api/me', checkAuth, (req, res) => {
	res.json({ id: req.user.id, username: req.user.username, role: req.user.role });
});

// Admin

function adminOnly(req, res, next) {
	if (req.user.role != 'ADMIN') return res.status(403).send('Accès refusé.');
	next();
}
app.get('/bat-computer', checkAuth, adminOnly, (req, res) => {
	res.sendFile(__dirname + '/private/bat-computer.html');
	writeAdminLog(req);
});

app.get('/api/secrets', checkAuth, adminOnly, (req, res) => {
	res.json([
		{ name: 'Batarang', desc: 'Arme de jet', icon: 'fa-shuriken' },
		{ name: 'Batmobile', desc: 'Véhicule de patrouille', icon: 'fa-car' },
	]);
});

app.post('/api/reports', checkAuth, adminOnly, (req, res) => {
	const { content } = req.body;
	const insert = db.prepare('INSERT INTO reports (user_id, content) VALUES (?, ?)');
	insert.run(req.user.id, content);
	res.status(201).send('Rapport envoyé !');
});

// Logs

function writeAdminLog(req) {
	const timestamp = new Date().toString();
	const insert = db.prepare('INSERT INTO logs (username, timestamp) VALUES (?, ?)');
	insert.run(req.user.username, timestamp);
}
