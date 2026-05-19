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
	const { username, password } = req.body;

	const hash = await bcrypt.hash(password, 10);

	try {
		const insert = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)');
		insert.run(username, hash);
		res.status(201).send('Utilisateur créé avec succès !');
	} catch (err) {
		res.status(409).send("Erreur : l'utilisateur existe déjà.");
	}
});

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

app.get('/bat-computer', checkAuth, (req, res) => {
	res.sendFile(__dirname + '/private/bat-computer.html');
});

app.get('/api/secrets', checkAuth, (req, res) => {
	res.json({ name: 'Batarang', desc: 'Arme de jet', icon: 'fa-shuriken' });
});
