const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

const { checkSessionIntegrity } = require('./middleware/security');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(
	session({
		name: 'bat_identity',
		secret: process.env.SESSION_SECRET || 'secret',
		resave: false,
		saveUninitialized: false,
		cookie: {
			httpOnly: true,
			sameSite: 'strict',
			maxAge: 1_800_000,
		},
		store: new SQLiteStore({ db: 'sessions.db', dir: './config' }),
	}),
);

app.use(checkSessionIntegrity);

const authRouter = require('./routes/auth');
app.use('/auth', authRouter);

const adminRouter = require('./routes/bat-computer');
app.use('/bat-computer', adminRouter);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
	console.log(`Serveur démarré sur http://localhost:${PORT}`);
});
