require('dotenv').config();
const express = require('express');
const helmet = require('helmet');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(helmet());

const authRouter = require('./routes/auth');
app.use('/auth', authRouter);

const adminRouter = require('./routes/bat-computer');
app.use('/bat-computer', adminRouter);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
	console.log(`Serveur démarré sur http://localhost:${PORT}`);
});
