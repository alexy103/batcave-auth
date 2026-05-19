document.getElementById('register-form').onsubmit = async (e) => {
	e.preventDefault();
	const username = document.getElementById('username').value.trim();
	const password = document.getElementById('password').value;
	const messageElement = document.getElementById('message');

	if (password.length < 8) {
		messageElement.style.color = 'red';
		messageElement.innerText = 'Erreur : le mot de passe doit contenir au moins 8 caractères.';
		return;
	}

	const response = await fetch('/register', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ username, password }),
	});

	if (response.ok) {
		messageElement.style.color = 'green';
		messageElement.innerText = 'Inscription réussie !';
		return;
	} else if (response.status === 409) {
		messageElement.innerText = "Erreur : l'utilisateur existe déjà.";
	} else {
		messageElement.innerText = "Erreur lors de l'inscription.";
	}
	messageElement.style.color = 'red';
};
