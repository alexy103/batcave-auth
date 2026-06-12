document.getElementById('register-form').onsubmit = async (e) => {
	e.preventDefault();

	const action = e.submitter.value;

	const username = document.getElementById('username').value.trim();
	const password = document.getElementById('password').value.trim();
	const role = document.getElementById('role').value;
	const messageElement = document.getElementById('message');

	if (!messageElement) return;
	messageElement.classList.remove('hidden');

	if (password.length < 8) {
		messageElement.style.color = 'red';
		messageElement.innerText = 'Erreur : le mot de passe doit contenir au moins 8 caractères.';
		return;
	}

	if (action === 'register') {
		const response = await fetch('/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ username, password, role }),
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
	}

	if (action === 'login') {
		const response = await fetch('/login', {
			method: 'POST',
			headers: {
				Authorization: 'Basic ' + btoa(`${username}:${password}`),
			},
		});

		if (response.ok) {
			const data = await response.json();
			window.location.href = data.user.role === 'ADMIN' ? '/bat-computer' : '';
			return;
		}

		messageElement.style.color = 'red';

		if (response.status === 401) {
			messageElement.innerText = 'Identifiants invalides.';
			return;
		}

		messageElement.innerText = 'Erreur lors de la connexion.';
	}
};
