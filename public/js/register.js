document.getElementById('register-form').onsubmit = async (e) => {
	e.preventDefault();

	const action = e.submitter.value;

	const username = document.getElementById('username').value.trim();
	const password = document.getElementById('password').value.trim();
	const role = document.getElementById('role').value;
	const messageElement = document.getElementById('message');
	const setupPanel = document.getElementById('setup-2fa-panel');
	const setupQr = document.getElementById('setup-2fa-qr');

	if (!messageElement) return;
	messageElement.classList.remove('hidden');

	if (setupPanel) {
		setupPanel.classList.add('hidden');
	}

	const generate2FASetupQR = async () => {
		messageElement.style.color = 'yellow';
		messageElement.innerText = 'Configuration 2FA en cours...';

		const setupResponseData = await fetch('/auth/setup-2fa', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ username, password }),
		});

		let setupData;
		try {
			setupData = await setupResponseData.json();
		} catch {
			setupData = { erreur: 'Réponse non JSON', status: setupResponseData.status };
		}

		if (!setupResponseData.ok || !setupData?.qrCodeBase64) {
			messageElement.style.color = 'red';
			messageElement.innerText = setupData?.erreur || 'Impossible de générer le QR code 2FA.';
			return false;
		}

		if (setupPanel && setupQr) {
			setupPanel.classList.remove('hidden');
			setupQr.src = setupData.qrCodeBase64;
		}

		messageElement.innerText = '';
		return true;
	};

	if (password.length < 8) {
		messageElement.style.color = 'red';
		messageElement.innerText = 'Erreur : le mot de passe doit contenir au moins 8 caractères.';
		return;
	}

	if (action === 'register') {
		const response = await fetch('/auth/register', {
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
		const response = await fetch('/auth/login', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ username, password }),
		});

		if (response.status === 200) {
			const loginData = await response.json();

			if (loginData.requires2FA) {
				const code = window.prompt('Entrez votre code à 6 chiffres :')?.trim();

				if (!code) {
					await generate2FASetupQR();
					return;
				}

				const verifyResponse = await fetch('/auth/verify-2fa', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					credentials: 'include',
					body: JSON.stringify({ username: loginData.username || username, code }),
				});

				if (!verifyResponse.ok) {
					messageElement.style.color = 'red';
					if (verifyResponse.status === 401) {
						messageElement.innerText = 'Code 2FA invalide ou expiré.';
						return;
					}
					messageElement.innerText = 'Erreur lors de la vérification 2FA.';
					return;
				}
			}

			const meResponse = await fetch('/auth/me', {
				method: 'GET',
				credentials: 'include',
			});
			if (!meResponse.ok) {
				messageElement.style.color = 'red';
				messageElement.innerText = 'Erreur lors de la récupération des informations utilisateur.';
				return;
			}

			let me;
			try {
				me = await meResponse.json();
			} catch {
				messageElement.style.color = 'red';
				messageElement.innerText = 'Session créée, mais réponse utilisateur invalide. Rechargez la page.';
				return;
			}

			if (me.role === 'ADMIN') {
				window.location.href = '/bat-computer';
				return;
			}

			messageElement.style.color = 'green';
			messageElement.innerText = "Connexion réussie, mais votre compte n'a pas d'accès admin.";
			return;
		}

		messageElement.style.color = 'red';

		if (response.status === 401) {
			messageElement.innerText = 'Identifiants invalides.';
			return;
		}

		if (response.status === 403) {
			await generate2FASetupQR();
			return;
		}

		messageElement.innerText = 'Erreur lors de la connexion.';
	}
};
