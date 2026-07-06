document.getElementById('change-password-form').onsubmit = async (e) => {
	e.preventDefault();
	const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{12,}$/;

	const oldPassword = document.getElementById('old-password').value.trim();
	const newPassword = document.getElementById('new-password').value.trim();
	const confirmPassword = document.getElementById('confirm-password').value.trim();
	const messageElement = document.getElementById('message');

	messageElement.classList.remove('hidden');

	if (newPassword !== confirmPassword) {
		messageElement.style.color = 'red';
		messageElement.innerText = 'Les deux mots de passe ne correspondent pas.';
		return;
	}

	if (!PASSWORD_REGEX.test(newPassword)) {
		messageElement.style.color = 'red';
		messageElement.innerText = 'Le mot de passe doit contenir au moins 12 caractères, 1 majuscule, 1 minuscule, 1 chiffre et 1 caractère spécial.';
		return;
	}

	const response = await fetch('/auth/change-password', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		credentials: 'include',
		body: JSON.stringify({ oldPassword, newPassword }),
	});

	if (response.ok) {
		messageElement.style.color = 'lightgreen';
		messageElement.innerText = 'Mot de passe changé avec succès.';
		setTimeout(() => {
			window.location.href = '/bat-computer';
		}, 800);
		return;
	}

	if (response.status === 401) {
		messageElement.style.color = 'red';
		messageElement.innerText = 'Mot de passe actuel incorrect ou session expirée.';
		return;
	}

	messageElement.style.color = 'red';
	messageElement.innerText = 'Erreur lors du changement de mot de passe.';
};
