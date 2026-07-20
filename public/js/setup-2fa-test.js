const button = document.getElementById('test-setup-2fa');
const output = document.getElementById('response');
const secretElement = document.getElementById('secret');
const qrImage = document.getElementById('qr-image');

button.onclick = async () => {
	output.textContent = 'Appel en cours...';
	secretElement.textContent = '';
	qrImage.removeAttribute('src');

	try {
		const response = await fetch('/auth/setup-2fa', {
			method: 'POST',
			credentials: 'include',
		});

		let data;
		try {
			data = await response.json();
		} catch {
			data = { message: 'Réponse non JSON', status: response.status };
		}

		output.textContent = JSON.stringify(
			{
				status: response.status,
				ok: response.ok,
				data,
			},
			null,
			2,
		);

		if (response.ok && data?.secret) {
			secretElement.textContent = data.secret;
		}

		if (response.ok && data?.qrCodeBase64) {
			qrImage.src = data.qrCodeBase64;
		}
	} catch (err) {
		output.textContent = `Erreur réseau: ${err.message}`;
	}
};
