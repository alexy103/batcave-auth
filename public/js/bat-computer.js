async function getCurrentUser() {
	const response = await fetch('/auth/me', {
		method: 'GET',
		headers: { 'Content-Type': 'application/json' },
	});

	if (response.ok) {
		const user = await response.json();
		document.querySelector('#welcome').textContent = `Bienvenue, Justicier ${user.username}`;
		return user;
	}
}

async function getSecrets() {
	const response = await fetch('/bat-computer/secrets', {
		method: 'GET',
		headers: { 'Content-Type': 'application/json' },
	});

	if (response.ok) {
		const res = await response.json();

		return res;
	}

	return null;
}

function showSecrets(secrets) {
	const container = document.querySelector('#secrets');
	secrets.forEach((secret) => {
		const card = document.createElement('div');
		card.innerHTML = `

		<div class="bg-yellow-400 text-gray-900 rounded p-4 my-2 w-fit min-w-96 mx-auto">
			<div>
				<p class="text-xl font-bold">${secret.name}</p>
				<p>${secret.desc}</p>
			</div>
		</div>

		
		`;
		container.appendChild(card);
	});
}

async function init() {
	const user = await getCurrentUser();

	if (user) {
		const secrets = await getSecrets();
		console.log(secrets);

		if (secrets) {
			showSecrets(secrets);
		}
	}
}

init();

document.getElementById('report-form').onsubmit = async (e) => {
	e.preventDefault();
	const report = document.getElementById('report');
	const val = report.value.trim();

	if (!val || val.length < 1) return;

	const response = await fetch('/bat-computer/reports', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ content: val }),
	});

	report.value = '';
};

document.getElementById('logout-button').onclick = async () => {
	const response = await fetch('/auth/logout', {
		method: 'POST',
	});

	if (response.ok) {
		window.location.href = '/';
	}
};
