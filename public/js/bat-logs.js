async function getLogs() {
	const response = await fetch('/bat-computer/api/logs', {
		method: 'GET',
		headers: { 'Content-Type': 'application/json' },
	});

	if (!response.ok) return [];

	return response.json();
}

function showLogs(logs) {
	const tbody = document.getElementById('logs-body');

	logs.forEach((log) => {
		const row = document.createElement('tr');

		row.innerHTML = `
			<td class="p-2 border border-yellow-400">${log.id}</td>
			<td class="p-2 border border-yellow-400">${log.username}</td>
			<td class="p-2 border border-yellow-400">${log.action}</td>
			<td class="p-2 border border-yellow-400">${log.ip_address}</td>
			<td class="p-2 border border-yellow-400 break-all">${log.user_agent}</td>
			<td class="p-2 border border-yellow-400">${log.timestamp}</td>
		`;

		tbody.appendChild(row);
	});
}

async function initLogs() {
	const logs = await getLogs();
	showLogs(logs);
}

initLogs();
