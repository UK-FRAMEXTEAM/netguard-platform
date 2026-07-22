const params = new URLSearchParams(window.location.search);
const type = params.get('type') || 'PHISHING';
document.getElementById('threatType').textContent = type.toUpperCase().slice(0, 40);

document.getElementById('goBack').addEventListener('click', () => history.back());
document.getElementById('closeTab').addEventListener('click', () => window.close());
