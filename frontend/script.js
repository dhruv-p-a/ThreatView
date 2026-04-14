const API_BASE_URL = 'https://threatview-x92w.onrender.com';
let threatChart;
let worldMap;

// ISO Country Code Mapping for jsVectorMap
const countryToCode = {
    "India": "IN", "USA": "US", "United States": "US", "Germany": "DE",
    "Russia": "RU", "China": "CN", "Brazil": "BR", "United Kingdom": "GB",
    "Canada": "CA", "France": "FR", "Japan": "JP", "Australia": "AU",
    "Netherlands": "NL", "Singapore": "SG"
};

document.addEventListener('DOMContentLoaded', () => {
    fetchRecentThreats();
    updateStats();
    loadBrandAlerts();
    loadCountryStats();

    setInterval(() => {
        fetchRecentThreats();
        updateStats();
        loadBrandAlerts();
        loadCountryStats();
    }, 15000);
});

async function loadBrandAlerts() {
    const alertSection = document.getElementById('brand-alerts-section');
    const alertList = document.getElementById('brand-alerts-list');
    try {
        const res = await fetch(`${API_BASE_URL}/brand-alerts`);
        const data = await res.json();
        if (data.length > 0) {
            alertSection.classList.remove('hidden');
            alertList.innerHTML = data.map(t => `
                <div class="brand-alert-item">
                    ⚠️ <strong>${t.value}</strong> detected on ${t.source}. (Type: ${t.threat_type})
                </div>
            `).join('');
        } else {
            alertSection.classList.add('hidden');
        }
    } catch (err) { console.error("Brand alert error:", err); }
}

async function loadCountryStats() {
    try {
        const res = await fetch(`${API_BASE_URL}/countries`);
        const data = await res.json();

        const mapData = {};
        for (const [name, count] of Object.entries(data)) {
            const code = countryToCode[name];
            if (code) mapData[code] = count;
        }

        if (!worldMap) {
            worldMap = new jsVectorMap({
                selector: '#world-map',
                map: 'world',
                visualizeData: {
                    scale: ['#dee2e6', '#dc3545'],
                    values: mapData
                },
                onRegionTooltipShow(event, tooltip, code) {
                    const count = mapData[code] || 0;
                    tooltip.text(`${tooltip.text()} - Detected Threats: ${count}`);
                }
            });
        } else {
            worldMap.updateSeries({
                regions: [{ values: mapData }]
            });
        }
    } catch (err) { console.error("Map loading error:", err); }
}

async function fetchRecentThreats() {
    const tableBody = document.getElementById('threat-table-body');
    try {
        const res = await fetch(`${API_BASE_URL}/threats`);
        if (!res.ok) throw new Error('Network response was not ok');
        const data = await res.json();
        tableBody.innerHTML = data.map(t => `
            <tr class="row-malicious">
                <td><span class="badge">${t.type}</span></td>
                <td style="word-break: break-all;">${t.value}</td>
                <td>${t.source}</td>
                <td style="color:#dc3545;">${t.threat_type}</td>
                <td><strong>${t.country || 'Unknown'}</strong></td>
            </tr>
        `).join('');
    } catch (err) {
        console.error("Feed error:", err);
        tableBody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:red;">⚠️ Connection Error: Is the FastAPI backend running?</td></tr>';
    }
}

async function updateStats() {
    try {
        const res = await fetch(`${API_BASE_URL}/stats`);
        const stats = await res.json();
        const ctx = document.getElementById('threatChart').getContext('2d');
        if (threatChart) threatChart.destroy();
        threatChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Phishing', 'Malware', 'Other'],
                datasets: [{
                    label: '# Threats',
                    data: [stats.phishing, stats.malware, stats.other],
                    backgroundColor: ['#dc3545', '#fd7e14', '#007bff']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: { y: { beginAtZero: true } }
            }
        });
    } catch (err) { console.error("Stats error:", err); }
}

async function searchThreat() {
    const val = document.getElementById('search-input').value.trim();
    const resultBox = document.getElementById('search-result');
    if (!val) return;
    try {
        const res = await fetch(`${API_BASE_URL}/search?value=${encodeURIComponent(val)}`);
        const data = await res.json();
        resultBox.classList.remove('hidden');
        if (data.status === 'Malicious') {
            resultBox.className = 'result-box malicious';
            resultBox.innerHTML = `<h3>⚠️ MALICIOUS: ${data.threat_type}</h3><p>Source: ${data.source}</p>`;
        } else {
            resultBox.className = 'result-box safe';
            resultBox.innerHTML = `<h3>✅ SAFE: No threats found</h3>`;
        }
    } catch (err) { resultBox.innerHTML = 'Error searching.'; }
}
