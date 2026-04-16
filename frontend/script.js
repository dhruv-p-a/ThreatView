const API_BASE_URL = 'https://threatview-x92w.onrender.com';
let threatChart;
let worldMap;

// ISO Country Code Mapping
const countryToCode = {
    "India": "IN", "USA": "US", "United States": "US", "Germany": "DE",
    "Russia": "RU", "China": "CN", "Brazil": "BR", "United Kingdom": "GB",
    "Canada": "CA", "France": "FR", "Japan": "JP", "Australia": "AU"
};

document.addEventListener('DOMContentLoaded', () => {
    console.log("ThreatView Production v1.3.0 Initialized");
    refreshAll();
    setInterval(refreshAll, 30000); // 30s auto-refresh
});

/**
 * Orchestrates global refresh based on UI selections
 */
function refreshAll() {
    const role = document.getElementById('role-select')?.value || 'pro';
    fetchRecentThreats(role);
    updateStats();
    loadBrandAlerts();
    loadCountryStats();
}

/**
 * RBAC: Fetch data based on user tier
 */
async function fetchRecentThreats(role = 'free') {
    const tableBody = document.getElementById('threat-table-body');
    const alertBanner = document.getElementById('global-alert');

    try {
        const res = await fetch(`${API_BASE_URL}/threats?role=${role}`);
        if (!res.ok) throw new Error('API Unreachable');
        const data = await res.json();

        tableBody.innerHTML = '';

        if (data.length > 0) {
            // Alert logic: If new Phishing/Malware in top 3, show banner
            const topThreats = data.slice(0, 3);
            const highRisk = topThreats.some(t => t.threat_type === "Phishing" || t.threat_type.includes("Malware"));

            if (highRisk && alertBanner) {
                alertBanner.classList.remove('hidden');
                setTimeout(() => alertBanner.classList.add('hidden'), 8000);
            }

            data.forEach(t => {
                const row = document.createElement('tr');
                row.classList.add('row-malicious');
                row.innerHTML = `
                    <td><span class="badge">${t.type}</span></td>
                    <td style="word-break: break-all;">${t.value}</td>
                    <td><strong>${t.source}</strong></td>
                    <td style="color:#dc3545;">${t.threat_type}</td>
                    <td><strong>${t.country || 'Unknown'}</strong></td>
                `;
                tableBody.appendChild(row);
            });
        }
    } catch (err) {
        console.error("Dashboard error:", err);
        if(tableBody) tableBody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:red;">⚠️ Network Error. Check backend status.</td></tr>';
    }
}

async function loadBrandAlerts() {
    const section = document.getElementById('brand-alerts-section');
    const list = document.getElementById('brand-alerts-list');
    try {
        const res = await fetch(`${API_BASE_URL}/brand-alerts`);
        const data = await res.json();
        if (data.length > 0) {
            section.classList.remove('hidden');
            list.innerHTML = data.map(t => `
                <div class="brand-alert-item" style="border-left:5px solid #dc3545; background:#fff5f5; padding:15px; border-radius:10px; margin-bottom:10px;">
                    🚨 <strong>URGENT:</strong> Brand assets targeted by <strong>${t.value}</strong> on ${t.source}.
                </div>
            `).join('');
        }
    } catch (e) {}
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

        if (window.jsVectorMap && !worldMap) {
            worldMap = new jsVectorMap({
                selector: '#world-map',
                map: 'world',
                visualizeData: { scale: ['#dee2e6', '#dc3545'], values: mapData }
            });
        } else if (worldMap) {
            worldMap.updateSeries({ regions: [{ values: mapData }] });
        }
    } catch (e) {}
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
                    label: 'Threat Count',
                    data: [stats.phishing, stats.malware, stats.other],
                    backgroundColor: ['#dc3545', '#fd7e14', '#28a745'],
                    borderRadius: 8
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    } catch (e) {}
}

async function searchThreat() {
    const val = document.getElementById('search-input').value.trim();
    const resultBox = document.getElementById('search-result');
    if (!val) return;

    resultBox.innerHTML = 'Analyzing...';
    resultBox.classList.remove('hidden');

    try {
        const res = await fetch(`${API_BASE_URL}/search?value=${encodeURIComponent(val)}`);
        const data = await res.json();

        if (data.status === 'Malicious') {
            resultBox.className = 'result-box malicious';
            resultBox.innerHTML = `<h3>⚠️ MALICIOUS: ${data.threat_type}</h3><p>Detected at: ${new Date(data.detected_at).toLocaleString()}</p>`;
        } else {
            resultBox.className = 'result-box safe';
            resultBox.innerHTML = `<h3>✅ SAFE</h3><p>Indicator not found in active database.</p>`;
        }
    } catch (e) { resultBox.innerHTML = 'Error communicating with analyzer.'; }
}
