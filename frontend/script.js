const API_BASE_URL = 'https://threatview-x92w.onrender.com';
let threatChart;
let worldMap;

// ISO Country Code Mapping - Expanded for better map coverage
const countryToCode = {
    "India": "IN", "USA": "US", "United States": "US", "Germany": "DE",
    "Russia": "RU", "China": "CN", "Brazil": "BR", "United Kingdom": "GB",
    "Canada": "CA", "France": "FR", "Japan": "JP", "Australia": "AU",
    "Netherlands": "NL", "Singapore": "SG", "Israel": "IL", "Italy": "IT"
};

document.addEventListener('DOMContentLoaded', () => {
    console.log("ThreatView Dashboard v1.2.0 Initialized");

    // Initial data load
    refreshAll();

    // Start auto-refresh timer (every 15 seconds)
    setInterval(refreshAll, 15000);

    // Support for Enter key in search input
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') searchThreat();
        });
    }
});

/**
 * Orchestrates the refresh of all dashboard components
 */
function refreshAll() {
    // Note: We use 'pro' role to bypass the 24h filter for testing/visibility
    fetchRecentThreats('pro');
    updateStats();
    loadBrandAlerts();
    loadCountryStats();
}

/**
 * RBAC: Role-based threat fetching.
 * 'free' returns last 24h, 'pro' returns full history.
 */
async function fetchRecentThreats(role = 'free') {
    const tableBody = document.getElementById('threat-table-body');
    try {
        const res = await fetch(`${API_BASE_URL}/threats?role=${role}`);
        if (!res.ok) throw new Error('Backend Unreachable');
        const data = await res.json();

        tableBody.innerHTML = '';

        if (data.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No threats found in this category.</td></tr>';
            return;
        }

        data.forEach(t => {
            const row = document.createElement('tr');
            row.classList.add('row-malicious');
            row.innerHTML = `
                <td><span class="badge">${t.type}</span></td>
                <td style="word-break: break-all; font-family: monospace;">${t.value}</td>
                <td><strong>${t.source}</strong></td>
                <td style="color:#dc3545;">${t.threat_type}</td>
                <td><strong>${t.country || 'Unknown'}</strong></td>
            `;
            tableBody.appendChild(row);
        });
    } catch (err) {
        console.error("Feed error:", err);
        tableBody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:red;">⚠️ Connection Error: Is the FastAPI backend running?</td></tr>';
    }
}

/**
 * Load critical threats flagged by Brand Protection logic
 */
async function loadBrandAlerts() {
    const alertSection = document.getElementById('brand-alerts-section');
    const alertList = document.getElementById('brand-alerts-list');
    try {
        const res = await fetch(`${API_BASE_URL}/brand-alerts`);
        const data = await res.json();

        if (data.length > 0) {
            alertSection.classList.remove('hidden');
            alertList.innerHTML = data.map(t => `
                <div class="brand-alert-item" style="background:#fff5f5; padding:12px; border-radius:8px; margin-bottom:8px; border-left:5px solid #dc3545;">
                    ⚠️ Brand Threat: <strong>${t.value}</strong> detected on ${t.source}.
                </div>
            `).join('');
        } else {
            alertSection.classList.add('hidden');
        }
    } catch (err) { console.error("Brand alert error:", err); }
}

/**
 * Initialize or update the Global Threat Map visualization
 */
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
                visualizeData: {
                    scale: ['#dee2e6', '#dc3545'], // Light to Dark red
                    values: mapData
                },
                onRegionTooltipShow(event, tooltip, code) {
                    const count = mapData[code] || 0;
                    tooltip.text(`${tooltip.text()} - Threats: ${count}`);
                }
            });
        } else if (worldMap) {
            // Update heat colors if map already exists
            worldMap.updateSeries({
                regions: [{ values: mapData }]
            });
        }
    } catch (err) { console.error("Map loading error:", err); }
}

/**
 * Refresh Chart.js statistics
 */
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
                    backgroundColor: ['#dc3545', '#fd7e14', '#007bff'],
                    borderRadius: 6
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

/**
 * Perform on-demand indicator lookup
 */
async function searchThreat() {
    const val = document.getElementById('search-input').value.trim();
    const resultBox = document.getElementById('search-result');

    if (!val) return;

    resultBox.innerHTML = 'Searching...';
    resultBox.classList.remove('hidden');

    try {
        const res = await fetch(`${API_BASE_URL}/search?value=${encodeURIComponent(val)}`);
        const data = await res.json();

        if (data.status === 'Malicious') {
            resultBox.className = 'result-box malicious';
            resultBox.innerHTML = `<h3>⚠️ MALICIOUS: ${data.threat_type}</h3><p>Source: ${data.source}</p>`;
        } else {
            resultBox.className = 'result-box safe';
            resultBox.innerHTML = `<h3>✅ SAFE: No threats found</h3>`;
        }
    } catch (err) {
        resultBox.innerHTML = 'Error searching backend.';
    }
}
