const API_BASE_URL = 'https://threatview-x92w.onrender.com';
let threatChart;
let worldMap;
let refreshInterval;
let autoHideTimer;

// ISO Country Code Mapping
const countryToCode = {
    "India": "IN", "USA": "US", "United States": "US", "Germany": "DE",
    "Russia": "RU", "China": "CN", "Brazil": "BR", "United Kingdom": "GB",
    "Canada": "CA", "France": "FR", "Japan": "JP", "Australia": "AU",
    "Netherlands": "NL", "Singapore": "SG", "Italy": "IT", "Israel": "IL"
};

/**
 * Initialization
 */
document.addEventListener('DOMContentLoaded', () => {
    console.log("ThreatView Production v1.5.0 Initialized");

    // Initial Load
    refreshAll();

    // Set auto-refresh every 10 seconds
    refreshInterval = setInterval(refreshAll, 10000);

    // Support Enter key for search
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') searchThreat();
        });
    }
});

/**
 * Orchestrates all data fetching
 */
async function refreshAll() {
    const role = document.getElementById('role-select')?.value || 'pro';
    const statusText = document.getElementById('refresh-status');
    const loader = document.getElementById('loading-indicator');

    if (statusText) statusText.innerText = "UPDATING...";
    if (loader) loader.classList.remove('hidden');

    try {
        await Promise.all([
            fetchRecentThreats(role),
            updateStats(),
            loadBrandAlerts(),
            loadCountryStats()
        ]);
        if (statusText) statusText.innerText = "LIVE";
    } catch (err) {
        console.error("Refresh Error:", err);
        if (statusText) statusText.innerText = "OFFLINE";
    } finally {
        if (loader) loader.classList.add('hidden');
    }
}

/**
 * 1. Fetch Intelligence Feed
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
            // Alert logic: Show only if high-risk threats exist
            const highRiskFound = data.some(t => t.threat_type === "Phishing" || t.threat_type.includes("Malware"));

            if (highRiskFound && alertBanner && alertBanner.classList.contains('hidden')) {
                alertBanner.classList.remove('hidden');

                // Auto-hide after 10 seconds
                if (autoHideTimer) clearTimeout(autoHideTimer);
                autoHideTimer = setTimeout(() => {
                    alertBanner.classList.add('hidden');
                }, 10000);
            }

            data.forEach(t => {
                const row = document.createElement('tr');

                // Row Highlighting logic
                if (t.threat_type === "Phishing") {
                    row.classList.add('row-phishing');
                } else if (t.threat_type.includes("Malware")) {
                    row.classList.add('row-malware');
                }

                row.innerHTML = `
                    <td><span class="badge">${t.type}</span></td>
                    <td style="word-break: break-all; font-family: monospace; font-weight: 600;">${t.value}</td>
                    <td><strong>${t.source}</strong></td>
                    <td style="font-weight: 700; color: ${t.threat_type === 'Phishing' ? '#dc3545' : '#1e293b'}">${t.threat_type}</td>
                    <td><img src="https://flagcdn.com/16x12/${(countryToCode[t.country] || 'un').toLowerCase()}.png" style="margin-right:8px"> ${t.country || 'Unknown'}</td>
                `;
                tableBody.appendChild(row);
            });
        }
    } catch (err) {
        if(tableBody) tableBody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:red;">Establishing secure connection...</td></tr>';
    }
}

/**
 * 2. Brand Protection Logic
 */
async function loadBrandAlerts() {
    const section = document.getElementById('brand-alerts-section');
    const list = document.getElementById('brand-alerts-list');
    try {
        const res = await fetch(`${API_BASE_URL}/brand-alerts`);
        const data = await res.json();

        if (data.length > 0) {
            section.classList.remove('hidden');
            list.innerHTML = data.map(t => `
                <div class="brand-alert-item" style="border-left:6px solid #6f42c1; background:#f5f3ff; padding:15px; border-radius:8px; margin-bottom:12px;">
                    🚨 <strong style="color:#5b21b6;">[BRAND ALERT]</strong>
                    Indicator <strong>${t.value}</strong> identified on <strong>${t.source}</strong> as <strong>${t.threat_type}</strong>.
                </div>
            `).join('');
        }
    } catch (e) {}
}

/**
 * 3. Stats & Charts (Chart.js)
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
                    data: [stats.phishing, stats.malware, stats.other],
                    backgroundColor: ['#dc3545', '#fd7e14', '#28a745'],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 1200, easing: 'easeOutElastic' },
                plugins: {
                    legend: { display: false },
                    // Show numbers on top of bars
                    tooltip: { enabled: true }
                },
                scales: {
                    y: { beginAtZero: true, grid: { color: '#f1f5f9' } },
                    x: { grid: { display: false } }
                }
            },
            plugins: [{
                afterDraw: (chart) => {
                    const ctx = chart.ctx;
                    chart.data.datasets.forEach((dataset, i) => {
                        const meta = chart.getDatasetMeta(i);
                        meta.data.forEach((bar, index) => {
                            const data = dataset.data[index];
                            ctx.fillStyle = '#475569';
                            ctx.textAlign = 'center';
                            ctx.font = 'bold 12px Inter';
                            ctx.fillText(data, bar.x, bar.y - 10);
                        });
                    });
                }
            }]
        });
    } catch (e) {}
}

/**
 * 4. Global Map (jsVectorMap)
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
                    scale: ['#f1f5f9', '#fd7e14', '#dc3545'], // Gray -> Orange -> Red
                    values: mapData
                },
                onRegionTooltipShow(event, tooltip, code) {
                    const count = mapData[code] || 0;
                    tooltip.text(`<b>${tooltip.text()}</b><br>Detected Threats: ${count}`);
                }
            });
        } else if (worldMap) {
            worldMap.updateSeries({ regions: [{ values: mapData }] });
        }
    } catch (e) {}
}

/**
 * 5. Search / Indicator Analysis
 */
async function searchThreat() {
    const val = document.getElementById('search-input').value.trim();
    const resultBox = document.getElementById('search-result');
    if (!val) return;

    resultBox.innerHTML = '<div style="text-align:center">🔍 Cross-referencing against global feeds...</div>';
    resultBox.classList.remove('hidden', 'malicious', 'safe');
    resultBox.style.display = 'block';

    try {
        const res = await fetch(`${API_BASE_URL}/search?value=${encodeURIComponent(val)}`);
        const data = await res.json();

        if (data.status === 'Malicious') {
            resultBox.className = 'result-box malicious';
            resultBox.innerHTML = `
                <h3>⚠️ Malicious Indicator Verified</h3>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:10px; margin-top:15px;">
                    <div><strong>Classification:</strong><br>${data.type}</div>
                    <div><strong>Threat Category:</strong><br>${data.threat_type}</div>
                    <div><strong>Intelligence Source:</strong><br>${data.source}</div>
                    <div><strong>Detection Date:</strong><br>${new Date(data.detected_at).toLocaleDateString()}</div>
                </div>
            `;
        } else {
            resultBox.className = 'result-box safe';
            resultBox.innerHTML = `
                <h3>✅ Indicator Appears Safe</h3>
                <p>No active threats matching <strong>${val}</strong> were found in our current intelligence repositories.</p>
            `;
        }
    } catch (e) { resultBox.innerHTML = '<p style="color:red">Analyzer Error. Please check connectivity.</p>'; }
}

function closeAlert() {
    const banner = document.getElementById('global-alert');
    if (banner) banner.classList.add('hidden');
    if (autoHideTimer) clearTimeout(autoHideTimer);
}
