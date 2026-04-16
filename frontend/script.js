const API_BASE_URL = 'https://threatview-x92w.onrender.com';
let threatChart;
let worldMap;
let refreshInterval;

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
    console.log("ThreatView Production v1.4.0 Initialized");

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
    const role = document.getElementById('role-select')?.value || 'free';
    const statusText = document.getElementById('refresh-status');
    const loader = document.getElementById('loading-indicator');

    if (statusText) statusText.innerText = "Updating...";
    if (loader) loader.classList.remove('hidden');

    try {
        await Promise.all([
            fetchRecentThreats(role),
            updateStats(),
            loadBrandAlerts(),
            loadCountryStats()
        ]);
        if (statusText) statusText.innerText = "Live";
    } catch (err) {
        console.error("Refresh Error:", err);
        if (statusText) statusText.innerText = "Connection Error";
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
            // Check for high-risk threats in recent data
            const highRiskExists = data.some(t => t.threat_type === "Phishing" || t.threat_type.includes("Malware"));

            if (highRiskExists && alertBanner) {
                alertBanner.classList.remove('hidden');
            }

            data.forEach(t => {
                const isHighRisk = t.threat_type === "Phishing" || t.threat_type.includes("Malware");
                const row = document.createElement('tr');
                if (isHighRisk) row.classList.add('row-high-risk');

                row.innerHTML = `
                    <td><span class="badge">${t.type}</span></td>
                    <td style="word-break: break-all; font-family: monospace; font-weight: 500;">${t.value}</td>
                    <td><strong>${t.source}</strong></td>
                    <td style="color: ${isHighRisk ? '#dc3545' : '#2d3436'}; font-weight: 600;">${t.threat_type}</td>
                    <td><strong>${t.country || 'Unknown'}</strong></td>
                `;
                tableBody.appendChild(row);
            });
        } else {
            tableBody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No data available for the selected tier.</td></tr>';
        }
    } catch (err) {
        tableBody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:red;">⚠️ Error connecting to Intelligence API.</td></tr>';
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
            list.innerHTML = data.map(t => {
                const color = t.threat_type === "Phishing" ? "var(--error-color)" : "var(--brand-purple)";
                return `
                    <div class="brand-alert-item" style="border-color: ${color}; background: ${color}08;">
                        <span style="color: ${color}; font-weight: 800;">[ALERT]</span>
                        Brand asset <strong>${t.value}</strong> targeted via <strong>${t.threat_type}</strong> on ${t.source}.
                    </div>
                `;
            }).join('');
        } else {
            section.classList.add('hidden');
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
                    label: 'Threat Volume',
                    data: [stats.phishing, stats.malware, stats.other],
                    backgroundColor: ['#dc3545', '#fd7e14', '#28a745'],
                    borderRadius: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 1500, easing: 'easeOutQuart' },
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: { beginAtZero: true, grid: { display: false } },
                    x: { grid: { display: false } }
                }
            }
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
                zoomButtons: true,
                visualizeData: {
                    scale: ['#f1f5f9', '#dc3545'], // Subtle blue-grey to deep red
                    values: mapData
                },
                onRegionTooltipShow(event, tooltip, code) {
                    const count = mapData[code] || 0;
                    tooltip.text(`${tooltip.text()} | Threats: ${count}`);
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

    resultBox.innerHTML = '<div class="searching">🔍 Cross-referencing indicator...</div>';
    resultBox.classList.remove('hidden', 'malicious', 'safe');
    resultBox.style.display = 'block';

    try {
        const res = await fetch(`${API_BASE_URL}/search?value=${encodeURIComponent(val)}`);
        const data = await res.json();

        if (data.status === 'Malicious') {
            resultBox.className = 'result-box malicious';
            resultBox.innerHTML = `
                <h3>⚠️ Malicious Activity Detected</h3>
                <p><strong>Type:</strong> ${data.threat_type}</p>
                <p><strong>Source:</strong> ${data.source}</p>
                <p><strong>First Seen:</strong> ${new Date(data.detected_at).toLocaleString()}</p>
            `;
        } else {
            resultBox.className = 'result-box safe';
            resultBox.innerHTML = `
                <h3>✅ No Threats Detected</h3>
                <p>Indicator <strong>${val}</strong> was not found in our active intelligence feeds.</p>
            `;
        }
    } catch (e) {
        resultBox.innerHTML = '<p style="color:red">Analyzer Offline. Try again later.</p>';
    }
}

/**
 * UI Helper: Close Top Alert
 */
function closeAlert() {
    const banner = document.getElementById('global-alert');
    if (banner) banner.classList.add('hidden');
}
