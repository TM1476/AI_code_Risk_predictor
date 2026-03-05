document.addEventListener('DOMContentLoaded', () => {
    // Initialize Lucide Icons
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }

    // Identify which page we are on
    const path = window.location.pathname;
    
    // If we are on the audit page, run the analysis automatically
    if (path.includes('/audit')) {
        loadAuditReport();
    }
});

/**
 * BUTTON CONNECTION: Captured from analyzer.html
 */
function startPolyAudit() {
    // 1. Get the code from the blue expanding box
    const codeArea = document.getElementById('polyCode');
    const codeContent = codeArea ? codeArea.value : null;

    if (!codeContent || codeContent.trim().length < 5) {
        alert("Input Buffer Empty: Please provide source code for analysis.");
        return;
    }

    // 2. Visual Feedback (Procedure Steps)
    const steps = document.querySelectorAll('.procedure-line span');
    if (steps[1]) steps[1].classList.add('active-step');

    // 3. Save code to browser memory (LocalStorage)
    localStorage.setItem('sentinel_pending_code', codeContent);

    // 4. Redirect to the separate Audit/Complexity page
    setTimeout(() => {
        window.location.href = '/audit';
    }, 600);
}

/**
 * AUDIT PAGE LOGIC: Runs when audit.html loads
 */
async function loadAuditReport() {
    const code = localStorage.getItem('sentinel_pending_code');
    const timeDisplay = document.getElementById('timestamp');
    
    if (!code) {
        window.location.href = '/'; // Redirect home if no code is found
        return;
    }

    try {
        // Fetch analysis from the Python Backend on Render
        const response = await fetch('/api/audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code: code })
        });

        const data = await response.json();

        if (data.status === "success") {
            // --- YOUR COMPLEXITY CHART LOGIC ---
            renderAuditCharts(data);

            // Populate the Threat Detection tags
            const pBox = document.getElementById('patterns');
            if (pBox) {
                pBox.innerHTML = data.details.length > 0 
                    ? data.details.map(v => `<span class="v-badge detected">${v.replace('_', ' ')}</span>`).join('')
                    : '<span class="v-badge" style="color:#3fb950">SECURE LOGIC</span>';
            }

            if (timeDisplay) timeDisplay.innerText = "Analyzed: " + new Date().toLocaleString();
        }
    } catch (err) {
        console.error("Connection failed to Python Kernel:", err);
    }
}

/**
 * VISUALIZATION: Your Chart.js Implementation
 * DO NOT CHANGE: This renders the visual gauges
 */
function renderAuditCharts(data) {
    if (typeof Chart === 'undefined') return;

    // Complexity Gauge
    const ctxComp = document.getElementById('complexityChart');
    if (ctxComp) {
        const compVal = data.complexity === 'A' ? 20 : data.complexity === 'B' ? 60 : 100;
        
        new Chart(ctxComp.getContext('2d'), {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [compVal, 100 - compVal],
                    backgroundColor: [data.complexity === 'A' ? '#3fb950' : '#f85149', '#161b22'],
                    borderWidth: 0,
                    borderRadius: 10
                }]
            },
            options: { cutout: '85%', plugins: { tooltip: { enabled: false } }, animation: { duration: 2000 } }
        });
        document.getElementById('gradeLabel').innerText = data.complexity;
        document.getElementById('gradeLabel').style.color = data.complexity === 'A' ? '#3fb950' : '#f85149';
    }

    // Risk Gauge
    const ctxRisk = document.getElementById('riskChart');
    if (ctxRisk) {
        const riskPct = data.score * 100;
        new Chart(ctxRisk.getContext('2d'), {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [riskPct, 100 - riskPct],
                    backgroundColor: [riskPct > 50 ? '#f85149' : '#3fb1ff', '#161b22'],
                    borderWidth: 0,
                    borderRadius: 10
                }]
            },
            options: { cutout: '85%', plugins: { tooltip: { enabled: false } }, animation: { duration: 2500 } }
        });
        document.getElementById('riskLabel').innerText = riskPct.toFixed(0) + '%';
    }
}
