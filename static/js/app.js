/* ═══════════════════════════════════════════════════════════════════════════
   CyberShield — Enterprise Threat Intelligence Platform
   Main Application JS
═══════════════════════════════════════════════════════════════════════════ */

"use strict";

// ─── Global State ─────────────────────────────────────────────────────────────
const State = {
    currentPage: 'dashboard',
    dashboardData: null,
    charts: {},
};

// ─── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initParticles();
    startClock();
    loadAPIStatus();
    showPage('dashboard');
    setInterval(loadAPIStatus, 60000);
});

// ─── Particles ─────────────────────────────────────────────────────────────────
function initParticles() {
    if (typeof particlesJS === 'undefined') return;
    particlesJS('particles-js', {
        particles: {
            number: { value: 60, density: { enable: true, value_area: 900 } },
            color: { value: '#00d9ff' },
            shape: { type: 'circle' },
            opacity: { value: 0.15, random: true, anim: { enable: true, speed: 0.4, opacity_min: 0.03 } },
            size: { value: 2, random: true },
            line_linked: { enable: true, distance: 130, color: '#00d9ff', opacity: 0.06, width: 1 },
            move: { enable: true, speed: 0.6, direction: 'none', random: true, straight: false, out_mode: 'out' },
        },
        interactivity: {
            detect_on: 'canvas',
            events: { onhover: { enable: true, mode: 'grab' }, onclick: { enable: false }, resize: true },
            modes: { grab: { distance: 140, line_linked: { opacity: 0.2 } } },
        },
        retina_detect: true,
    });
}

// ─── Clock ────────────────────────────────────────────────────────────────────
function startClock() {
    const el = document.getElementById('clock');
    function tick() {
        const now = new Date();
        el.textContent = now.toLocaleTimeString('en-US', { hour12: false }) + ' UTC' +
            (now.getTimezoneOffset() < 0 ? '+' : '-') +
            String(Math.abs(now.getTimezoneOffset() / 60)).padStart(2, '0');
    }
    tick();
    setInterval(tick, 1000);
}

// ─── Navigation ───────────────────────────────────────────────────────────────
function showPage(pageId) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const page = document.getElementById('page-' + pageId);
    const nav = document.getElementById('nav-' + pageId);
    if (page) page.classList.add('active');
    if (nav) nav.classList.add('active');

    State.currentPage = pageId;

    const titles = {
        dashboard: 'Dashboard',
        feeds: 'Real-Time Threat Feeds',
        ingest: 'Data Ingestion',
        ioc: 'IOC Analysis',
        campaigns: 'Campaign Analysis',
        analytics: 'Advanced AI Analytics',
        analyst: 'AI Threat Analyst Chat',
        performance: 'Performance Metrics',
    };
    document.getElementById('pageTitle').textContent = titles[pageId] || pageId;

    // Load page-specific data
    if (pageId === 'dashboard') loadDashboard();
    else if (pageId === 'campaigns') loadCampaigns();
    else if (pageId === 'performance') loadPerformance();
    else if (pageId === 'analytics') loadAnalytics();

    // Close sidebar on mobile
    document.getElementById('sidebar').classList.remove('open');
}

// Nav click listeners
document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => showPage(btn.dataset.page));
});

// Mobile menu toggle
document.getElementById('menuToggle').addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('open');
});

// ─── API Status ────────────────────────────────────────────────────────────────
async function loadAPIStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        setStatus('st-otx', data.alienvault_otx);
        setStatus('st-vt', data.virustotal);
        setStatus('st-abuse', data.abuseipdb);
        setStatus('st-llm', true, data.llm_model || 'LLM');
    } catch (e) {
        ['st-otx', 'st-vt', 'st-abuse', 'st-llm'].forEach(id => setStatus(id, false));
    }
}

function setStatus(id, online, label) {
    const el = document.getElementById(id);
    if (!el) return;
    const dot = el.querySelector('.status-dot');
    if (dot) {
        dot.className = 'status-dot ' + (online ? 'online' : 'offline');
    }
    if (label) el.textContent = '';
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
async function loadDashboard() {
    showLoading('Loading threat intelligence data...');
    try {
        const res = await fetch('/api/dashboard/stats');
        const data = await res.json();
        State.dashboardData = data;

        updateKPIs(data);
        updateThreatLevel(data.threat_level);
        renderThreatMap(data.country_attacks);
        renderSectorChart(data.sector_data);
        renderHeatmap(data.heatmap);
        renderTimelineChart(data.timeline);
        renderIocChart(data.ioc_types);
        renderRecentDocs(data.recent_documents);

    } catch (e) {
        showNotification('Failed to load dashboard: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

function updateKPIs(data) {
    animateCount('kpiDocs', data.total_documents);
    animateCount('kpiCampaigns', data.active_campaigns);
    animateCount('kpiIocs', data.ioc_count);
    animateCount('kpiSources', data.source_count);
}

function animateCount(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    const start = parseInt(el.textContent) || 0;
    const duration = 1200;
    const startTime = performance.now();
    function tick(now) {
        const progress = Math.min((now - startTime) / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(start + (target - start) * ease).toLocaleString();
        if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
}

function updateThreatLevel(tl) {
    if (!tl) return;
    const pill = document.getElementById('threatLevelPill');
    const dot = pill.querySelector('.tl-dot');
    const text = pill.querySelector('.tl-text');
    text.textContent = tl.level + ' (' + tl.score + '%)';
    dot.style.background = tl.color;
    dot.style.boxShadow = `0 0 8px ${tl.color}`;
    pill.className = 'threat-level-pill tl-' + tl.level.toLowerCase();
}

// ─── Threat Map (D3 + TopoJSON) ────────────────────────────────────────────────
async function renderThreatMap(countryAttacks) {
    const container = document.getElementById('threatMap');
    container.innerHTML = '';

    const W = container.clientWidth || 600;
    const H = 280;

    const svg = d3.select('#threatMap')
        .append('svg')
        .attr('width', W)
        .attr('height', H)
        .style('background', 'transparent');

    const projection = d3.geoNaturalEarth1()
        .scale(W / 2 / Math.PI * 0.9)
        .translate([W / 2, H / 2]);

    const path = d3.geoPath().projection(projection);

    // ISO country code map
    const isoMap = {
        'US': 840, 'CN': 156, 'RU': 643, 'IN': 356, 'DE': 276,
        'GB': 826, 'FR': 250, 'BR': 76, 'AU': 36, 'JP': 392,
        'KR': 410, 'CA': 124, 'IT': 380, 'NL': 528, 'SG': 702, 'ZA': 710
    };

    const maxVal = Math.max(...Object.values(countryAttacks), 1);

    function getColor(iso2) {
        const val = countryAttacks[iso2] || 0;
        if (val === 0) return '#0d1e35';
        const ratio = val / maxVal;
        if (ratio > 0.8) return '#ff1744';
        if (ratio > 0.5) return '#ff6d00';
        if (ratio > 0.2) return '#ffd600';
        return '#00e676';
    }

    try {
        const world = await d3.json('/static/assets/countries-110m.json');
        const countries = topojson.feature(world, world.objects.countries);

        // Map numeric IDs to ISO2
        const numToIso2 = {};
        for (const [iso2, num] of Object.entries(isoMap)) {
            numToIso2[String(num)] = iso2;
        }

        svg.selectAll('path')
            .data(countries.features)
            .enter()
            .append('path')
            .attr('d', path)
            .attr('fill', d => getColor(numToIso2[String(d.id)] || ''))
            .attr('stroke', '#1a2f4a')
            .attr('stroke-width', 0.3)
            .style('cursor', 'pointer')
            .style('transition', 'opacity .2s')
            .on('mouseover', function (event, d) {
                const iso2 = numToIso2[String(d.id)] || '';
                const val = countryAttacks[iso2] || 0;
                if (iso2) {
                    d3.select(this).attr('stroke', '#00d9ff').attr('stroke-width', 1.5);
                    showMapTooltip(event, iso2, val);
                }
            })
            .on('mouseout', function () {
                d3.select(this).attr('stroke', '#1a2f4a').attr('stroke-width', 0.3);
                hideMapTooltip();
            });

        // Add pulse circles for high-attack countries
        for (const [iso2, val] of Object.entries(countryAttacks)) {
            if (val > 0) {
                // Rough centroids
                const centroids = {
                    'US': [-95, 38], 'CN': [105, 35], 'RU': [60, 55], 'IN': [78, 22],
                    'DE': [10, 51], 'GB': [-2, 54], 'FR': [2, 46], 'BR': [-53, -10],
                    'AU': [134, -26], 'JP': [138, 37], 'KR': [127, 36], 'CA': [-95, 60],
                    'IT': [12, 43], 'NL': [5, 52], 'SG': [104, 1], 'ZA': [25, -29],
                };
                const coord = centroids[iso2];
                if (!coord) continue;
                const [cx, cy] = projection(coord);
                if (!cx || !cy) continue;
                const r = 2 + (val / maxVal) * 8;
                const color = getColor(iso2);

                // Pulse ring
                const pulse = svg.append('circle')
                    .attr('cx', cx).attr('cy', cy)
                    .attr('r', r)
                    .attr('fill', 'none')
                    .attr('stroke', color)
                    .attr('stroke-width', 1.5)
                    .attr('opacity', 0.8);

                pulse.append('animate')
                    .attr('attributeName', 'r')
                    .attr('from', r).attr('to', r * 3)
                    .attr('dur', '2s').attr('repeatCount', 'indefinite');

                pulse.append('animate')
                    .attr('attributeName', 'opacity')
                    .attr('from', 0.8).attr('to', 0)
                    .attr('dur', '2s').attr('repeatCount', 'indefinite');

                svg.append('circle')
                    .attr('cx', cx).attr('cy', cy).attr('r', r)
                    .attr('fill', color).attr('opacity', 0.9);
            }
        }

    } catch (e) {
        // Fallback: simple text display
        container.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:center;height:280px;color:#3d526a;font-family:var(--font-mono);font-size:.8rem;">
        Map data unavailable (network required for TopoJSON)<br>
        <span style="color:#00d9ff;margin-top:.5rem;">Top attack sources loaded in charts</span>
      </div>`;
    }
}

function showMapTooltip(event, iso2, val) {
    let tip = document.getElementById('mapTip');
    if (!tip) {
        tip = document.createElement('div');
        tip.id = 'mapTip';
        tip.style.cssText = `position:fixed;background:#080f1e;border:1px solid rgba(0,217,255,0.3);
      border-radius:6px;padding:6px 10px;font-family:'JetBrains Mono',monospace;font-size:.72rem;
      color:#00d9ff;pointer-events:none;z-index:9999;`;
        document.body.appendChild(tip);
    }
    tip.textContent = `${iso2}: ${val} attacks`;
    tip.style.left = (event.clientX + 12) + 'px';
    tip.style.top = (event.clientY - 30) + 'px';
    tip.style.display = 'block';
}

function hideMapTooltip() {
    const tip = document.getElementById('mapTip');
    if (tip) tip.style.display = 'none';
}

// ─── Sector Chart ─────────────────────────────────────────────────────────────
function renderSectorChart(sectorData) {
    const ctx = document.getElementById('sectorChart');
    if (!ctx) return;
    if (State.charts.sector) State.charts.sector.destroy();

    const labels = Object.keys(sectorData);
    const values = Object.values(sectorData);

    const colors = [
        '#00d9ff', '#7b2ff7', '#ff6d00', '#ff1744',
        '#00e676', '#ffd600', '#0066ff', '#ff4081'
    ];

    State.charts.sector = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: colors.map(c => c + '33'),
                borderColor: colors,
                borderWidth: 2,
                hoverBackgroundColor: colors.map(c => c + '66'),
                hoverBorderWidth: 3,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#7a92b4',
                        font: { family: "'Space Grotesk'" },
                        boxWidth: 10,
                        padding: 10,
                    }
                },
                tooltip: {
                    backgroundColor: '#080f1e',
                    borderColor: 'rgba(0,217,255,0.3)',
                    borderWidth: 1,
                    titleColor: '#00d9ff',
                    bodyColor: '#e2eaf5',
                    callbacks: {
                        label: ctx => ` ${ctx.label}: ${ctx.parsed} threats`
                    }
                }
            },
            animation: { animateScale: true, animateRotate: true, duration: 1200 },
        }
    });
}

// ─── Heatmap (D3) ─────────────────────────────────────────────────────────────
function renderHeatmap(heatmapData) {
    const container = document.getElementById('heatmapChart');
    if (!container) return;
    container.innerHTML = '';

    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const hours = d3.range(24);
    const cellW = 26, cellH = 28, marginLeft = 48, marginTop = 30;
    const W = cellW * 24 + marginLeft + 20;
    const H = cellH * 7 + marginTop + 20;

    const maxVal = d3.max(heatmapData, d => d.value) || 1;

    const colorScale = d3.scaleSequential()
        .domain([0, maxVal])
        .interpolator(t => {
            const colors = ['#030912', '#0a1f3a', '#00d9ff44', '#00d9ff', '#7b2ff7', '#ff1744'];
            const i = Math.min(Math.floor(t * (colors.length - 1)), colors.length - 2);
            const f = t * (colors.length - 1) - i;
            return d3.interpolateRgb(colors[i], colors[i + 1])(f);
        });

    const svg = d3.select('#heatmapChart')
        .append('svg')
        .attr('width', W).attr('height', H);

    // Hour labels
    hours.forEach(h => {
        if (h % 3 === 0) {
            svg.append('text')
                .attr('x', marginLeft + h * cellW + cellW / 2)
                .attr('y', marginTop - 6)
                .attr('text-anchor', 'middle')
                .attr('fill', '#3d526a')
                .attr('font-size', '9px')
                .attr('font-family', "'JetBrains Mono'")
                .text(h + ':00');
        }
    });

    // Day labels
    days.forEach((day, i) => {
        svg.append('text')
            .attr('x', marginLeft - 6)
            .attr('y', marginTop + i * cellH + cellH / 2 + 4)
            .attr('text-anchor', 'end')
            .attr('fill', '#7a92b4')
            .attr('font-size', '10px')
            .attr('font-family', "'JetBrains Mono'")
            .text(day);
    });

    // Cells
    heatmapData.forEach(d => {
        const dayIdx = days.indexOf(d.day);
        const hourIdx = d.hour;
        if (dayIdx < 0) return;

        const rect = svg.append('rect')
            .attr('x', marginLeft + hourIdx * cellW)
            .attr('y', marginTop + dayIdx * cellH)
            .attr('width', cellW - 2)
            .attr('height', cellH - 2)
            .attr('rx', 3)
            .attr('fill', colorScale(d.value))
            .attr('stroke', 'rgba(0,217,255,0.05)')
            .attr('stroke-width', 0.5)
            .style('cursor', 'pointer')
            .on('mouseover', function (event) {
                d3.select(this).attr('stroke', '#00d9ff').attr('stroke-width', 1.5);
                showMapTooltip(event, `${d.day} ${d.hour}:00`, d.value);
            })
            .on('mouseout', function () {
                d3.select(this).attr('stroke', 'rgba(0,217,255,0.05)').attr('stroke-width', 0.5);
                hideMapTooltip();
            });

        // Entrance animation
        rect.attr('opacity', 0)
            .transition()
            .delay(dayIdx * 50 + hourIdx * 8)
            .duration(400)
            .attr('opacity', 1);
    });
}

// ─── Timeline Chart ───────────────────────────────────────────────────────────
function renderTimelineChart(timeline) {
    const ctx = document.getElementById('timelineChart');
    if (!ctx) return;
    if (State.charts.timeline) State.charts.timeline.destroy();

    const labels = timeline.map(d => d.date);
    const values = timeline.map(d => d.count);

    const grad = ctx.getContext('2d').createLinearGradient(0, 0, 0, 240);
    grad.addColorStop(0, 'rgba(0,217,255,0.25)');
    grad.addColorStop(1, 'rgba(0,217,255,0)');

    State.charts.timeline = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: 'Documents',
                data: values,
                borderColor: '#00d9ff',
                backgroundColor: grad,
                borderWidth: 2,
                pointBackgroundColor: '#00d9ff',
                pointBorderColor: '#030912',
                pointBorderWidth: 2,
                pointRadius: 4,
                tension: 0.4,
                fill: true,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: cyberTooltip(),
            },
            scales: {
                x: cyberScaleX(),
                y: cyberScaleY('Documents'),
            },
        }
    });
}

// ─── IOC Chart ────────────────────────────────────────────────────────────────
function renderIocChart(iocTypes) {
    const ctx = document.getElementById('iocChart');
    if (!ctx) return;
    if (State.charts.ioc) State.charts.ioc.destroy();

    const labels = Object.keys(iocTypes);
    const values = Object.values(iocTypes);

    const colors = ['#00d9ff', '#7b2ff7', '#ff6d00', '#ff1744', '#00e676', '#ffd600'];

    State.charts.ioc = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'IOCs',
                data: values,
                backgroundColor: colors.map(c => c + '33'),
                borderColor: colors,
                borderWidth: 2,
                borderRadius: 6,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: cyberTooltip(),
            },
            scales: {
                x: cyberScaleX(),
                y: cyberScaleY('Count'),
            },
        }
    });
}

// ─── Chart helper styles ──────────────────────────────────────────────────────
function cyberTooltip() {
    return {
        backgroundColor: '#080f1e',
        borderColor: 'rgba(0,217,255,0.3)',
        borderWidth: 1,
        titleColor: '#00d9ff',
        bodyColor: '#e2eaf5',
        padding: 10,
    };
}

function cyberScaleX() {
    return {
        ticks: { color: '#3d526a', font: { family: "'JetBrains Mono'", size: 10 } },
        grid: { color: 'rgba(0,217,255,0.04)', drawBorder: false },
        border: { color: 'transparent' },
    };
}

function cyberScaleY(label) {
    return {
        ticks: { color: '#3d526a', font: { family: "'JetBrains Mono'", size: 10 } },
        grid: { color: 'rgba(0,217,255,0.06)', drawBorder: false },
        border: { color: 'transparent' },
        title: { display: !!label, text: label, color: '#7a92b4', font: { size: 10 } },
    };
}

// ─── Recent Docs Table ────────────────────────────────────────────────────────
function renderRecentDocs(docs) {
    const tbody = document.getElementById('recentDocsTbody');
    if (!tbody) return;
    if (!docs || !docs.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="loading-row">No documents yet. Ingest some data!</td></tr>';
        return;
    }
    tbody.innerHTML = docs.map(d => `
    <tr>
      <td style="color:#7a92b4;font-family:var(--font-mono)">#${d.id}</td>
      <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(d.title || 'Untitled')}</td>
      <td><span class="badge badge-${(d.source_type || 'manual').toLowerCase()}">${d.source_type || 'manual'}</span></td>
      <td style="color:#7a92b4;font-family:var(--font-mono);font-size:.72rem">${formatDate(d.timestamp)}</td>
      <td><button class="btn-delete" onclick="deleteDoc(${d.id})">🗑</button></td>
    </tr>`).join('');
}

async function loadRecentDocs() {
    try {
        const res = await fetch('/api/documents?limit=20');
        const data = await res.json();
        renderRecentDocs(data.documents);
        const tbody = document.getElementById('feedDocsTbody');
        if (tbody) {
            tbody.innerHTML = data.documents.map(d => `
        <tr>
          <td style="color:#7a92b4;font-family:var(--font-mono)">#${d.id}</td>
          <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(d.title)}</td>
          <td><span class="badge badge-${(d.source_type || 'manual').toLowerCase()}">${d.source_type || 'manual'}</span></td>
          <td style="color:#7a92b4;font-family:var(--font-mono);font-size:.72rem">${formatDate(d.timestamp)}</td>
        </tr>`).join('') || '<tr><td colspan="4" class="loading-row">No data</td></tr>';
        }
    } catch (e) { }
}

async function deleteDoc(id) {
    if (!confirm(`Delete document #${id}?`)) return;
    try {
        const res = await fetch('/api/documents/' + id, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) { showNotification('Document deleted', 'success'); loadDashboard(); }
        else showNotification('Delete failed', 'error');
    } catch (e) { showNotification('Error: ' + e.message, 'error'); }
}

// ─── Feeds ────────────────────────────────────────────────────────────────────
async function fetchFeed(source) {
    showLoading(`Fetching from ${source}...`);
    try {
        const res = await fetch('/api/feeds/fetch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source })
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        showNotification(`✓ Ingested ${data.ingested} documents from ${source}`, 'success');
        loadRecentDocs();
    } catch (e) {
        showNotification('Feed error: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

// ─── Ingest ───────────────────────────────────────────────────────────────────
async function uploadDocument() {
    const title = document.getElementById('docTitle').value.trim();
    const content = document.getElementById('docContent').value.trim();
    const source = document.getElementById('docSource').value;
    const url = document.getElementById('docUrl').value.trim();
    const result = document.getElementById('uploadResult');

    if (!content) { showNotification('Please enter document content', 'error'); return; }

    showLoading('Processing document...');
    try {
        const res = await fetch('/api/documents/upload', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title: title || 'Untitled', content, source_type: source, url })
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);

        result.className = 'upload-result result-success';
        result.innerHTML = `
      <strong>✓ Document processed successfully!</strong><br>
      ID: #${data.doc_id} &nbsp;|&nbsp;
      IOCs Extracted: ${data.iocs_extracted} &nbsp;|&nbsp;
      TTPs Extracted: ${data.ttps_extracted}`;

        showNotification('Document ingested successfully', 'success');
        document.getElementById('docContent').value = '';
        document.getElementById('docTitle').value = '';
    } catch (e) {
        result.className = 'upload-result result-error';
        result.innerHTML = '✗ Error: ' + e.message;
        showNotification('Upload failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

async function ingestBlog() {
    const url = document.getElementById('blogUrl').value.trim();
    const result = document.getElementById('blogResult');

    if (!url) { showNotification('Please enter a URL', 'error'); return; }

    showLoading('Ingesting blog post...');
    try {
        const res = await fetch('/api/ingest/blog', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);

        result.className = 'upload-result result-success';
        result.innerHTML = `✓ <strong>${escHtml(data.title)}</strong><br>IOCs: ${data.iocs} | TTPs: ${data.ttps}`;
        showNotification('Blog post ingested!', 'success');
    } catch (e) {
        result.className = 'upload-result result-error';
        result.innerHTML = '✗ ' + e.message;
        showNotification('Blog ingest failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

// ─── Manage Data ──────────────────────────────────────────────────────────────
async function ingestKafka() {
    const topic = document.getElementById('kafkaTopic').value.trim();
    const result = document.getElementById('kafkaResult');

    if (!topic) { showNotification('Please enter a Kafka topic', 'error'); return; }

    showLoading('Ingesting stream & fusing campaigns...');
    try {
        const res = await fetch('/api/ingest/kafka', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ topic })
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);

        result.className = 'upload-result result-success';
        result.innerHTML = `✓ <strong>Stream Ingested</strong><br>New Documents: ${data.ingested} | Campaigns Updated: ${data.campaigns_updated}`;
        showNotification(data.message || 'Stream successfully processed', 'success');
    } catch (e) {
        result.className = 'upload-result result-error';
        result.innerHTML = '✗ ' + e.message;
        showNotification('Stream ingest failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

// ─── Manage Data ──────────────────────────────────────────────────────────────
async function loadManageTable() {
    try {
        const res = await fetch('/api/documents?limit=200');
        const data = await res.json();
        const tbody = document.getElementById('manageTbody');
        if (!data.documents.length) {
            tbody.innerHTML = '<tr><td colspan="5" class="loading-row">No documents</td></tr>';
            return;
        }
        tbody.innerHTML = data.documents.map(d => `
      <tr>
        <td style="font-family:var(--font-mono);color:#7a92b4">#${d.id}</td>
        <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(d.title || 'Untitled')}</td>
        <td><span class="badge badge-${(d.source_type || 'manual').toLowerCase()}">${d.source_type || 'manual'}</span></td>
        <td style="font-family:var(--font-mono);font-size:.72rem;color:#7a92b4">${formatDate(d.timestamp)}</td>
        <td><button class="btn-delete" onclick="deleteDoc(${d.id})">🗑 Delete</button></td>
      </tr>`).join('');
    } catch (e) { showNotification('Error loading documents', 'error'); }
}

// Switch tabs in ingest
function switchTab(page, tab, btn) {
    document.querySelectorAll(`#page-${page} .tab-content`).forEach(t => t.classList.remove('active'));
    document.querySelectorAll(`#page-${page} .tab-btn`).forEach(b => b.classList.remove('active'));
    const tabEl = document.getElementById(`${page}-tab-${tab}`);
    if (tabEl) tabEl.classList.add('active');
    btn.classList.add('active');

    if (tab === 'manage') loadManageTable();
}

// ─── IOC ──────────────────────────────────────────────────────────────────────
async function analyzeIoc() {
    const val = document.getElementById('iocSearch').value.trim();
    const panel = document.getElementById('iocResult');
    if (!val) { showNotification('Enter an IOC value to analyze', 'info'); return; }

    showLoading('Analyzing IOC...');
    panel.style.display = 'none';
    try {
        const res = await fetch('/api/iocs/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ioc: val })
        });
        const data = await res.json();
        panel.style.display = 'block';

        if (data.found) {
            panel.innerHTML = `
        <h3 style="color:var(--cyan);margin-bottom:.75rem">
          <svg viewBox="0 0 24 24" style="width:16px;height:16px;stroke:var(--cyan);fill:none;stroke-width:2;vertical-align:middle;margin-right:6px"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          IOC Analyzed: ${escHtml(val)}
        </h3>
        <div style="background:rgba(0,217,255,0.04);border-radius:8px;padding:1rem;font-family:var(--font-mono);font-size:.82rem;color:var(--text-primary);white-space:pre-wrap;line-height:1.7">
          ${escHtml(data.llm_analysis || JSON.stringify(data, null, 2))}
        </div>`;
        } else {
            panel.innerHTML = `
        <div style="color:var(--orange);font-family:var(--font-mono)">
          ⚠ IOC not found in database: <strong>${escHtml(val)}</strong><br>
          <span style="color:var(--text-muted)">${escHtml(data.message || 'No data available')}</span>
        </div>`;
        }
    } catch (e) {
        panel.style.display = 'block';
        panel.innerHTML = `<div style="color:var(--red)">Error: ${e.message}</div>`;
    } finally {
        hideLoading();
    }
}

async function loadIocs() {
    try {
        const res = await fetch('/api/iocs');
        const data = await res.json();
        const tbody = document.getElementById('iocTableBody');
        if (!data.iocs.length) {
            tbody.innerHTML = '<tr><td colspan="4" class="loading-row">No IOCs tracked yet</td></tr>';
            return;
        }
        tbody.innerHTML = data.iocs.map(ioc => {
            const conf = Math.round((ioc.confidence || 0) * 100);
            return `
        <tr>
          <td><span class="badge badge-${ioc.type}">${ioc.type}</span></td>
          <td style="font-family:var(--font-mono);font-size:.78rem;color:var(--cyan)">${escHtml(ioc.value)}</td>
          <td>
            <div class="confidence-bar">
              <div class="conf-track"><div class="conf-fill" style="width:${conf}%"></div></div>
              <span style="font-family:var(--font-mono);font-size:.7rem;color:#7a92b4">${conf}%</span>
            </div>
          </td>
          <td style="font-family:var(--font-mono);font-size:.72rem;color:#7a92b4">${formatDate(ioc.last_seen)}</td>
        </tr>`;
        }).join('');
    } catch (e) { }
}

// Search on Enter
document.getElementById('iocSearch').addEventListener('keydown', e => {
    if (e.key === 'Enter') analyzeIoc();
});

// ─── Campaigns ────────────────────────────────────────────────────────────────
async function loadCampaigns() {
    try {
        const res = await fetch('/api/campaigns');
        const data = await res.json();
        const tbody = document.getElementById('campaignTbody');
        if (!data.campaigns.length) {
            tbody.innerHTML = '<tr><td colspan="5" class="loading-row">No campaigns yet. Run Fusion Analysis to detect campaigns.</td></tr>';
            return;
        }
        tbody.innerHTML = data.campaigns.map(c => {
            const conf = Math.round((c.confidence || 0) * 100);
            const docIds = JSON.parse(c.document_ids || '[]');
            return `
        <tr>
          <td style="font-family:var(--font-mono);color:#7a92b4">#${c.id}</td>
          <td style="color:var(--cyan);font-weight:600">${escHtml(c.name)}</td>
          <td>
            <div class="confidence-bar">
              <div class="conf-track"><div class="conf-fill" style="width:${conf}%"></div></div>
              <span style="font-family:var(--font-mono);font-size:.7rem;color:#7a92b4">${conf}%</span>
            </div>
          </td>
          <td style="font-family:var(--font-mono)">${docIds.length}</td>
          <td style="font-family:var(--font-mono);font-size:.72rem;color:#7a92b4">${formatDate(c.created_at)}</td>
        </tr>`;
        }).join('');
    } catch (e) { }
}

async function runFusion() {
    const statusEl = document.getElementById('fusionStatus');
    statusEl.textContent = 'Running fusion analysis...';
    showLoading('Running Fusion Analysis...');
    try {
        const res = await fetch('/api/campaigns/run-fusion', { method: 'POST' });
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        statusEl.textContent = `✓ Found ${data.campaigns_found} campaigns | IOC correlations: ${data.ioc_correlations} | TTP: ${data.ttp_correlations}`;
        showNotification(`Fusion complete! ${data.campaigns_found} campaigns detected.`, 'success');
        loadCampaigns();
    } catch (e) {
        statusEl.textContent = '✗ Error: ' + e.message;
        showNotification('Fusion failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

// ─── AI Analytics ─────────────────────────────────────────────────────────────

async function loadAnalytics() {
    try {
        const res = await fetch('/api/campaigns');
        const data = await res.json();
        const select = document.getElementById('profileCampaignSelect');
        if (data.campaigns.length === 0) {
            select.innerHTML = '<option value="">-- No campaigns available --</option>';
            return;
        }
        select.innerHTML = '<option value="">-- Select a Campaign --</option>' +
            data.campaigns.map(c => `<option value="${c.id}">${escHtml(c.name)}</option>`).join('');
    } catch (e) { }
}

function switchAnalyticsTab(tab, btn) {
    document.querySelectorAll('#page-analytics .tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('#page-analytics .tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(`analytics-tab-${tab}`).classList.add('active');
    btn.classList.add('active');
}

async function generateProfile() {
    const campaignId = document.getElementById('profileCampaignSelect').value;
    if (!campaignId) {
        showNotification('Please select a campaign', 'info');
        return;
    }

    showLoading('Generating Threat Actor Profile (this may take a minute)...');
    const card = document.getElementById('profileResultCard');
    const body = document.getElementById('profileResultBody');
    card.style.display = 'none';

    try {
        const res = await fetch('/api/analytics/profile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ campaign_id: parseInt(campaignId) })
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);

        card.style.display = 'block';
        body.innerHTML = marked.parse(data.profile);
        showNotification('Profile generated successfully', 'success');
    } catch (e) {
        showNotification('Error: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

async function generatePrediction() {
    showLoading('Analyzing historical data to predict next attack...');
    const card = document.getElementById('predictResultCard');
    const body = document.getElementById('predictResultBody');
    card.style.display = 'none';

    try {
        const res = await fetch('/api/analytics/predict', { method: 'POST' });
        const data = await res.json();
        if (data.error) throw new Error(data.error);

        card.style.display = 'block';
        body.innerHTML = marked.parse(data.prediction);
        showNotification('Prediction completed', 'success');
    } catch (e) {
        showNotification('Error: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

async function generateReport() {
    showLoading('Generating comprehensive executive report...');
    const card = document.getElementById('reportResultCard');
    const body = document.getElementById('reportResultBody');
    const pdfBtn = document.getElementById('btnDownloadPdf');
    card.style.display = 'none';
    if (pdfBtn) pdfBtn.style.display = 'none';

    try {
        const res = await fetch('/api/analytics/report', { method: 'POST' });
        const data = await res.json();
        if (data.error) throw new Error(data.error);

        card.style.display = 'block';
        body.innerHTML = marked.parse(data.report);
        body.setAttribute('data-raw-report', encodeURIComponent(data.report));

        if (pdfBtn) pdfBtn.style.display = '';

        showNotification('Executive report generated', 'success');
    } catch (e) {
        showNotification('Error: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

async function downloadPdfReport() {
    const body = document.getElementById('reportResultBody');
    if (!body) return;
    const rawReport = decodeURIComponent(body.getAttribute('data-raw-report') || '');
    if (!rawReport) return;

    showNotification('Preparing PDF for download...', 'info');
    try {
        const res = await fetch('/api/export/pdf', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report: rawReport })
        });

        if (!res.ok) throw new Error('PDF Generation failed');

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = 'Executive_Threat_Report.pdf';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
    } catch (e) {
        showNotification('Error downloading PDF: ' + e.message, 'error');
    }
}

async function exportSTIX() {
    showNotification('Exporting STIX 2.1 Bundle...', 'info');
    try {
        const res = await fetch('/api/export/stix', { method: 'GET' });
        if (!res.ok) throw new Error('STIX Export failed');

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = 'cybershield_stix_export.json';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        showNotification('STIX Bundle downloaded', 'success');
    } catch (e) {
        showNotification('Error exporting STIX: ' + e.message, 'error');
    }
}

async function generatePlaybook() {
    const threatType = document.getElementById('playbookThreatType').value;
    const severity = document.getElementById('playbookSeverity').value;

    showLoading('Generating Incident Response Playbook...');
    const card = document.getElementById('playbookResultCard');
    const body = document.getElementById('playbookResultBody');
    card.style.display = 'none';

    try {
        const res = await fetch('/api/analytics/playbook', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ threat_type: threatType, severity: severity })
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);

        card.style.display = 'block';
        body.innerHTML = marked.parse(data.playbook);
        showNotification('Playbook generated successfully', 'success');
    } catch (e) {
        showNotification('Error: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

// ─── AI Analyst ───────────────────────────────────────────────────────────────
async function submitQuery() {
    const input = document.getElementById('analystQuery');
    const query = input.value.trim();
    if (!query) return;

    const chatWindow = document.getElementById('chatWindow');

    // Add user message
    addChatMsg(chatWindow, 'user', 'YOU', query);
    input.value = '';

    // Typing indicator
    const typingId = 'typing-' + Date.now();
    const typingEl = document.createElement('div');
    typingEl.className = 'chat-msg bot';
    typingEl.id = typingId;
    typingEl.innerHTML = `
    <div class="chat-avatar">AI</div>
    <div class="chat-bubble" style="padding:14px">
      <span class="typing-dot"></span>
      <span class="typing-dot"></span>
      <span class="typing-dot"></span>
    </div>`;
    chatWindow.appendChild(typingEl);
    chatWindow.scrollTop = chatWindow.scrollHeight;

    try {
        const res = await fetch('/api/analyst/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query })
        });
        const data = await res.json();
        typingEl.remove();

        const response = data.llm_response || data.message || JSON.stringify(data, null, 2);
        addChatMsg(chatWindow, 'bot', 'AI', response);
    } catch (e) {
        typingEl.remove();
        addChatMsg(chatWindow, 'bot', 'AI', '⚠ Error: ' + e.message);
    }
}

function addChatMsg(chatWindow, type, avatar, text) {
    const msg = document.createElement('div');
    msg.className = 'chat-msg ' + type;
    msg.innerHTML = `
    <div class="chat-avatar">${avatar}</div>
    <div class="chat-bubble">${escHtml(text).replace(/\n/g, '<br>')}</div>`;
    chatWindow.appendChild(msg);
    chatWindow.scrollTop = chatWindow.scrollHeight;
}

// ─── Performance ──────────────────────────────────────────────────────────────
async function loadPerformance() {
    try {
        const res = await fetch('/api/performance');
        const data = await res.json();
        const { stats, metrics } = data;

        // KPIs
        if (stats.llm_query_analyst) {
            document.getElementById('perfLlmAvg').textContent = stats.llm_query_analyst.avg_latency.toFixed(2) + 's';
            document.getElementById('perfTotal').textContent = stats.llm_query_analyst.count;
        }
        if (stats.extraction_total) {
            document.getElementById('perfExtAvg').textContent = stats.extraction_total.avg_latency.toFixed(2) + 's';
        }

        // Charts
        if (metrics.llm_query_analyst) renderPerfChart('perfLlmChart', metrics.llm_query_analyst, 'LLM Latency', '#00d9ff');
        if (metrics.extraction_total) renderPerfChart('perfExtChart', metrics.extraction_total, 'Extraction', '#7b2ff7');

        // Table
        const tbody = document.getElementById('perfTbody');
        const rows = Object.entries(stats).map(([op, s]) => `
      <tr>
        <td style="font-family:var(--font-mono)">${op}</td>
        <td style="font-family:var(--font-mono)">${s.count}</td>
        <td style="font-family:var(--font-mono)">${s.avg_latency.toFixed(2)}</td>
        <td style="font-family:var(--font-mono)">${s.min_latency.toFixed(2)}</td>
        <td style="font-family:var(--font-mono)">${s.max_latency.toFixed(2)}</td>
        <td style="font-family:var(--font-mono)">${s.p95_latency.toFixed(2)}</td>
      </tr>`).join('');
        tbody.innerHTML = rows || '<tr><td colspan="6" class="loading-row">No metrics yet</td></tr>';

    } catch (e) { }
}

function renderPerfChart(canvasId, data, label, color) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    if (State.charts[canvasId]) State.charts[canvasId].destroy();

    const labels = data.map(d => formatDate(d.timestamp));
    const values = data.map(d => d.duration);

    State.charts[canvasId] = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label,
                data: values,
                borderColor: color,
                backgroundColor: color + '22',
                borderWidth: 2,
                pointRadius: 3,
                tension: 0.4,
                fill: true,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false }, tooltip: cyberTooltip() },
            scales: { x: cyberScaleX(), y: cyberScaleY('Seconds') },
        }
    });
}

// ─── Utilities ────────────────────────────────────────────────────────────────
function escHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function formatDate(ts) {
    if (!ts) return '—';
    try {
        const d = new Date(ts);
        return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) +
            ' ' + d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    } catch (e) { return ts.slice(0, 16); }
}

function showLoading(text) {
    const overlay = document.getElementById('loadingOverlay');
    const textEl = document.getElementById('loadingText');
    textEl.textContent = text || 'Processing...';
    overlay.style.display = 'flex';
}

function hideLoading() {
    document.getElementById('loadingOverlay').style.display = 'none';
}

function showNotification(msg, type = 'info') {
    const el = document.getElementById('notification');
    el.textContent = msg;
    el.className = `notification ${type} show`;
    clearTimeout(el._timer);
    el._timer = setTimeout(() => { el.classList.remove('show'); }, 3500);
}
