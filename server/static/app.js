// AegisSOC Multi-Agent Web Application Logic

let currentInvestigationState = null;
let networkGraphInstance = null;
let benchmarkChartInstance = null;

// Tab Switching
function switchTab(tabId) {
  const tabs = ['triage', 'incidents', 'malware', 'reports', 'benchmark'];
  tabs.forEach(t => {
    const view = document.getElementById(`view-${t}`);
    const btn = document.getElementById(`tab-${t}`);
    if (view && btn) {
      if (t === tabId) {
        view.classList.remove('hidden');
        btn.classList.add('border-cyan-400', 'text-cyan-400');
        btn.classList.remove('border-transparent', 'text-slate-400');
      } else {
        view.classList.add('hidden');
        btn.classList.remove('border-cyan-400', 'text-cyan-400');
        btn.classList.add('border-transparent', 'text-slate-400');
      }
    }
  });

  if (tabId === 'incidents' && currentInvestigationState) {
    renderIncidentGraph(currentInvestigationState);
  }
}

// Reset Agent Workflow Nodes UI
function resetAgentNodes() {
  const agents = ['ingestion', 'correlation', 'malware', 'threatintel', 'reasoning'];
  agents.forEach(a => {
    const node = document.getElementById(`node-${a}`);
    const stat = document.getElementById(`stat-${a}`);
    if (node) {
      node.classList.remove('active', 'completed');
    }
    if (stat) {
      stat.innerText = 'WAITING';
      stat.className = 'mt-3 text-[11px] font-mono text-slate-500 bg-slate-900 px-2 py-0.5 rounded border border-slate-800';
    }
  });
}

// Update Agent Node Status
function updateAgentNode(agentKey, status, label) {
  const node = document.getElementById(`node-${agentKey}`);
  const stat = document.getElementById(`stat-${agentKey}`);
  if (!node || !stat) return;

  if (status === 'RUNNING') {
    node.classList.add('active');
    node.classList.remove('completed');
    stat.innerText = 'PROCESSING...';
    stat.className = 'mt-3 text-[11px] font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800 animate-pulse';
  } else if (status === 'COMPLETED') {
    node.classList.remove('active');
    node.classList.add('completed');
    stat.innerText = label || 'COMPLETED';
    stat.className = 'mt-3 text-[11px] font-mono text-emerald-400 bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800';
  }
}

// Append message to Agent Message Bus
function appendAgentMessage(sender, recipient, content, timeStr) {
  const logContainer = document.getElementById('agentMessageLog');
  const msgEl = document.createElement('div');
  msgEl.className = 'p-2.5 rounded bg-slate-900/90 border border-slate-800 flex flex-col space-y-1 hover:border-slate-700 transition-all';
  
  let senderColor = 'text-cyan-400';
  if (sender === 'CorrelationAgent') senderColor = 'text-blue-400';
  if (sender === 'MalwareAnalysisAgent') senderColor = 'text-rose-400';
  if (sender === 'ThreatIntelAgent') senderColor = 'text-purple-400';
  if (sender === 'ReasoningAgent') senderColor = 'text-emerald-400';

  msgEl.innerHTML = `
    <div class="flex items-center justify-between text-[11px]">
      <div class="flex items-center space-x-1.5">
        <span class="font-bold ${senderColor}">[${sender}]</span>
        <span class="text-slate-500">→</span>
        <span class="text-slate-400 font-semibold">[${recipient}]</span>
      </div>
      <span class="text-[10px] text-slate-500">${timeStr || new Date().toLocaleTimeString()}</span>
    </div>
    <div class="text-slate-300 text-xs pl-1">${content}</div>
  `;

  logContainer.appendChild(msgEl);
  logContainer.scrollTop = logContainer.scrollHeight;
}

// Execute Full Multi-Agent Triage Pipeline
async function executeTriagePipeline() {
  const scenario = document.getElementById('scenarioSelect').value;
  const noiseCount = parseInt(document.getElementById('noiseSelect').value) || 20;
  const btn = document.getElementById('runPipelineBtn');

  btn.disabled = true;
  btn.classList.add('opacity-50', 'cursor-not-allowed');
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> <span>Triage in Progress...</span>`;

  resetAgentNodes();
  document.getElementById('agentMessageLog').innerHTML = '';
  document.getElementById('quickReportStatus').innerText = 'ANALYZING';
  document.getElementById('quickReportStatus').className = 'px-2.5 py-1 rounded text-xs font-bold font-mono bg-cyan-950 text-cyan-400 border border-cyan-800 animate-pulse';

  try {
    // Visual step progression
    updateAgentNode('ingestion', 'RUNNING');

    const res = await fetch('/api/pipeline/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scenario_name: scenario,
        total_noise_alerts: noiseCount
      })
    });

    if (!res.ok) throw new Error(`Pipeline execution failed: ${res.statusText}`);
    const state = await res.json();
    currentInvestigationState = state;

    // Simulate Agent Step Transitions visually
    setTimeout(() => updateAgentNode('ingestion', 'COMPLETED', `${state.normalized_alerts.length} ALERTS`), 200);
    setTimeout(() => updateAgentNode('correlation', 'RUNNING'), 300);
    setTimeout(() => updateAgentNode('correlation', 'COMPLETED', `${state.incident_clusters.length} INCIDENTS`), 600);
    setTimeout(() => {
      updateAgentNode('malware', 'RUNNING');
      updateAgentNode('threatintel', 'RUNNING');
    }, 700);
    setTimeout(() => {
      updateAgentNode('malware', 'COMPLETED', `${Object.keys(state.malware_reports).length} SAMPLES`);
      updateAgentNode('threatintel', 'COMPLETED', 'ENRICHED');
      updateAgentNode('reasoning', 'RUNNING');
    }, 1000);
    setTimeout(() => {
      updateAgentNode('reasoning', 'COMPLETED', `${state.incident_reports.length} REPORTS`);
      finishPipelineDisplay(state);
    }, 1300);

  } catch (err) {
    console.error(err);
    alert(`Error executing triage: ${err.message}`);
    btn.disabled = false;
    btn.classList.remove('opacity-50', 'cursor-not-allowed');
    btn.innerHTML = `<i class="fa-solid fa-play"></i> <span>Run Multi-Agent Triage</span>`;
  }
}

function finishPipelineDisplay(state) {
  const btn = document.getElementById('runPipelineBtn');
  btn.disabled = false;
  btn.classList.remove('opacity-50', 'cursor-not-allowed');
  btn.innerHTML = `<i class="fa-solid fa-play"></i> <span>Run Multi-Agent Triage</span>`;

  // Populate message trace
  const logContainer = document.getElementById('agentMessageLog');
  logContainer.innerHTML = '';
  state.agent_messages.forEach(msg => {
    appendAgentMessage(msg.sender_agent, msg.recipient_agent, msg.content, new Date(msg.timestamp).toLocaleTimeString());
  });
  document.getElementById('msgCountBadge').innerText = `${state.agent_messages.length} messages`;

  // Populate Quick Metrics
  const rawCount = state.raw_alerts.length;
  const incCount = state.incident_reports.length;
  const reduction = rawCount > 0 ? ((rawCount - incCount) / rawCount * 100).toFixed(1) : 0;
  const totalLatency = state.execution_trace.reduce((acc, step) => acc + (step.duration_ms || 0), 0);

  document.getElementById('quickRawAlerts').innerText = rawCount;
  document.getElementById('quickIncidents').innerText = incCount;
  document.getElementById('quickCompression').innerText = `${reduction}%`;
  document.getElementById('quickLatency').innerText = `${totalLatency.toFixed(1)} ms`;
  document.getElementById('quickReportStatus').innerText = 'TRIAGE COMPLETE';
  document.getElementById('quickReportStatus').className = 'px-2.5 py-1 rounded text-xs font-bold font-mono bg-emerald-950 text-emerald-400 border border-emerald-800';

  // Render sub-views
  renderIncidentClusters(state);
  renderMalwareReports(state);
  renderIncidentReports(state);
}

// Render Incident Network Graph via Vis.js
function renderIncidentGraph(state) {
  const container = document.getElementById('incidentNetworkGraph');
  if (!container || !state) return;

  const nodes = [];
  const edges = [];
  const seenNodes = new Set();

  state.incident_clusters.forEach(cluster => {
    const clusNodeId = `c_${cluster.cluster_id}`;
    if (!seenNodes.has(clusNodeId)) {
      nodes.push({
        id: clusNodeId,
        label: `Incident\n${cluster.title.substring(0, 20)}...`,
        color: { background: '#ff0055', border: '#ff5588' },
        shape: 'box',
        font: { color: '#ffffff', size: 12, face: 'monospace' }
      });
      seenNodes.add(clusNodeId);
    }

    if (cluster.primary_host) {
      const hostId = `h_${cluster.primary_host}`;
      if (!seenNodes.has(hostId)) {
        nodes.push({
          id: hostId,
          label: `Host:\n${cluster.primary_host}`,
          color: { background: '#00f0ff', border: '#38bdf8' },
          shape: 'diamond',
          font: { color: '#0a0e17', size: 11, face: 'monospace' }
        });
        seenNodes.add(hostId);
      }
      edges.push({ from: clusNodeId, to: hostId, label: 'affects', color: { color: '#475569' } });
    }

    cluster.related_ips.forEach(ip => {
      const ipId = `ip_${ip}`;
      if (!seenNodes.has(ipId)) {
        nodes.push({
          id: ipId,
          label: `C2 IP:\n${ip}`,
          color: { background: '#fbbf24', border: '#f59e0b' },
          shape: 'ellipse',
          font: { color: '#0a0e17', size: 11, face: 'monospace' }
        });
        seenNodes.add(ipId);
      }
      edges.push({ from: clusNodeId, to: ipId, label: 'connects', color: { color: '#fbbf24' } });
    });

    cluster.related_processes.forEach(proc => {
      const procId = `p_${proc}`;
      if (!seenNodes.has(procId)) {
        nodes.push({
          id: procId,
          label: `Proc:\n${proc}`,
          color: { background: '#a855f7', border: '#c084fc' },
          shape: 'dot',
          size: 15,
          font: { color: '#ffffff', size: 10, face: 'monospace' }
        });
        seenNodes.add(procId);
      }
      edges.push({ from: clusNodeId, to: procId, label: 'executes', color: { color: '#a855f7' } });
    });
  });

  const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
  const options = {
    physics: {
      solver: 'forceAtlas2Based',
      forceAtlas2Based: { gravitationalConstant: -50, centralGravity: 0.01, springLength: 90 }
    },
    interaction: { hover: true }
  };

  networkGraphInstance = new vis.Network(container, data, options);
}

// Render Incident Cluster Cards
function renderIncidentClusters(state) {
  const container = document.getElementById('incidentClusterList');
  if (!container) return;

  if (!state.incident_clusters || state.incident_clusters.length === 0) {
    container.innerHTML = `<div class="text-slate-500 text-sm italic">No incidents correlated.</div>`;
    return;
  }

  container.innerHTML = state.incident_clusters.map(c => `
    <div class="glass-panel p-5 space-y-3 border-l-4 ${c.cluster_severity === 'Critical' ? 'border-l-rose-500' : (c.cluster_severity === 'High' ? 'border-l-orange-500' : 'border-l-cyan-500')}">
      <div class="flex items-center justify-between">
        <div class="flex items-center space-x-3">
          <span class="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-slate-900 border border-slate-800 text-slate-300">${c.cluster_id}</span>
          <h4 class="text-base font-bold text-white">${c.title}</h4>
        </div>
        <span class="px-3 py-1 rounded-full text-xs font-bold font-mono ${c.cluster_severity === 'Critical' ? 'bg-rose-950 text-rose-400 border border-rose-800' : 'bg-cyan-950 text-cyan-400 border border-cyan-800'}">
          ${c.cluster_severity.toUpperCase()}
        </span>
      </div>

      <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono bg-slate-900/60 p-3 rounded-lg border border-slate-800/80">
        <div><span class="text-slate-400">Primary Host:</span> <span class="text-cyan-400 font-bold">${c.primary_host || 'N/A'}</span></div>
        <div><span class="text-slate-400">Primary User:</span> <span class="text-slate-200">${c.primary_user || 'N/A'}</span></div>
        <div><span class="text-slate-400">Alerts Aggregated:</span> <span class="text-emerald-400 font-bold">${c.alert_count}</span></div>
        <div><span class="text-slate-400">Correlation Score:</span> <span class="text-purple-400 font-bold">${(c.correlation_score * 100).toFixed(0)}%</span></div>
      </div>

      <div>
        <span class="text-xs uppercase text-slate-400 font-semibold block mb-1">MITRE ATT&CK Kill-Chain Progression</span>
        <div class="flex flex-wrap gap-2">
          ${c.mitre_attack_chain.map(t => `<span class="px-2 py-0.5 rounded text-[11px] bg-slate-800 text-slate-300 border border-slate-700 font-mono">${t}</span>`).join('')}
        </div>
      </div>
    </div>
  `).join('');
}

// Render Malware Forensics Tab
function renderMalwareReports(state) {
  const container = document.getElementById('malwareResultsContainer');
  if (!container) return;

  const reports = Object.values(state.malware_reports || {});
  if (reports.length === 0) {
    container.innerHTML = `<div class="lg:col-span-3 text-slate-500 text-sm italic">No malware artifacts detected in this alert stream.</div>`;
    return;
  }

  container.innerHTML = reports.map(r => `
    <div class="glass-panel p-5 space-y-4 border ${r.is_malicious ? 'border-rose-500/40' : 'border-emerald-500/40'}">
      <div class="flex items-center justify-between pb-3 border-b border-slate-800">
        <div>
          <div class="font-bold text-white text-sm">${r.file_name}</div>
          <div class="text-[10px] text-slate-400 font-mono">${r.sha256.substring(0, 24)}...</div>
        </div>
        <span class="px-2.5 py-1 rounded text-xs font-mono font-bold ${r.is_malicious ? 'bg-rose-950 text-rose-400 border border-rose-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'}">
          ${r.threat_classification} (Risk: ${r.risk_score.toFixed(0)}/100)
        </span>
      </div>

      <!-- YARA Hits -->
      <div>
        <span class="text-xs text-slate-400 font-semibold uppercase block mb-1.5 flex items-center space-x-1">
          <i class="fa-solid fa-bullseye text-rose-400"></i> <span>Matched YARA Signatures</span>
        </span>
        ${r.yara_matches.length > 0 ? r.yara_matches.map(y => `
          <div class="bg-slate-900 p-2.5 rounded border border-slate-800 text-xs font-mono space-y-1 mb-2">
            <div class="text-rose-400 font-bold">${y.rule_name}</div>
            <div class="text-slate-400 text-[11px]">${y.description}</div>
            <div class="text-[10px] text-slate-500">Tags: ${y.tags.join(', ')}</div>
          </div>
        `).join('') : '<div class="text-slate-500 text-xs">No static YARA signature triggers.</div>'}
      </div>

      <!-- PE Details if present -->
      ${r.static_analysis ? `
        <div class="text-xs font-mono bg-slate-900/80 p-3 rounded border border-slate-800 space-y-1.5">
          <div class="flex justify-between"><span class="text-slate-400">Max Entropy:</span> <span class="${r.static_analysis.max_entropy > 7.0 ? 'text-rose-400 font-bold' : 'text-emerald-400'}">${r.static_analysis.max_entropy.toFixed(2)} / 8.0</span></div>
          <div class="flex justify-between"><span class="text-slate-400">Packed Payload:</span> <span class="text-white">${r.static_analysis.is_packed ? 'YES (High Entropy)' : 'NO'}</span></div>
          <div class="flex justify-between"><span class="text-slate-400">Suspicious APIs:</span> <span class="text-yellow-400">${r.static_analysis.suspicious_imports.length > 0 ? r.static_analysis.suspicious_imports.join(', ') : 'None'}</span></div>
        </div>
      ` : ''}
    </div>
  `).join('');
}

// Render Final Incident Reports & Playbooks
function renderIncidentReports(state) {
  const container = document.getElementById('incidentReportsContainer');
  if (!container) return;

  const reports = state.incident_reports || [];
  if (reports.length === 0) {
    container.innerHTML = `<div class="text-slate-500 text-sm italic">No reports synthesized.</div>`;
    return;
  }

  container.innerHTML = reports.map(r => `
    <div class="glass-panel p-6 space-y-5 border-l-4 ${r.severity === 'Critical' ? 'border-l-rose-500' : (r.severity === 'High' ? 'border-l-orange-500' : 'border-l-emerald-500')}">
      
      <!-- Header -->
      <div class="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div class="flex items-center space-x-3">
            <span class="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-slate-900 border border-slate-800 text-cyan-400">${r.incident_id}</span>
            <h3 class="text-lg font-bold text-white">${r.title}</h3>
          </div>
          <p class="text-xs text-slate-400 font-mono mt-1">Generated: ${new Date(r.generated_at).toLocaleString()} | Verdict: <span class="font-bold text-white">${r.verdict}</span> (Confidence: ${(r.confidence_score*100).toFixed(0)}%)</p>
        </div>
        <div class="flex items-center space-x-3">
          <span class="px-3.5 py-1.5 rounded-full text-xs font-bold font-mono ${r.severity === 'Critical' ? 'bg-rose-950 text-rose-400 border border-rose-800' : (r.severity === 'High' ? 'bg-orange-950 text-orange-400 border border-orange-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800')}">
            ${r.severity.toUpperCase()}
          </span>
          <button onclick="downloadStixBundle('${r.incident_id}')" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono flex items-center space-x-1.5">
            <i class="fa-solid fa-download"></i> <span>Export STIX 2.1</span>
          </button>
        </div>
      </div>

      <!-- Executive Summary & Root Cause -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
        <div class="bg-slate-900/70 p-4 rounded-xl border border-slate-800">
          <span class="text-slate-400 font-semibold uppercase block mb-1.5 flex items-center space-x-1.5">
            <i class="fa-solid fa-file-lines text-cyan-400"></i> <span>Executive Summary</span>
          </span>
          <p class="text-slate-200 leading-relaxed">${r.executive_summary}</p>
        </div>
        <div class="bg-slate-900/70 p-4 rounded-xl border border-slate-800">
          <span class="text-slate-400 font-semibold uppercase block mb-1.5 flex items-center space-x-1.5">
            <i class="fa-solid fa-magnifying-glass text-purple-400"></i> <span>Root Cause Analysis & Blast Radius</span>
          </span>
          <p class="text-slate-200 leading-relaxed mb-2">${r.root_cause_analysis}</p>
          <div class="text-[11px] font-mono text-slate-400"><strong class="text-slate-300">Blast Radius:</strong> ${r.blast_radius}</div>
        </div>
      </div>

      <!-- Response & Containment Playbook -->
      <div>
        <h4 class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center space-x-1.5">
          <i class="fa-solid fa-shield-virus text-emerald-400"></i>
          <span>Automated Containment & Remediation Playbook (${r.containment_actions.length} Steps)</span>
        </h4>
        
        <div class="space-y-3">
          ${r.containment_actions.map((act, i) => `
            <div class="bg-slate-950 p-3.5 rounded-lg border border-slate-800 text-xs space-y-2">
              <div class="flex items-center justify-between">
                <div class="flex items-center space-x-2">
                  <span class="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center font-bold font-mono text-[10px]">${i+1}</span>
                  <span class="font-bold text-slate-200">${act.action_type}: ${act.target}</span>
                </div>
                <span class="text-[10px] px-2 py-0.5 rounded bg-slate-900 text-slate-400 font-mono">Priority P${act.priority}</span>
              </div>
              <div class="text-slate-400 text-[11px]">${act.description}</div>
              <div class="relative">
                <pre class="bg-slate-900 p-2.5 rounded border border-slate-800 text-cyan-300 font-mono text-[11px] overflow-x-auto select-all"><code>${act.command_or_script}</code></pre>
                <button onclick="copyToClipboard('${act.command_or_script.replace(/'/g, "\\'")}')" class="absolute right-2 top-2 text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-1 rounded">
                  Copy
                </button>
              </div>
            </div>
          `).join('')}
        </div>
      </div>

    </div>
  `).join('');
}

// Download STIX Bundle Helper
function downloadStixBundle(incidentId) {
  if (!currentInvestigationState) return;
  const report = currentInvestigationState.incident_reports.find(r => r.incident_id === incidentId);
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report.stix_bundle || {}, null, 2));
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", `STIX2_${incidentId}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}

// Copy to Clipboard
function copyToClipboard(text) {
  navigator.clipboard.writeText(text);
  alert("Containment script copied to clipboard!");
}

// Run Standalone Malware Sample Analysis
async function runSampleMalwareAnalysis() {
  const hash = document.getElementById('malwareInputHash').value.trim();
  try {
    const res = await fetch('/api/malware/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        file_name: hash.endsWith('.exe') ? hash : "artifact_payload.exe",
        file_hash_sha256: hash
      })
    });
    const rep = await res.json();
    const mockState = { malware_reports: { [rep.sha256]: rep } };
    renderMalwareReports(mockState);
  } catch (e) {
    alert("Analysis failed: " + e.message);
  }
}

// Execute Benchmark Suite
async function executeBenchmark() {
  const dataset = document.getElementById('benchmarkDatasetSelect').value;
  const btn = document.getElementById('runBenchmarkBtn');
  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> <span>Evaluating...</span>`;

  try {
    const res = await fetch('/api/benchmark/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dataset_name: dataset, total_alerts: 50 })
    });
    const data = await res.json();

    const ma = data.multi_agent_system;
    const sl = data.single_llm_baseline;
    const rb = data.rule_based_baseline;

    // Update Cards
    document.getElementById('bm-ma-f1').innerText = ma.f1_score.toFixed(4);
    document.getElementById('bm-ma-prec').innerText = (ma.precision * 100).toFixed(1) + '%';
    document.getElementById('bm-ma-rec').innerText = (ma.recall * 100).toFixed(1) + '%';
    document.getElementById('bm-ma-fp').innerText = ma.false_positive_reduction_rate.toFixed(1) + '%';
    document.getElementById('bm-ma-comp').innerText = ma.alert_compression_ratio.toFixed(1) + '%';

    document.getElementById('bm-sl-f1').innerText = sl.f1_score.toFixed(4);
    document.getElementById('bm-sl-prec').innerText = (sl.precision * 100).toFixed(1) + '%';
    document.getElementById('bm-sl-rec').innerText = (sl.recall * 100).toFixed(1) + '%';
    document.getElementById('bm-sl-fp').innerText = sl.false_positive_reduction_rate.toFixed(1) + '%';
    document.getElementById('bm-sl-comp').innerText = sl.alert_compression_ratio.toFixed(1) + '%';

    document.getElementById('bm-rb-f1').innerText = rb.f1_score.toFixed(4);
    document.getElementById('bm-rb-prec').innerText = (rb.precision * 100).toFixed(1) + '%';
    document.getElementById('bm-rb-rec').innerText = (rb.recall * 100).toFixed(1) + '%';
    document.getElementById('bm-rb-fp').innerText = rb.false_positive_reduction_rate.toFixed(1) + '%';
    document.getElementById('bm-rb-comp').innerText = rb.alert_compression_ratio.toFixed(1) + '%';

    renderBenchmarkChart(ma, sl, rb);

  } catch (e) {
    alert("Benchmark failed: " + e.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-bolt"></i> <span>Run Benchmark</span>`;
  }
}

// Render Benchmark Comparison Chart via Chart.js
function renderBenchmarkChart(ma, sl, rb) {
  const ctx = document.getElementById('benchmarkChart');
  if (!ctx) return;

  if (benchmarkChartInstance) {
    benchmarkChartInstance.destroy();
  }

  benchmarkChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['F1-Score (%)', 'Precision (%)', 'Recall (%)', 'FP Suppression Rate (%)', 'Alert Compression (%)'],
      datasets: [
        {
          label: 'Aegis Multi-Agent System',
          data: [ma.f1_score * 100, ma.precision * 100, ma.recall * 100, ma.false_positive_reduction_rate, ma.alert_compression_ratio],
          backgroundColor: 'rgba(0, 255, 157, 0.8)',
          borderColor: '#00ff9d',
          borderWidth: 1
        },
        {
          label: 'Single-LLM Direct Prompt',
          data: [sl.f1_score * 100, sl.precision * 100, sl.recall * 100, sl.false_positive_reduction_rate, sl.alert_compression_ratio],
          backgroundColor: 'rgba(251, 191, 36, 0.8)',
          borderColor: '#fbbf24',
          borderWidth: 1
        },
        {
          label: 'Rule-Based SIEM',
          data: [rb.f1_score * 100, rb.precision * 100, rb.recall * 100, rb.false_positive_reduction_rate, rb.alert_compression_ratio],
          backgroundColor: 'rgba(0, 240, 255, 0.8)',
          borderColor: '#00f0ff',
          borderWidth: 1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          max: 100,
          grid: { color: '#1e293b' },
          ticks: { color: '#94a3b8' }
        },
        x: {
          grid: { color: '#1e293b' },
          ticks: { color: '#94a3b8' }
        }
      },
      plugins: {
        legend: { labels: { color: '#f8fafc', font: { family: 'monospace' } } }
      }
    }
  });
}

// Auto-run mixed triage on load
window.addEventListener('DOMContentLoaded', () => {
  executeTriagePipeline();
});
