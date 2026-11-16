import {
    useCallback,
    useEffect,
    useMemo,
    useState
} from "react";

import {
    API_BASE_URL,
    explainIncident,
    fetchDashboardData,
    fetchLiveLog,
    fetchSimulationStatus,
    generateNormalTraffic,
    injectAttack,
    injectRandomAttack,
    runDemoSimulation,
    startLiveSimulation,
    stopLiveSimulation
} from "./api";

import "./App.css";


const EMPTY_DATA = {
    statistics: {},
    events: [],
    alerts: [],
    incidents: [],
    analyses: [],
    decisions: [],
    responses: [],
    auditRecords: []
};


const NAVIGATION_ITEMS = [
    {
        id: "overview",
        label: "Overview",
        symbol: "⌂"
    },
    {
        id: "incidents",
        label: "Incidents",
        symbol: "⚠"
    },
    {
        id: "events",
        label: "Events",
        symbol: "◉"
    },
    {
        id: "responses",
        label: "Responses",
        symbol: "◆"
    },
    {
        id: "audit",
        label: "Audit Trail",
        symbol: "✓"
    }
];


function formatLabel(value) {

    if (!value) {
        return "Unknown";
    }

    return String(value)
        .replaceAll("_", " ")
        .toLowerCase()
        .replace(
            /\b\w/g,
            character =>
                character.toUpperCase()
        );
}


function formatTimestamp(value) {

    if (!value) {
        return "Not available";
    }

    if (
        /^\d{2}:\d{2}:\d{2}$/.test(
            value
        )
    ) {
        return value;
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return value;
    }

    return date.toLocaleString();
}


function severityClass(severity) {

    return (
        `severity-badge severity-`
        + String(
            severity || "unknown"
        ).toLowerCase()
    );
}


function getIncidentSources(incident) {

    const sources =
        incident.payload?.sources || [];

    if (sources.length === 0) {
        return "None";
    }

    return sources
        .map(
            source =>
                source.value
        )
        .join(", ");
}


function getEventDetails(event) {

    const payload = event.payload || {};

    if (payload.username) {
        return (
            `${payload.username} from `
            + `${payload.source_ip || "unknown IP"}`
        );
    }

    if (payload.endpoint) {
        return (
            `${payload.method || "GET"} `
            + `${payload.endpoint}`
        );
    }

    if (payload.destination_port) {
        return (
            `${payload.source_ip || "unknown IP"} `
            + `→ port `
            + `${payload.destination_port}`
        );
    }

    if (payload.process_name) {
        return (
            `${payload.process_name} `
            + `(${payload.process_id || "no PID"})`
        );
    }

    return "Security activity observed";
}


function StatCard({
    label,
    value,
    detail,
    tone,
    badge,
    icon
}) {
    return (
        <article className={`stat-card ${tone}`}>
            <div className="stat-card-top">
                <span className="stat-label-wrap">
                    {icon && <span className="stat-icon">{icon}</span>}
                    <span>{label}</span>
                </span>
                {badge ? <span className="stat-badge">{badge}</span> : <span className="stat-indicator" />}
            </div>

            <div className="stat-value-wrap">
                <strong className="stat-value">
                    {typeof value === "number" ? value.toLocaleString() : (value ?? 0)}
                </strong>
            </div>

            <p className="stat-detail">{detail}</p>
        </article>
    );
}


function EmptyState({ message }) {

    return (
        <div className="empty-state">
            <span>◇</span>
            <p>{message}</p>
        </div>
    );
}

function LiveConsoleModal({ entries = [], isRunning, onClose }) {
    const bottomRef = useCallback(node => {
        if (node) node.scrollIntoView({ behavior: "smooth" });
    }, []);

    const typeClass = (type) => {
        switch (type) {
            case "ATTACK": return "attack";
            case "DETECTION": return "detection";
            case "ERROR": return "error";
            case "SYSTEM": return "system";
            default: return "event";
        }
    };

    return (
        <div className="console-overlay" onClick={onClose}>
            <div className="console-window" onClick={e => e.stopPropagation()}>
                <div className="console-header">
                    <span className="console-title">
                        {isRunning
                            ? <><span className="pulsing-dot"></span> LIVE CONSOLE STREAM</>
                            : "LIVE CONSOLE (offline)"}
                    </span>
                    <button className="console-close-btn" onClick={onClose}>✕ Close</button>
                </div>
                <div className="console-body">
                    {entries.length === 0 && (
                        <div className="console-line system">Waiting for telemetry events…</div>
                    )}
                    {entries.map((e, i) => (
                        <div key={i} className={`console-line ${typeClass(e.type)}`}>
                            <span className="console-ts">[{e.time}]</span>
                            {" "}{e.detail}
                        </div>
                    ))}
                    <div ref={bottomRef}></div>
                </div>
            </div>
        </div>
    );
}

const ATTACK_SCENARIOS = [
    {
        id: "brute-force",
        name: "Distributed Brute Force",
        category: "Credential Stuffing",
        severity: "HIGH",
        icon: "🔨",
        desc: "Rapid multi-source auth spray against authentication endpoints"
    },
    {
        id: "ddos",
        name: "Volumetric DDoS Assault",
        category: "SYN / HTTP Flood",
        severity: "CRITICAL",
        icon: "🌊",
        desc: "High-density packet barrage designed to saturate gateway capacity"
    },
    {
        id: "port-scan",
        name: "Stealth Reconnaissance",
        category: "Perimeter Sweep",
        severity: "MEDIUM",
        icon: "📡",
        desc: "Sequential TCP port probe mapping perimeter infrastructure"
    },
    {
        id: "suspicious-process",
        name: "Rogue Process Spawn",
        category: "Privilege Escalation",
        severity: "CRITICAL",
        icon: "☣️",
        desc: "Unauthorized shell execution & suspicious PID memory tampering"
    }
];

function SimulationControls({
    busy,
    message,
    error,
    liveMode = {},
    onNormalTraffic,
    onAttack,
    onRandomAttack,
    onRunDemo,
    onStartLive,
    onStopLive,
    onViewConsole
}) {

    const [normalCount, setNormalCount] =
        useState(10);
    const [demoSeed, setDemoSeed] =
        useState(42);
    const [liveSeed, setLiveSeed] =
        useState(42);

    const isLive = Boolean(liveMode?.is_running);

    return (
        <section className="panel simulation-panel">
            <div className="panel-heading">
                <div>
                    <p className="eyebrow">
                        THREAT EMULATION ENVIRONMENT
                    </p>

                    <h2>
                        Tactical Simulation Deck
                    </h2>
                </div>

                <div className="status-indicators">
                    {isLive && (
                        <span className="live-status-pill">
                            <span className="pulsing-dot"></span> LIVE RADAR ACTIVE (Seed: {liveMode.seed})
                        </span>
                    )}
                    <span className={
                        (busy || isLive)
                            ? "simulation-status running"
                            : "simulation-status idle"
                    }>
                        {isLive ? "Telemetry Streaming" : busy ? "Deploying..." : "Standby"}
                    </span>
                </div>
            </div>

            {/* AUTONOMOUS MODES (DEMO & LIVE) */}
            <div className="simulation-section autonomous-section">
                <div className="section-title-wrap">
                    <h3>Autonomous Battle Stations</h3>
                    <p>
                        Execute end-to-end multi-stage attack scenarios or maintain continuous background telemetry streaming.
                    </p>
                </div>

                <div className="simulation-mode-cards">
                    {/* DEMO MODE CARD */}
                    <div className="mode-card demo-card">
                        <div>
                            <div className="mode-card-header">
                                <span className="mode-icon">🚀</span>
                                <div>
                                    <strong>Automated Demo Scenario</strong>
                                    <span className="mode-subtitle">4-Stage Attack Lifecycle</span>
                                </div>
                            </div>

                            <p className="mode-desc">
                                Sequentially fires normal baselining, brute force, volumetric DDoS, stealth port scan, and suspicious execution with real-time AI evaluation.
                            </p>

                            <div className="stage-flow-pills">
                                <span className="stage-pill">BASELINE</span>
                                <span className="stage-arrow">→</span>
                                <span className="stage-pill">AUTH SPRAY</span>
                                <span className="stage-arrow">→</span>
                                <span className="stage-pill">DDOS</span>
                                <span className="stage-arrow">→</span>
                                <span className="stage-pill">PORT SCAN</span>
                                <span className="stage-arrow">→</span>
                                <span className="stage-pill">ROGUE PID</span>
                            </div>
                        </div>

                        <div className="mode-controls">
                            <div className="seed-input-wrapper">
                                <label htmlFor="demo-seed">Seed:</label>
                                <input
                                    id="demo-seed"
                                    type="number"
                                    value={demoSeed}
                                    onChange={e => setDemoSeed(Number(e.target.value) || 42)}
                                    disabled={busy || isLive}
                                />
                            </div>

                            <button
                                className="simulation-button demo-button"
                                onClick={() => onRunDemo && onRunDemo(demoSeed)}
                                disabled={busy || isLive}
                            >
                                Launch Demo Scenario 🚀
                            </button>
                        </div>
                    </div>

                    {/* LIVE STREAMING MODE CARD */}
                    <div className={`mode-card live-card ${isLive ? "active-live" : ""}`}>
                        <div>
                            <div className="mode-card-header">
                                <span className="mode-icon">⚡</span>
                                <div>
                                    <strong>Continuous Live Stream</strong>
                                    <span className="mode-subtitle">Real-Time Threat Telemetry</span>
                                </div>
                            </div>

                            <p className="mode-desc">
                                Emulates live SOC operations with uninterrupted traffic flow interspersed with randomized adversarial assault spikes at irregular intervals.
                            </p>
                        </div>

                        <div className="mode-controls">
                            {!isLive ? (
                                <>
                                    <div className="seed-input-wrapper">
                                        <label htmlFor="live-seed">Seed:</label>
                                        <input
                                            id="live-seed"
                                            type="number"
                                            value={liveSeed}
                                            onChange={e => setLiveSeed(Number(e.target.value) || 42)}
                                            disabled={busy}
                                        />
                                    </div>

                                    <div className="live-actions">
                                        <button
                                            className="simulation-button live-button"
                                            onClick={() => onStartLive && onStartLive(liveSeed, false)}
                                            disabled={busy}
                                        >
                                            Engage Stream ⚡
                                        </button>

                                        <button
                                            className="simulation-button random-seed-button"
                                            onClick={() => onStartLive && onStartLive(null, true)}
                                            disabled={busy}
                                        >
                                            Random Seed 🎲
                                        </button>
                                    </div>
                                </>
                            ) : (
                                <div className="live-running-bar">
                                    <div className="live-metric-pill">
                                        <span>Events: <strong>{liveMode.events_generated || 0}</strong></span>
                                        <span>Attacks: <strong>{liveMode.attacks_injected || 0}</strong></span>
                                    </div>

                                    <button
                                        className="simulation-button console-view-button"
                                        onClick={() => onViewConsole && onViewConsole()}
                                    >
                                        📟 Terminal Feed
                                    </button>

                                    <button
                                        className="simulation-button stop-live-button"
                                        onClick={() => onStopLive && onStopLive()}
                                    >
                                        Terminate Stream ⏹
                                    </button>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>

            {/* TACTICAL THREAT ARSENAL */}
            <div className="threat-arsenal-section">
                <div className="section-title-wrap">
                    <h3>Threat Arsenal // Targeted Assault Scenarios</h3>
                    <p>
                        Directly inject isolated attack vectors to test sensor fidelity, behavioral models, and automated counter-response agents.
                    </p>
                </div>

                <div className="threat-arsenal-grid">
                    {ATTACK_SCENARIOS.map(attack => (
                        <div key={attack.id} className="threat-card">
                            <div className="threat-card-top">
                                <span className="threat-card-icon">{attack.icon}</span>
                                <span className={`threat-severity-tag ${attack.severity.toLowerCase()}`}>
                                    {attack.severity}
                                </span>
                            </div>
                            <span className="threat-category">{attack.category}</span>
                            <h4>{attack.name}</h4>
                            <p>{attack.desc}</p>
                            <button
                                className="threat-launch-btn"
                                onClick={() => onAttack(attack.id)}
                                disabled={busy || isLive}
                            >
                                Launch Assault ⚡
                            </button>
                        </div>
                    ))}
                </div>

                <div className="random-attack-strip">
                    <div className="random-strip-text">
                        <strong>🎲 Unpredictable Adversary Injection</strong>
                        <p>Simulates an unknown threat actor by dynamically selecting an evasion technique at runtime.</p>
                    </div>
                    <button
                        className="simulation-button random-seed-button"
                        onClick={onRandomAttack}
                        disabled={busy || isLive}
                    >
                        Deploy Random Threat 🎲
                    </button>
                </div>
            </div>

            {/* NORMAL TELEMETRY GENERATOR */}
            <div className="normal-traffic-section">
                <div className="section-title-wrap">
                    <h3>Baseline Telemetry Generator</h3>
                    <p>
                        Stream legitimate network flows, authentications, and system transactions to evaluate anomaly false-positive tolerance.
                    </p>
                </div>

                <div className="normal-controls-row">
                    <div className="preset-pills">
                        {[10, 25, 50, 100].map(count => (
                            <button
                                key={count}
                                type="button"
                                className="preset-pill"
                                onClick={() => setNormalCount(count)}
                                disabled={busy || isLive}
                            >
                                +{count}
                            </button>
                        ))}
                    </div>

                    <div className="normal-input-wrap">
                        <label htmlFor="normal-count">Count:</label>
                        <input
                            id="normal-count"
                            type="number"
                            min="1"
                            max="100"
                            value={normalCount}
                            onChange={e => setNormalCount(Math.min(100, Math.max(1, Number(e.target.value) || 1)))}
                            disabled={busy || isLive}
                        />
                    </div>

                    <button
                        className="simulation-button normal-button"
                        onClick={() => onNormalTraffic(normalCount)}
                        disabled={busy || isLive}
                    >
                        Generate Normal Traffic 🟢
                    </button>
                </div>
            </div>

            {busy && (
                <div className="simulation-feedback">
                    ⚡ Telemetry generation & threat analysis in progress. Sensors correlating vectors...
                </div>
            )}

            {message && (
                <div className="simulation-result success">
                    ✓ {message}
                </div>
            )}

            {error && (
                <div className="simulation-result failure">
                    ⚠ {error}
                </div>
            )}
        </section>
    );
}

function Overview({
    data,
    onSelectIncident,
    simulationBusy,
    simulationMessage,
    simulationError,
    liveMode,
    onNormalTraffic,
    onAttack,
    onRandomAttack,
    onRunDemo,
    onStartLive,
    onStopLive,
    onViewConsole
}) {

    const severityCounts = useMemo(
        () => {

            const counts = {
                CRITICAL: 0,
                HIGH: 0,
                MEDIUM: 0,
                LOW: 0
            };

            for (
                const incident
                of data.incidents
            ) {

                const severity =
                    incident.severity;

                if (
                    Object.hasOwn(
                        counts,
                        severity
                    )
                ) {
                    counts[severity] += 1;
                }
            }

            return counts;
        },
        [data.incidents]
    );

    const maximumSeverityCount = Math.max(
        1,
        ...Object.values(
            severityCounts
        )
    );

    return (
        <>
            <SimulationControls
                busy={simulationBusy}
                message={simulationMessage}
                error={simulationError}
                liveMode={liveMode}
                onNormalTraffic={onNormalTraffic}
                onAttack={onAttack}
                onRandomAttack={onRandomAttack}
                onRunDemo={onRunDemo}
                onStartLive={onStartLive}
                onStopLive={onStopLive}
                onViewConsole={onViewConsole}
            />

            <section className="stat-grid">
                <StatCard
                    label="Security Events"
                    value={data.statistics.events}
                    detail="Observed network & system packets"
                    tone="emerald"
                    badge="TELEMETRY"
                    icon="📡"
                />

                <StatCard
                    label="Active Incidents"
                    value={data.statistics.incidents}
                    detail="Correlated multi-source threats"
                    tone="red"
                    badge="THREATS"
                    icon="🚨"
                />

                <StatCard
                    label="Security Alerts"
                    value={data.statistics.alerts}
                    detail="Rule & ML anomaly triggers"
                    tone="orange"
                    badge="DETECTIONS"
                    icon="⚡"
                />

                <StatCard
                    label="Autonomous Mitigations"
                    value={data.statistics.responses}
                    detail="Automated agent countermeasures"
                    tone="purple"
                    badge="DEFENDED"
                    icon="🛡️"
                />
            </section>

            <section className="dashboard-grid">
                <article className="panel">
                    <div className="panel-heading">
                        <div>
                            <p className="eyebrow">
                                Risk distribution
                            </p>
                            <h2>
                                Incidents by severity
                            </h2>
                        </div>
                    </div>

                    <div className="severity-chart">
                        {
                            Object.entries(
                                severityCounts
                            ).map(
                                ([
                                    severity,
                                    count
                                ]) => (
                                    <div
                                        className="severity-row"
                                        key={severity}
                                    >
                                        <span>
                                            {formatLabel(
                                                severity
                                            )}
                                        </span>

                                        <div className="bar-track">
                                            <div
                                                className={
                                                    `bar-fill bar-`
                                                    + severity.toLowerCase()
                                                }
                                                style={{
                                                    width:
                                                        `${(
                                                            count
                                                            / maximumSeverityCount
                                                        ) * 100}%`
                                                }}
                                            />
                                        </div>

                                        <strong>
                                            {count}
                                        </strong>
                                    </div>
                                )
                            )
                        }
                    </div>
                </article>

                <article className="panel system-panel">
                    <div className="panel-heading">
                        <div>
                            <p className="eyebrow">
                                System health
                            </p>
                            <h2>
                                Detection pipeline
                            </h2>
                        </div>

                        <span className="live-badge">
                            Live
                        </span>
                    </div>

                    <div className="pipeline-list">
                        <div>
                            <span className="pipeline-dot active" />
                            Rule-based detection
                            <strong>Operational</strong>
                        </div>

                        <div>
                            <span className="pipeline-dot active" />
                            Isolation Forest
                            <strong>Operational</strong>
                        </div>

                        <div>
                            <span className="pipeline-dot active" />
                            Multi-agent response
                            <strong>Operational</strong>
                        </div>

                        <div>
                            <span className="pipeline-dot active" />
                            SQLite persistence
                            <strong>Connected</strong>
                        </div>
                    </div>
                </article>
            </section>

            <section className="dashboard-grid lower-grid">
                <article className="panel wide-panel">
                    <div className="panel-heading">
                        <div>
                            <p className="eyebrow">
                                Threat intelligence
                            </p>
                            <h2>
                                Recent incidents
                            </h2>
                        </div>
                    </div>

                    {
                        data.incidents.length === 0
                            ? (
                                <EmptyState
                                    message={
                                        "No incidents have been detected."
                                    }
                                />
                            )
                            : (
                                <div className="table-wrapper">
                                    <table>
                                        <thead>
                                            <tr>
                                                <th>Type</th>
                                                <th>Severity</th>
                                                <th>Sources</th>
                                                <th>Status</th>
                                                <th>Updated</th>
                                            </tr>
                                        </thead>

                                        <tbody>
                                            {
                                                data.incidents
                                                    .slice(0, 6)
                                                    .map(
                                                        incident => (
                                                            <tr
                                                                key={
                                                                    incident.incident_id
                                                                }
                                                                onClick={
                                                                    () =>
                                                                        onSelectIncident(
                                                                            incident
                                                                        )
                                                                }
                                                            >
                                                                <td>
                                                                    <strong>
                                                                        {
                                                                            formatLabel(
                                                                                incident.incident_type
                                                                            )
                                                                        }
                                                                    </strong>
                                                                </td>

                                                                <td>
                                                                    <span
                                                                        className={
                                                                            severityClass(
                                                                                incident.severity
                                                                            )
                                                                        }
                                                                    >
                                                                        {
                                                                            incident.severity
                                                                        }
                                                                    </span>
                                                                </td>

                                                                <td>
                                                                    {
                                                                        getIncidentSources(
                                                                            incident
                                                                        )
                                                                    }
                                                                </td>

                                                                <td>
                                                                    {
                                                                        formatLabel(
                                                                            incident.status
                                                                        )
                                                                    }
                                                                </td>

                                                                <td>
                                                                    {
                                                                        formatTimestamp(
                                                                            incident.updated_at
                                                                        )
                                                                    }
                                                                </td>
                                                            </tr>
                                                        )
                                                    )
                                            }
                                        </tbody>
                                    </table>
                                </div>
                            )
                    }
                </article>

                <article className="panel">
                    <div className="panel-heading">
                        <div>
                            <p className="eyebrow">
                                Defensive activity
                            </p>
                            <h2>
                                Recent responses
                            </h2>
                        </div>
                    </div>

                    <div className="activity-list">
                        {
                            data.responses.length === 0
                                ? (
                                    <EmptyState
                                        message={
                                            "No responses recorded."
                                        }
                                    />
                                )
                                : (
                                    data.responses
                                        .slice(0, 5)
                                        .map(
                                            response => (
                                                <div
                                                    className="activity-item"
                                                    key={
                                                        response.response_id
                                                    }
                                                >
                                                    <span className="activity-icon">
                                                        ◆
                                                    </span>

                                                    <div>
                                                        <strong>
                                                            {
                                                                formatLabel(
                                                                    response.action
                                                                )
                                                            }
                                                        </strong>

                                                        <p>
                                                            {
                                                                formatLabel(
                                                                    response.status
                                                                )
                                                            }
                                                        </p>
                                                    </div>

                                                    <span className="activity-time">
                                                        {
                                                            formatTimestamp(
                                                                response.response_timestamp
                                                            )
                                                        }
                                                    </span>
                                                </div>
                                            )
                                        )
                                )
                        }
                    </div>
                </article>
            </section>
        </>
    );
}


function IncidentsView({
    incidents,
    searchTerm,
    severityFilter,
    onSearch,
    onSeverityChange,
    onSelectIncident
}) {

    const filteredIncidents =
        incidents.filter(
            incident => {

                const searchableText = [
                    incident.incident_id,
                    incident.incident_type,
                    incident.severity,
                    incident.status,
                    getIncidentSources(
                        incident
                    )
                ]
                    .join(" ")
                    .toLowerCase();

                const matchesSearch =
                    searchableText.includes(
                        searchTerm.toLowerCase()
                    );

                const matchesSeverity =
                    severityFilter === "ALL"
                    || incident.severity
                        === severityFilter;

                return (
                    matchesSearch
                    && matchesSeverity
                );
            }
        );

    return (
        <section className="panel full-panel">
            <div className="panel-heading responsive-heading">
                <div>
                    <p className="eyebrow">
                        Correlated threats
                    </p>
                    <h2>
                        Security incidents
                    </h2>
                </div>

                <div className="filters">
                    <input
                        type="search"
                        placeholder={
                            "Search incidents..."
                        }
                        value={searchTerm}
                        onChange={
                            event =>
                                onSearch(
                                    event.target.value
                                )
                        }
                    />

                    <select
                        value={severityFilter}
                        onChange={
                            event =>
                                onSeverityChange(
                                    event.target.value
                                )
                        }
                    >
                        <option value="ALL">
                            All severities
                        </option>
                        <option value="CRITICAL">
                            Critical
                        </option>
                        <option value="HIGH">
                            High
                        </option>
                        <option value="MEDIUM">
                            Medium
                        </option>
                        <option value="LOW">
                            Low
                        </option>
                    </select>
                </div>
            </div>

            {
                filteredIncidents.length === 0
                    ? (
                        <EmptyState
                            message={
                                "No incidents match the selected filters."
                            }
                        />
                    )
                    : (
                        <div className="table-wrapper">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Incident ID</th>
                                        <th>Type</th>
                                        <th>Severity</th>
                                        <th>Confidence</th>
                                        <th>Sources</th>
                                        <th>Status</th>
                                        <th>Updated</th>
                                    </tr>
                                </thead>

                                <tbody>
                                    {
                                        filteredIncidents.map(
                                            incident => (
                                                <tr
                                                    key={
                                                        incident.incident_id
                                                    }
                                                    onClick={
                                                        () =>
                                                            onSelectIncident(
                                                                incident
                                                            )
                                                    }
                                                >
                                                    <td className="id-cell">
                                                        {
                                                            incident.incident_id
                                                        }
                                                    </td>

                                                    <td>
                                                        {
                                                            formatLabel(
                                                                incident.incident_type
                                                            )
                                                        }
                                                    </td>

                                                    <td>
                                                        <span
                                                            className={
                                                                severityClass(
                                                                    incident.severity
                                                                )
                                                            }
                                                        >
                                                            {
                                                                incident.severity
                                                            }
                                                        </span>
                                                    </td>

                                                    <td>
                                                        {
                                                            Math.round(
                                                                incident.confidence
                                                                * 100
                                                            )
                                                        }%
                                                    </td>

                                                    <td>
                                                        {
                                                            getIncidentSources(
                                                                incident
                                                            )
                                                        }
                                                    </td>

                                                    <td>
                                                        {
                                                            formatLabel(
                                                                incident.status
                                                            )
                                                        }
                                                    </td>

                                                    <td>
                                                        {
                                                            formatTimestamp(
                                                                incident.updated_at
                                                            )
                                                        }
                                                    </td>
                                                </tr>
                                            )
                                        )
                                    }
                                </tbody>
                            </table>
                        </div>
                    )
            }
        </section>
    );
}


function EventsView({ events }) {

    return (
        <section className="panel full-panel">
            <div className="panel-heading">
                <div>
                    <p className="eyebrow">
                        Raw telemetry
                    </p>
                    <h2>
                        Recent security events
                    </h2>
                </div>
            </div>

            {
                events.length === 0
                    ? (
                        <EmptyState
                            message={
                                "No events have been stored."
                            }
                        />
                    )
                    : (
                        <div className="event-grid">
                            {
                                events.map(
                                    event => (
                                        <article
                                            className="event-card"
                                            key={
                                                event.event_id
                                            }
                                        >
                                            <div>
                                                <span className="event-type">
                                                    {
                                                        formatLabel(
                                                            event.event_type
                                                        )
                                                    }
                                                </span>

                                                <span className="event-time">
                                                    {
                                                        formatTimestamp(
                                                            event.event_timestamp
                                                        )
                                                    }
                                                </span>
                                            </div>

                                            <p>
                                                {
                                                    getEventDetails(
                                                        event
                                                    )
                                                }
                                            </p>
                                        </article>
                                    )
                                )
                            }
                        </div>
                    )
            }
        </section>
    );
}


function ResponsesView({
    decisions,
    responses
}) {

    return (
        <section className="dashboard-grid">
            <article className="panel">
                <div className="panel-heading">
                    <div>
                        <p className="eyebrow">
                            Decision Agent
                        </p>
                        <h2>
                            Recent decisions
                        </h2>
                    </div>
                </div>

                <div className="activity-list">
                    {
                        decisions.length === 0
                            ? (
                                <EmptyState
                                    message={
                                        "No decisions recorded."
                                    }
                                />
                            )
                            : (
                                decisions.map(
                                    decision => (
                                        <div
                                            className="activity-item"
                                            key={
                                                decision.decision_id
                                            }
                                        >
                                            <span className="activity-icon">
                                                ◇
                                            </span>

                                            <div>
                                                <strong>
                                                    {
                                                        formatLabel(
                                                            decision.recommended_action
                                                        )
                                                    }
                                                </strong>

                                                <p>
                                                    Incident: {
                                                        decision.incident_id
                                                    }
                                                </p>
                                            </div>

                                            <span
                                                className={
                                                    decision.automatic
                                                        ? "mode-badge automatic"
                                                        : "mode-badge manual"
                                                }
                                            >
                                                {
                                                    decision.automatic
                                                        ? "Automatic"
                                                        : "Manual"
                                                }
                                            </span>
                                        </div>
                                    )
                                )
                            )
                    }
                </div>
            </article>

            <article className="panel">
                <div className="panel-heading">
                    <div>
                        <p className="eyebrow">
                            Response Agent
                        </p>
                        <h2>
                            Executed responses
                        </h2>
                    </div>
                </div>

                <div className="activity-list">
                    {
                        responses.length === 0
                            ? (
                                <EmptyState
                                    message={
                                        "No responses recorded."
                                    }
                                />
                            )
                            : (
                                responses.map(
                                    response => (
                                        <div
                                            className="activity-item"
                                            key={
                                                response.response_id
                                            }
                                        >
                                            <span className="activity-icon">
                                                ◆
                                            </span>

                                            <div>
                                                <strong>
                                                    {
                                                        formatLabel(
                                                            response.action
                                                        )
                                                    }
                                                </strong>

                                                <p>
                                                    {
                                                        formatLabel(
                                                            response.status
                                                        )
                                                    }
                                                </p>
                                            </div>

                                            <span className="activity-time">
                                                {
                                                    formatTimestamp(
                                                        response.response_timestamp
                                                    )
                                                }
                                            </span>
                                        </div>
                                    )
                                )
                            )
                    }
                </div>
            </article>
        </section>
    );
}


function AuditView({ records }) {

    return (
        <section className="panel full-panel">
            <div className="panel-heading">
                <div>
                    <p className="eyebrow">
                        Response safety
                    </p>
                    <h2>
                        Audit trail
                    </h2>
                </div>
            </div>

            {
                records.length === 0
                    ? (
                        <EmptyState
                            message={
                                "No audit records available."
                            }
                        />
                    )
                    : (
                        <div className="table-wrapper">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Action</th>
                                        <th>Policy status</th>
                                        <th>Incident</th>
                                        <th>Reason</th>
                                        <th>Timestamp</th>
                                    </tr>
                                </thead>

                                <tbody>
                                    {
                                        records.map(
                                            record => (
                                                <tr
                                                    key={
                                                        record.audit_id
                                                    }
                                                >
                                                    <td>
                                                        {
                                                            formatLabel(
                                                                record.action
                                                            )
                                                        }
                                                    </td>

                                                    <td>
                                                        <span className="policy-badge">
                                                            {
                                                                formatLabel(
                                                                    record.policy_status
                                                                )
                                                            }
                                                        </span>
                                                    </td>

                                                    <td className="id-cell">
                                                        {
                                                            record.incident_id
                                                            || "None"
                                                        }
                                                    </td>

                                                    <td>
                                                        {
                                                            record.policy_reason
                                                        }
                                                    </td>

                                                    <td>
                                                        {
                                                            formatTimestamp(
                                                                record.audit_timestamp
                                                            )
                                                        }
                                                    </td>
                                                </tr>
                                            )
                                        )
                                    }
                                </tbody>
                            </table>
                        </div>
                    )
            }
        </section>
    );
}


function IncidentDrawer({
    incident,
    onClose
}) {

    const payload = incident?.payload || {};
    const [customExplanation, setCustomExplanation] = useState(null);
    const [lastIncidentId, setLastIncidentId] = useState(incident?.incident_id);
    const [explaining, setExplaining] = useState(false);
    const [explainError, setExplainError] = useState("");

    if (incident && incident.incident_id !== lastIncidentId) {
        setLastIncidentId(incident.incident_id);
        setCustomExplanation(null);
        setExplainError("");
        setExplaining(false);
    }

    const explanation =
        customExplanation
        || incident?.llm_enrichment
        || payload.llm_enrichment
        || null;

    const handleExplain = async () => {
        if (!incident) return;
        setExplaining(true);
        setExplainError("");
        try {
            const result = await explainIncident(incident.incident_id);
            if (result && result.explanation) {
                setCustomExplanation(result.explanation);
            }
        } catch (err) {
            setExplainError(err.message || "Failed to generate AI explanation");
        } finally {
            setExplaining(false);
        }
    };

    if (!incident) {
        return null;
    }

    const severity = (incident.severity || "unknown").toLowerCase();

    return (
        <div
            className="drawer-backdrop"
            onClick={onClose}
        >
            <aside
                className={`incident-drawer severity-border-${severity}`}
                onClick={event => event.stopPropagation()}
            >
                <div className="drawer-top-bar" />

                <div className="drawer-header-row">
                    <div className="drawer-title-group">
                        <span className="drawer-tag">THREAT DOSSIER // CLASSIFIED INTEL</span>
                        <h2>
                            {formatLabel(incident.incident_type)}
                        </h2>
                        <div className="drawer-badges">
                            <span className={severityClass(incident.severity)}>
                                {incident.severity} THREAT
                            </span>
                            <span className="confidence-pill">
                                CONFIDENCE: {Math.round((incident.confidence || 0) * 100)}%
                            </span>
                            <span className="status-pill-subtle">
                                {formatLabel(incident.status)}
                            </span>
                        </div>
                    </div>

                    <button
                        className="drawer-close"
                        onClick={onClose}
                        aria-label="Close incident details"
                    >
                        ✕
                    </button>
                </div>

                {/* 4 HUD METRIC CARDS */}
                <div className="incident-hud-grid">
                    <div className="hud-metric-card">
                        <span className="hud-metric-label">INCIDENT IDENTIFIER</span>
                        <strong className="hud-metric-value monospace">{incident.incident_id}</strong>
                    </div>

                    <div className="hud-metric-card">
                        <span className="hud-metric-label">DETECTION ENGINES</span>
                        <strong className="hud-metric-value">
                            {(payload.detection_methods || []).map(formatLabel).join(", ") || "Rule Engine"}
                        </strong>
                    </div>

                    <div className="hud-metric-card">
                        <span className="hud-metric-label">SOURCE / TARGET ENTITY</span>
                        <strong className="hud-metric-value monospace">{getIncidentSources(incident)}</strong>
                    </div>

                    <div className="hud-metric-card">
                        <span className="hud-metric-label">SUPPORTING ALERTS</span>
                        <strong className="hud-metric-value">{payload.alerts?.length || 0} correlated events</strong>
                    </div>
                </div>

                {/* TIMELINE METRICS */}
                <div className="incident-timeline-strip">
                    <div className="timeline-node">
                        <span className="timeline-dot" />
                        <div>
                            <span className="timeline-label">FIRST DETECTED</span>
                            <span className="timeline-time">{formatTimestamp(incident.created_at)}</span>
                        </div>
                    </div>
                    <div className="timeline-connector" />
                    <div className="timeline-node">
                        <span className="timeline-dot active" />
                        <div>
                            <span className="timeline-label">LAST OBSERVED</span>
                            <span className="timeline-time">{formatTimestamp(incident.updated_at)}</span>
                        </div>
                    </div>
                </div>

                {/* AI EXPLAINER LAYER */}
                <div className="ai-explainer-section">
                    <div className="ai-explainer-header">
                        <div>
                            <span className="ai-section-tag">AI DEFENSE INTELLIGENCE</span>
                            <h3>Neural Incident Advisor</h3>
                            <p className="ai-subtitle">Autonomous LLM correlation & defensive playbook synthesis</p>
                        </div>
                        <button
                            className="ai-explain-button"
                            onClick={handleExplain}
                            disabled={explaining}
                        >
                            {explaining ? "Synthesizing..." : explanation ? "Re-Analyze ✨" : "Explain with AI ✨"}
                        </button>
                    </div>

                    {explainError && (
                        <div className="ai-error-banner">
                            <span>⚠</span>
                            <p>{explainError}</p>
                        </div>
                    )}

                    {explaining && (
                        <div className="ai-loading-card">
                            <span className="spinner-icon radar-spin">⚡</span>
                            <div>
                                <strong>Consulting Security LLM Layer...</strong>
                                <p>Synthesizing telemetry anomalies, attack patterns & counter-response vectors.</p>
                            </div>
                        </div>
                    )}

                    {explanation && !explaining && (
                        <div className="ai-explanation-content">
                            <div className="ai-badge-row">
                                <span className={`ai-source-badge ${explanation.source === "ollama" ? "ollama" : "fallback"}`}>
                                    {explanation.source === "ollama" ? `🤖 Ollama (${explanation.model || "llama3.2"})` : `🛡️ Local Hybrid Engine`}
                                </span>
                                {explanation.why_flagged?.primary_detector && (
                                    <span className="ai-detector-badge">
                                        Vector: {explanation.why_flagged.primary_detector}
                                    </span>
                                )}
                            </div>

                            <div className="ai-card">
                                <h4>📋 Executive Threat Summary</h4>
                                <p>{explanation.summary}</p>
                            </div>

                            <div className="ai-card">
                                <h4>🎯 Why Was This Detected?</h4>
                                <p>{explanation.why_flagged?.plain_explanation || explanation.root_cause}</p>
                                {explanation.why_flagged?.key_signals && explanation.why_flagged.key_signals.length > 0 && (
                                    <ul className="ai-signals-list">
                                        {explanation.why_flagged.key_signals.map((sig, idx) => (
                                            <li key={idx}><strong>Signal {idx + 1}:</strong> {sig}</li>
                                        ))}
                                    </ul>
                                )}
                            </div>

                            <div className="ai-card">
                                <h4>🛡️ Defense Response Rationale</h4>
                                <p>{explanation.why_response_chosen}</p>
                            </div>

                            <div className="ai-card">
                                <h4>⚡ Recommended Countermeasures</h4>
                                <ul className="ai-measures-list">
                                    {explanation.recommended_measures?.map((measure, idx) => (
                                        <li key={idx}>
                                            <span className="measure-check">✓</span>
                                            <span>{measure}</span>
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        </div>
                    )}
                </div>

                <div className="drawer-footer">
                    <button className="drawer-dismiss-btn" onClick={onClose}>
                        Close Dossier [ESC]
                    </button>
                </div>
            </aside>
        </div>
    );
}


function App() {

    const [data, setData] = useState(
        EMPTY_DATA
    );

    const [activeView, setActiveView] =
        useState("overview");

    const [loading, setLoading] =
        useState(true);

    const [refreshing, setRefreshing] =
        useState(false);

    const [error, setError] =
        useState("");

    const [lastUpdated, setLastUpdated] =
        useState(null);

    const [
        selectedIncident,
        setSelectedIncident
    ] = useState(null);

    const [searchTerm, setSearchTerm] =
        useState("");

    const [
        severityFilter,
        setSeverityFilter
    ] = useState("ALL");

    const [simulationBusy, setSimulationBusy] =
        useState(false);

    const [simulationMessage, setSimulationMessage] =
        useState("");

    const [simulationError, setSimulationError] =
        useState("");

    const [liveMode, setLiveMode] =
        useState({
            is_running: false,
            seed: null,
            events_generated: 0,
            attacks_injected: 0
        });

    const [showConsole, setShowConsole] = useState(false);
    const [liveLog, setLiveLog] = useState([]);
    const [toasts, setToasts] = useState([]);
    const [zuluTime, setZuluTime] = useState(() => new Date().toISOString().substring(11, 19));

    const addToast = useCallback((type, title, message) => {
        const id = Date.now() + Math.random();
        setToasts(prev => [...prev.slice(-3), { id, type, title, message }]);
        setTimeout(() => {
            setToasts(prev => prev.filter(t => t.id !== id));
        }, 4500);
    }, []);

    const dismissToast = useCallback((id) => {
        setToasts(prev => prev.filter(t => t.id !== id));
    }, []);

    useEffect(() => {
        const timer = setInterval(() => {
            setZuluTime(new Date().toISOString().substring(11, 19));
        }, 1000);
        return () => clearInterval(timer);
    }, []);

    useEffect(() => {
        const handleKeyDown = (e) => {
            if (e.key === "Escape") {
                setSelectedIncident(null);
                setShowConsole(false);
            }
        };
        window.addEventListener("keydown", handleKeyDown);
        return () => window.removeEventListener("keydown", handleKeyDown);
    }, []);

    const defconStatus = useMemo(() => {
        if (!data.incidents || data.incidents.length === 0) {
            return { level: "defcon-nominal", label: "DEFCON 4 // NOMINAL" };
        }
        if (data.incidents.some(i => i.severity === "CRITICAL")) {
            return { level: "defcon-1", label: "DEFCON 1 // CRITICAL" };
        }
        if (data.incidents.some(i => i.severity === "HIGH")) {
            return { level: "defcon-2", label: "DEFCON 2 // ELEVATED" };
        }
        return { level: "defcon-nominal", label: "DEFCON 3 // GUARDED" };
    }, [data.incidents]);

    const loadData = useCallback(
        async (
            silent = false,
            signal
        ) => {

            if (silent) {
                setRefreshing(true);
            } else {
                setLoading(true);
            }

            try {

                const dashboardData =
                    await fetchDashboardData(
                        signal
                    );

                setData(dashboardData);
                setError("");
                setLastUpdated(new Date());

            } catch (requestError) {

                if (
                    requestError.name
                    !== "AbortError"
                ) {
                    setError(
                        requestError.message
                    );
                }

            } finally {

                setLoading(false);
                setRefreshing(false);
            }
        },
        []
    );

    const runSimulation = async (
        simulationFunction,
        ...args
    ) => {

        if (simulationBusy) {
            return;
        }

        setSimulationBusy(true);
        setSimulationMessage("");
        setSimulationError("");

        try {

            const result = await simulationFunction(
                ...args
            );

            setSimulationMessage(
                `${result.operation}: `
                + `${result.events_generated} events generated. `
                + `${result.message}`
            );

            addToast(
                result.operation?.toLowerCase().includes("attack") ? "attack" : "success",
                result.operation ? `${formatLabel(result.operation)} EXECUTED` : "SIMULATION SUCCESS",
                `${result.events_generated || 0} events dispatched. ${result.message || ""}`
            );

            await loadData(true);

        } catch (requestError) {

            setSimulationError(
                requestError.message
            );

            addToast("error", "SIMULATION FAULT", requestError.message || "Failed to execute simulation");

        } finally {

            setSimulationBusy(false);
        }
    };

    const handleRunDemo = async (seed = 42) => {
        await runSimulation(runDemoSimulation, seed);
    };

    const handleStartLive = async (seed = null, useRandomSeed = false) => {
        setSimulationBusy(true);
        setSimulationMessage("");
        setSimulationError("");
        try {
            const result = await startLiveSimulation(seed, useRandomSeed);
            setLiveMode(
                result.live_mode
                || { is_running: true, seed }
            );
            setLiveLog([]);
            setShowConsole(true);
            setSimulationMessage(result.message);
            addToast("live", "LIVE RADAR STREAM ENGAGED", `Real-time telemetry active (Seed: ${seed || "Random"})`);
            await loadData(true);
        } catch (err) {
            setSimulationError(
                err.message || "Failed to start live simulation"
            );
            addToast("error", "LIVE STREAM ERROR", err.message || "Could not start live stream");
        } finally {
            setSimulationBusy(false);
        }
    };

    const handleStopLive = async () => {
        setSimulationBusy(true);
        try {
            const result = await stopLiveSimulation();
            setLiveMode({
                is_running: false,
                seed: null,
                events_generated: 0,
                attacks_injected: 0
            });
            setSimulationMessage(result.message);
            addToast("info", "LIVE STREAM TERMINATED", "Background telemetry collection stopped.");
            await loadData(true);
        } catch (err) {
            setSimulationError(
                err.message || "Failed to stop live simulation"
            );
            addToast("error", "TERMINATION ERROR", err.message || "Could not stop live stream");
        } finally {
            setSimulationBusy(false);
        }
    };

    useEffect(() => {
        if (!liveMode.is_running) return;
        const interval = setInterval(async () => {
            try {
                const status = await fetchSimulationStatus();
                if (status.live_mode) {
                    setLiveMode(prev => ({
                        ...prev,
                        events_generated: status.live_mode.events_generated ?? prev.events_generated,
                        attacks_injected: status.live_mode.attacks_injected ?? prev.attacks_injected,
                        is_running: status.live_mode.is_running ?? prev.is_running,
                    }));
                }
            } catch (e) { void e; }
            loadData(true);
        }, 2500);
        return () => clearInterval(interval);
    }, [liveMode.is_running, loadData]);

    // Poll live log when console is open
    useEffect(() => {
        if (!showConsole) return;
        const pollLog = async () => {
            try {
                const data = await fetchLiveLog();
                setLiveLog(data.entries || []);
                // Also keep stats fresh from log endpoint
                if (liveMode.is_running) {
                    setLiveMode(prev => ({
                        ...prev,
                        events_generated: data.events_generated ?? prev.events_generated,
                        attacks_injected: data.attacks_injected ?? prev.attacks_injected,
                    }));
                }
            } catch (e) { void e; }
        };
        pollLog();
        const interval = setInterval(pollLog, 1500);
        return () => clearInterval(interval);
    }, [showConsole, liveMode.is_running]);

    useEffect(
        () => {

            const controller =
                new AbortController();

            const initialLoadTimer =
                window.setTimeout(
                    () => {
                        loadData(
                            false,
                            controller.signal
                        );
                    },
                    0
                );

            const refreshInterval =
                window.setInterval(
                    () => {
                        loadData(
                            true,
                            controller.signal
                        );
                    },
                    15000
                );

            return () => {
                controller.abort();

                window.clearTimeout(
                    initialLoadTimer
                );

                window.clearInterval(
                    refreshInterval
                );
            };
        },
        [loadData]
    );

    function renderActiveView() {

        if (activeView === "incidents") {
            return (
                <IncidentsView
                    incidents={
                        data.incidents
                    }
                    searchTerm={
                        searchTerm
                    }
                    severityFilter={
                        severityFilter
                    }
                    onSearch={
                        setSearchTerm
                    }
                    onSeverityChange={
                        setSeverityFilter
                    }
                    onSelectIncident={
                        setSelectedIncident
                    }
                />
            );
        }

        if (activeView === "events") {
            return (
                <EventsView
                    events={data.events}
                />
            );
        }

        if (activeView === "responses") {
            return (
                <ResponsesView
                    decisions={
                        data.decisions
                    }
                    responses={
                        data.responses
                    }
                />
            );
        }

        if (activeView === "audit") {
            return (
                <AuditView
                    records={
                        data.auditRecords
                    }
                />
            );
        }

        return (
            <Overview
                data={data}
                onSelectIncident={setSelectedIncident}
                simulationBusy={simulationBusy}
                simulationMessage={simulationMessage}
                simulationError={simulationError}
                liveMode={liveMode}
                onNormalTraffic={count =>
                    runSimulation(
                        generateNormalTraffic,
                        count
                    )
                }
                onAttack={attackType =>
                    runSimulation(
                        injectAttack,
                        attackType
                    )
                }
                onRandomAttack={() =>
                    runSimulation(
                        injectRandomAttack
                    )
                }
                onRunDemo={handleRunDemo}
                onStartLive={handleStartLive}
                onStopLive={handleStopLive}
                onViewConsole={() => setShowConsole(true)}
            />
        );
    }

    return (
        <div className="app-shell">
            <aside className="sidebar">
                <div className="brand">
                    <div className="brand-mark">
                        🛡️
                    </div>

                    <div className="brand-text-wrap">
                        <strong>
                            Cyber Shield
                        </strong>
                        <span>
                            Autonomous Defense
                        </span>
                    </div>
                </div>

                <nav>
                    {
                        NAVIGATION_ITEMS.map(
                            item => (
                                <button
                                    key={item.id}
                                    className={
                                        activeView
                                        === item.id
                                            ? "nav-item active"
                                            : "nav-item"
                                    }
                                    onClick={
                                        () =>
                                            setActiveView(
                                                item.id
                                            )
                                    }
                                >
                                    <span className="nav-symbol">
                                        {item.symbol}
                                    </span>

                                    {item.label}
                                </button>
                            )
                        )
                    }
                </nav>

                <div className="sidebar-status">
                    <span className="status-dot-pulse" />

                    <div>
                        <strong>
                            Core Engine: Active
                        </strong>
                        <p>
                            API: {
                                API_BASE_URL
                            }
                        </p>
                    </div>
                </div>
            </aside>

            <main className="main-content">
                <header className="topbar">
                    <div className="topbar-title-wrap">
                        <p className="eyebrow">
                            CYBER SHIELD // AUTONOMOUS CYBER DEFENSE OPERATIONS
                        </p>

                        <h1>
                            {
                                NAVIGATION_ITEMS
                                    .find(
                                        item =>
                                            item.id
                                            === activeView
                                    )
                                    ?.label
                            }
                        </h1>
                    </div>

                    <div className="topbar-actions">
                        <div className={`defcon-badge ${defconStatus.level}`}>
                            {defconStatus.label}
                        </div>

                        <div className="zulu-clock">
                            <span>ZULU TIME (UTC)</span>
                            <strong>{zuluTime} Z</strong>
                        </div>

                        <div className="updated-time">
                            <span>
                                LAST TELEMETRY SYNC  
                            </span>

                            <strong>
                                {
                                    lastUpdated
                                        ? lastUpdated
                                            .toLocaleTimeString()
                                        : "PENDING"
                                }
                            </strong>
                        </div>

                        <button
                            className="refresh-button"
                            onClick={
                                () =>
                                    loadData(true)
                            }
                            disabled={refreshing}
                        >
                            {
                                refreshing
                                    ? "Syncing..."
                                    : "Sync Telemetry 🔄"
                            }
                        </button>
                    </div>
                </header>

                {
                    error
                        ? (
                            <section className="error-banner">
                                <div>
                                    <strong>
                                        Backend unavailable
                                    </strong>

                                    <p>{error}</p>
                                </div>

                                <button
                                    onClick={
                                        () =>
                                            loadData()
                                    }
                                >
                                    Retry
                                </button>
                            </section>
                        )
                        : null
                }

                {
                    loading
                        ? (
                            <section className="loading-state">
                                <span className="loader" />
                                <p>
                                    Loading security data...
                                </p>
                            </section>
                        )
                        : (
                            renderActiveView()
                        )
                }
            </main>

            <IncidentDrawer
                incident={selectedIncident}
                onClose={
                    () =>
                        setSelectedIncident(
                            null
                        )
                }
            />

            {showConsole && (
                <LiveConsoleModal
                    entries={liveLog}
                    isRunning={liveMode.is_running}
                    onClose={() => setShowConsole(false)}
                />
            )}

            <div className="toast-container">
                {toasts.map(toast => (
                    <div
                        key={toast.id}
                        className={`toast-card toast-${toast.type}`}
                        onClick={() => dismissToast(toast.id)}
                    >
                        <div className="toast-header">
                            <span className="toast-badge">{toast.type.toUpperCase()}</span>
                            <button
                                className="toast-close"
                                onClick={(e) => {
                                    e.stopPropagation();
                                    dismissToast(toast.id);
                                }}
                            >
                                ✕
                            </button>
                        </div>
                        <strong className="toast-title">{toast.title}</strong>
                        <p className="toast-message">{toast.message}</p>
                    </div>
                ))}
            </div>
        </div>
    );
}


export default App;