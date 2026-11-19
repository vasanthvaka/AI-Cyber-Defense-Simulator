import {
    useCallback,
    useEffect,
    useMemo,
    useRef,
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
    resetDatabase,
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

/* ==========================================================================
   INLINE SVG SYSTEM ICONS (RESTRAINED SECOPS ICONOGRAPHY)
   ========================================================================== */

function NavIcon({ type }) {
    switch (type) {
        case "activity":
            return (
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                </svg>
            );
        case "alert":
            return (
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="12" cy="12" r="10" />
                    <line x1="12" y1="8" x2="12" y2="12" />
                    <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
            );
        case "terminal":
            return (
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="4 17 10 11 4 5" />
                    <line x1="12" y1="19" x2="20" y2="19" />
                </svg>
            );
        case "shield":
            return (
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
            );
        case "check":
            return (
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                    <polyline points="14 2 14 8 20 8" />
                    <line x1="16" y1="13" x2="8" y2="13" />
                    <line x1="16" y1="17" x2="8" y2="17" />
                    <polyline points="10 9 9 9 8 9" />
                </svg>
            );
        default:
            return null;
    }
}

function ShieldIcon() {
    return (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
    );
}

function PlayIcon() {
    return (
        <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor">
            <polygon points="5 3 19 12 5 21 5 3" />
        </svg>
    );
}

function StopIcon() {
    return (
        <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor">
            <rect x="4" y="4" width="16" height="16" rx="2" />
        </svg>
    );
}

function RefreshIcon() {
    return (
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="23 4 23 10 17 10" />
            <polyline points="1 20 1 14 7 14" />
            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
        </svg>
    );
}

function TerminalIcon() {
    return (
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="4 17 10 11 4 5" />
            <line x1="12" y1="19" x2="20" y2="19" />
        </svg>
    );
}

function CrosshairIcon() {
    return (
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" />
            <line x1="22" y1="12" x2="18" y2="12" />
            <line x1="6" y1="12" x2="2" y2="12" />
            <line x1="12" y1="6" x2="12" y2="2" />
            <line x1="12" y1="22" x2="12" y2="18" />
        </svg>
    );
}

function BrainIcon() {
    return (
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96.44 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 4.44-2.04z" />
            <path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96.44 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-4.44-2.04z" />
        </svg>
    );
}

function CloseIcon({ size = 11 }) {
    return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <line x1="18" y1="6" x2="6" y2="18" />
            <line x1="6" y1="6" x2="18" y2="18" />
        </svg>
    );
}

function TrashIcon() {
    return (
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="3 6 5 6 21 6" />
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
        </svg>
    );
}

/* ==========================================================================
   MATRIX RAIN CANVAS (BOOT SEQUENCE BACKGROUND)
   ========================================================================== */

function MatrixCanvas() {
    const canvasRef = useRef(null);

    useEffect(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        const W = canvas.width = canvas.offsetWidth;
        const H = canvas.height = canvas.offsetHeight;
        const fontSize = 11;
        const cols = Math.floor(W / fontSize);
        const drops = Array.from({ length: cols }, () => Math.random() * -50);
        const chars = "アイウエオカキクケコ01ABCDEF⬡⬢⬣⬤⬥:;!?#$%&AEGIS".split("");

        const draw = () => {
            ctx.fillStyle = "rgba(6, 9, 16, 0.07)";
            ctx.fillRect(0, 0, W, H);
            ctx.font = `${fontSize}px "JetBrains Mono", monospace`;
            drops.forEach((y, i) => {
                const char = chars[Math.floor(Math.random() * chars.length)];
                const brightness = Math.random() > 0.95 ? "#93c5fd" : "rgba(59, 130, 246, 0.6)";
                ctx.fillStyle = brightness;
                ctx.fillText(char, i * fontSize, y * fontSize);
                drops[i] = y > H / fontSize && Math.random() > 0.975 ? 0 : y + 1;
            });
        };

        const id = setInterval(draw, 55);
        return () => clearInterval(id);
    }, []);

    return <canvas ref={canvasRef} className="boot-matrix-canvas" style={{ width: "100%", height: "100%" }} />;
}

/* ==========================================================================
   CINEMATIC BOOT INTRO SEQUENCE (HIGH-PRODUCTION NETFLIX STYLE)
   ========================================================================== */

function BootSequence({ onComplete }) {
    const [progress, setProgress] = useState(0);
    const [isFading, setIsFading] = useState(false);

    const stages = useMemo(() => [
        "INITIALIZING AEGIS DEFENSE KERNEL...",
        "MOUNTING MITRE ATT&CK REPOSITORIES...",
        "CALIBRATING ISOLATION FOREST ML SENSORS...",
        "DEFENSE MESH SYNCHRONIZED // ALL SYSTEMS ARMED"
    ], []);

    const stageIndex = useMemo(() => {
        if (progress > 75) return 3;
        if (progress > 45) return 2;
        if (progress > 15) return 1;
        return 0;
    }, [progress]);

    const handleDismiss = useCallback(() => {
        setIsFading(true);
        setTimeout(onComplete, 450);
    }, [onComplete]);

    useEffect(() => {
        const interval = setInterval(() => {
            setProgress(prev => {
                if (prev >= 100) {
                    clearInterval(interval);
                    setTimeout(handleDismiss, 400);
                    return 100;
                }
                const increment = Math.floor(Math.random() * 12) + 8;
                return Math.min(prev + increment, 100);
            });
        }, 90);

        return () => clearInterval(interval);
    }, [handleDismiss]);

    return (
        <div className={`boot-overlay ${isFading ? "fading-out" : ""}`} onClick={handleDismiss}>
            <MatrixCanvas />
            <div className="boot-container" onClick={e => e.stopPropagation()}>
                <div className="boot-emblem-wrap">
                    <div className="boot-energy-ring" />
                    <div className="boot-radar-sweep" />
                    <div className="boot-shield-glow">
                        <svg width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" className="boot-shield-icon">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            <polyline points="9 12 11 14 15 10" />
                        </svg>
                    </div>
                </div>

                <div className="boot-brand-title">
                    <span>AEGIS SECOPS</span>
                    <small>AUTONOMOUS CYBER DEFENSE PLATFORM</small>
                </div>

                <div className="boot-progress-bar-wrap">
                    <div className="boot-progress-bar" style={{ width: `${progress}%` }} />
                </div>

                <div className="boot-status-text">
                    <div>
                        <span className="boot-cursor">&gt;</span> {stages[stageIndex]}
                    </div>
                    <span className="boot-pct">{progress}%</span>
                </div>

                <button className="boot-skip-btn" onClick={handleDismiss}>
                    Skip Initialization [ESC]
                </button>
            </div>
        </div>
    );
}

/* ==========================================================================
   TACTICAL RADAR WIDGET (LIVE PERIMETER MONITOR)
   ========================================================================== */

function TacticalRadar({ isLive, eventsCount, attacksCount }) {
    return (
        <div className={`tactical-radar-widget ${isLive ? "active-radar" : ""}`}>
            <div className="radar-screen">
                <div className="radar-ring ring-1" />
                <div className="radar-ring ring-2" />
                <div className="radar-ring ring-3" />
                <div className="radar-crosshair-h" />
                <div className="radar-crosshair-v" />
                <div className="radar-sweep-beam" />
                {isLive && (
                    <>
                        <div className="radar-blip blip-1" />
                        <div className="radar-blip blip-2" />
                        <div className="radar-blip blip-3" />
                    </>
                )}
                <div className="radar-center-dot" />
            </div>
            <div className="radar-intel">
                <div className="radar-intel-header">
                    <span className="radar-dot-pulse" />
                    <strong>{isLive ? "LIVE SENSOR PERIMETER ACTIVE" : "SENSOR PERIMETER STANDBY"}</strong>
                </div>
                <div className="radar-stats-mini">
                    <div>
                        <span>INGESTED EVENTS</span>
                        <strong>{typeof eventsCount === "number" ? eventsCount.toLocaleString() : (eventsCount || 0)}</strong>
                    </div>
                    <div>
                        <span>ADVERSARY INJECTIONS</span>
                        <strong style={{ color: attacksCount > 0 ? "var(--red)" : "inherit" }}>
                            {typeof attacksCount === "number" ? attacksCount.toLocaleString() : (attacksCount || 0)}
                        </strong>
                    </div>
                </div>
            </div>
        </div>
    );
}

const NAVIGATION_ITEMS = [
    {
        id: "overview",
        label: "Overview",
        icon: "activity"
    },
    {
        id: "incidents",
        label: "Incidents",
        icon: "alert"
    },
    {
        id: "events",
        label: "Telemetry Events",
        icon: "terminal"
    },
    {
        id: "responses",
        label: "Response Actions",
        icon: "shield"
    },
    {
        id: "audit",
        label: "Audit Log",
        icon: "check"
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
            character => character.toUpperCase()
        );
}

function formatTimestamp(value) {
    if (!value) {
        return "Not available";
    }

    if (/^\d{2}:\d{2}:\d{2}$/.test(value)) {
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
        + String(severity || "unknown").toLowerCase()
    );
}

function getIncidentSources(incident) {
    const sources = incident.payload?.sources || [];

    if (sources.length === 0) {
        return "None";
    }

    return sources
        .map(source => source.value)
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

/* ==========================================================================
   DATADOG / AWS STYLE KPI TILE
   ========================================================================== */

function StatCard({
    label,
    value,
    detail,
    tone,
    badge
}) {
    return (
        <article className={`kpi-card ${tone}`}>
            <div className="kpi-header">
                <span className="kpi-label">{label}</span>
                {badge && <span className="kpi-badge">{badge}</span>}
            </div>

            <div className="kpi-body">
                <span className="kpi-value">
                    {typeof value === "number" ? value.toLocaleString() : (value ?? 0)}
                </span>
            </div>

            <p className="kpi-detail">{detail}</p>
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

/* ==========================================================================
   LIVE STREAMING CONSOLE MODAL
   ========================================================================== */

function LiveConsoleModal({ entries = [], isRunning, onClose }) {
    const bottomRef = useCallback(node => {
        if (node) node.scrollIntoView({ behavior: "smooth" });
    }, []);

    const typeTagClass = (type) => {
        switch (type) {
            case "ATTACK": return "log-tag-attack";
            case "DETECTION": return "log-tag-detection";
            case "ERROR": return "log-tag-error";
            case "SYSTEM": return "log-tag-system";
            default: return "log-tag-event";
        }
    };

    return (
        <div className="modal-backdrop" onClick={onClose}>
            <div className="terminal-modal" onClick={e => e.stopPropagation()}>
                <div className="terminal-header">
                    <div className="terminal-title">
                        <span className={`status-dot ${isRunning ? "status-dot-active" : "status-dot-offline"}`} />
                        <span>Live Telemetry Ingestion {isRunning ? "(Active Stream)" : "(Offline)"}</span>
                    </div>
                    <button className="btn-close" onClick={onClose} aria-label="Close terminal"><CloseIcon /></button>
                </div>
                <div className="terminal-body">
                    {entries.length === 0 && (
                        <div className="log-line">
                            <span className="log-msg" style={{ color: "var(--text-muted)" }}>Waiting for telemetry events...</span>
                        </div>
                    )}
                    {entries.map((e, i) => (
                        <div key={i} className={`log-line ${e.type ? e.type.toLowerCase() : ""}`}>
                            <span className="log-ts">[{e.time}]</span>
                            <span className={`log-tag ${typeTagClass(e.type)}`}>{e.type}</span>
                            <span className="log-msg">{e.detail}</span>
                        </div>
                    ))}
                    <div ref={bottomRef} />
                </div>
            </div>
        </div>
    );
}

/* ==========================================================================
   ENTERPRISE MITRE ATT&CK SCENARIOS
   ========================================================================== */

const ATTACK_SCENARIOS = [
    {
        id: "brute-force",
        name: "Credential Stuffing",
        category: "Credential Access",
        technique: "T1110.003",
        severity: "HIGH",
        desc: "Automated authentication spraying against endpoint auth services to test lockouts."
    },
    {
        id: "ddos",
        name: "Network Service Flood",
        category: "Network Impact",
        technique: "T1498.001",
        severity: "CRITICAL",
        desc: "High-volume SYN packet flood designed to test gateway bandwidth and rate limits."
    },
    {
        id: "port-scan",
        name: "Network Service Discovery",
        category: "Discovery",
        technique: "T1046",
        severity: "MEDIUM",
        desc: "Structured perimeter sweep probing TCP services across boundary subnets."
    },
    {
        id: "suspicious-process",
        name: "Command Interpreter Spawn",
        category: "Execution",
        technique: "T1059.001",
        severity: "CRITICAL",
        desc: "Rogue interactive shell execution and unauthorized memory tampering detection."
    }
];

/* ==========================================================================
   SIMULATION CONTROL DECK
   ========================================================================== */

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
    const [normalCount, setNormalCount] = useState(10);
    const [demoSeed, setDemoSeed] = useState(42);
    const [liveSeed, setLiveSeed] = useState(42);

    const isLive = Boolean(liveMode?.is_running);

    return (
        <section className="panel simulation-panel">
            <div className="panel-heading">
                <div>
                    <p className="section-eyebrow">
                        Adversary Emulation & Ingestion
                    </p>
                    <h2>
                        Security Operations Testing Deck
                    </h2>
                </div>

                <div className="status-indicators">
                    {isLive ? (
                        <span className="status-pill status-pill-active">
                            <span className="status-dot-active" />
                            Live Ingestion Active (Seed: {liveMode.seed ?? "Random"})
                        </span>
                    ) : busy ? (
                        <span className="status-pill status-pill-busy">
                            Executing Request...
                        </span>
                    ) : (
                        <span className="status-pill status-pill-ready">
                            Engine Ready
                        </span>
                    )}
                </div>
            </div>

            {/* Autonomous Test Suites */}
            <div className="sim-subpanel">
                <div className="subpanel-header">
                    <h3>Autonomous Test Suites</h3>
                    <p>
                        Execute structured end-to-end attack scenarios or maintain continuous background telemetry streaming.
                    </p>
                </div>

                <div className="sim-mode-grid">
                    {/* Automated Demo Scenario */}
                    <div className="sim-card">
                        <div className="sim-card-top">
                            <span className="mode-tag">Automated Demo</span>
                            <div className="sim-card-title-wrap">
                                <h4>4-Stage Threat Lifecycle</h4>
                            </div>
                        </div>

                        <p className="sim-card-desc">
                            Sequentially evaluates baseline telemetry, credential stuffing, volumetric DDoS, port discovery, and rogue process execution.
                        </p>

                        <div className="stage-sequence-row">
                            <span className="seq-step">Baseline</span>
                            <span className="seq-sep">→</span>
                            <span className="seq-step">Auth Spray</span>
                            <span className="seq-sep">→</span>
                            <span className="seq-step">SYN Flood</span>
                            <span className="seq-sep">→</span>
                            <span className="seq-step">Port Sweep</span>
                            <span className="seq-sep">→</span>
                            <span className="seq-step">Rogue Shell</span>
                        </div>

                        <div className="sim-controls-row">
                            <div className="inline-input-group">
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
                                className="btn btn-primary"
                                onClick={() => onRunDemo && onRunDemo(demoSeed)}
                                disabled={busy || isLive}
                            >
                                <PlayIcon /> Run Demonstration
                            </button>
                        </div>
                    </div>

                    {/* Continuous Live Ingestion */}
                    <div className={`sim-card ${isLive ? "sim-card-live" : ""}`}>
                        <div className="sim-card-top">
                            <span className="mode-tag" style={{ color: isLive ? "var(--green)" : "var(--blue)" }}>
                                Background Ingestion
                            </span>
                            <div className="sim-card-title-wrap">
                                <h4>Continuous Live Stream</h4>
                            </div>
                        </div>

                        <p className="sim-card-desc">
                            Simulates live production SOC operations with uninterrupted traffic flow interspersed with randomized adversarial assault spikes.
                        </p>

                        <div className="sim-controls-row">
                            {!isLive ? (
                                <>
                                    <div className="inline-input-group">
                                        <label htmlFor="live-seed">Seed:</label>
                                        <input
                                            id="live-seed"
                                            type="number"
                                            value={liveSeed}
                                            onChange={e => setLiveSeed(Number(e.target.value) || 42)}
                                            disabled={busy}
                                        />
                                    </div>

                                    <button
                                        className="btn btn-secondary"
                                        onClick={() => onStartLive && onStartLive(liveSeed, false)}
                                        disabled={busy}
                                    >
                                        <PlayIcon /> Start Live Feed
                                    </button>

                                    <button
                                        className="btn btn-outline"
                                        onClick={() => onStartLive && onStartLive(null, true)}
                                        disabled={busy}
                                    >
                                        Random Seed
                                    </button>
                                </>
                            ) : (
                                <div className="live-active-bar">
                                    <div className="live-counts">
                                        <span>Events: <strong>{liveMode.events_generated || 0}</strong></span>
                                        <span className="counts-divider">|</span>
                                        <span>Attacks: <strong>{liveMode.attacks_injected || 0}</strong></span>
                                    </div>

                                    <div className="live-actions">
                                        <button
                                            className="btn btn-secondary btn-sm"
                                            onClick={() => onViewConsole && onViewConsole()}
                                        >
                                            <TerminalIcon /> View Stream
                                        </button>

                                        <button
                                            className="btn btn-danger btn-sm"
                                            onClick={() => onStopLive && onStopLive()}
                                        >
                                            <StopIcon /> Stop Ingestion
                                        </button>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                <TacticalRadar
                    isLive={isLive}
                    eventsCount={liveMode.events_generated || 0}
                    attacksCount={liveMode.attacks_injected || 0}
                />
            </div>

            {/* Targeted Adversary Scenarios */}
            <div className="sim-subpanel">
                <div className="subpanel-header">
                    <h3>Targeted Adversary Scenarios</h3>
                    <p>
                        Directly inject isolated MITRE ATT&CK techniques into the detection pipeline to validate sensor telemetry and automated responses.
                    </p>
                </div>

                <div className="attack-cards-grid">
                    {ATTACK_SCENARIOS.map(attack => (
                        <div key={attack.id} className="attack-card">
                            <div>
                                <div className="attack-card-header">
                                    <span className="technique-tag">{attack.technique}</span>
                                    <span className={`severity-tag severity-${attack.severity.toLowerCase()}`}>
                                        {attack.severity}
                                    </span>
                                </div>
                                <span className="attack-category">{attack.category}</span>
                                <h4>{attack.name}</h4>
                                <p>{attack.desc}</p>
                            </div>
                            <button
                                className="btn btn-secondary btn-sm"
                                onClick={() => onAttack(attack.id)}
                                disabled={busy || isLive}
                            >
                                <CrosshairIcon /> Execute Vector
                            </button>
                        </div>
                    ))}
                </div>

                <div className="random-adversary-card">
                    <div>
                        <span className="section-eyebrow">Zero-Day Emulation</span>
                        <h4>Dynamic Evasion Vector</h4>
                        <p>Injects an unpredictably selected adversarial technique to evaluate sensor heuristic robustness.</p>
                    </div>
                    <button
                        className="btn btn-outline btn-sm"
                        onClick={onRandomAttack}
                        disabled={busy || isLive}
                    >
                        Inject Random Vector
                    </button>
                </div>
            </div>

            {/* Baseline Telemetry Generator */}
            <div className="sim-subpanel">
                <div className="subpanel-header">
                    <h3>Baseline Telemetry Ingestion</h3>
                    <p>
                        Stream legitimate network flows, authentications, and system transactions to evaluate anomaly false-positive tolerance.
                    </p>
                </div>

                <div className="baseline-controls-row">
                    <div className="preset-buttons">
                        {[10, 25, 50, 100].map(count => (
                            <button
                                key={count}
                                type="button"
                                className="btn-chip"
                                onClick={() => setNormalCount(count)}
                                disabled={busy || isLive}
                            >
                                +{count} Events
                            </button>
                        ))}
                    </div>

                    <div className="inline-input-group">
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
                        className="btn btn-primary"
                        onClick={() => onNormalTraffic(normalCount)}
                        disabled={busy || isLive}
                    >
                        Ingest Normal Traffic
                    </button>
                </div>
            </div>

            {busy && (
                <div className="status-banner status-banner-info">
                    Simulating telemetry ingestion & pipeline correlation in progress...
                </div>
            )}

            {message && (
                <div className="status-banner status-banner-success">
                    {message}
                </div>
            )}

            {error && (
                <div className="status-banner status-banner-error">
                    {error}
                </div>
            )}
        </section>
    );
}

/* ==========================================================================
   OVERVIEW VIEW
   ========================================================================== */

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
    const severityCounts = useMemo(() => {
        const counts = {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0
        };

        for (const incident of data.incidents) {
            const severity = incident.severity;
            if (Object.hasOwn(counts, severity)) {
                counts[severity] += 1;
            }
        }

        return counts;
    }, [data.incidents]);

    const maximumSeverityCount = Math.max(
        1,
        ...Object.values(severityCounts)
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

            <section className="kpi-grid">
                <StatCard
                    label="Telemetry Events"
                    value={data.statistics.events}
                    detail="Observed network & system packets"
                    tone="blue"
                    badge="RAW"
                />

                <StatCard
                    label="Active Incidents"
                    value={data.statistics.incidents}
                    detail="Correlated multi-source threats"
                    tone="red"
                    badge="TRIAGE"
                />

                <StatCard
                    label="Detection Alerts"
                    value={data.statistics.alerts}
                    detail="Rule & ML anomaly triggers"
                    tone="amber"
                    badge="DETECTIONS"
                />

                <StatCard
                    label="Autonomous Mitigations"
                    value={data.statistics.responses}
                    detail="Automated policy countermeasures"
                    tone="green"
                    badge="ENFORCED"
                />
            </section>

            <section className="dashboard-grid">
                <article className="panel">
                    <div className="panel-heading">
                        <div>
                            <p className="section-eyebrow">
                                Risk Distribution
                            </p>
                            <h2>
                                Incidents by Severity
                            </h2>
                        </div>
                    </div>

                    <div className="severity-chart">
                        {Object.entries(severityCounts).map(([severity, count]) => (
                            <div className="severity-row" key={severity}>
                                <span>{formatLabel(severity)}</span>
                                <div className="bar-track">
                                    <div
                                        className={`bar-fill bar-${severity.toLowerCase()}`}
                                        style={{
                                            width: `${(count / maximumSeverityCount) * 100}%`
                                        }}
                                    />
                                </div>
                                <strong>{count}</strong>
                            </div>
                        ))}
                    </div>
                </article>

                <article className="panel system-panel">
                    <div className="panel-heading">
                        <div>
                            <p className="section-eyebrow">
                                System Health
                            </p>
                            <h2>
                                Pipeline Engines
                            </h2>
                        </div>
                        <span className="live-badge">Live</span>
                    </div>

                    <div className="pipeline-list">
                        <div>
                            <span><span className="pipeline-dot" />Rule-based Correlator</span>
                            <strong>Operational</strong>
                        </div>

                        <div>
                            <span><span className="pipeline-dot" />Isolation Forest ML</span>
                            <strong>Operational</strong>
                        </div>

                        <div>
                            <span><span className="pipeline-dot" />Multi-Agent Response</span>
                            <strong>Operational</strong>
                        </div>

                        <div>
                            <span><span className="pipeline-dot" />SQLite Telemetry Store</span>
                            <strong>Connected</strong>
                        </div>
                    </div>
                </article>
            </section>

            <section className="dashboard-grid lower-grid">
                <article className="panel wide-panel">
                    <div className="panel-heading">
                        <div>
                            <p className="section-eyebrow">
                                Threat Intelligence
                            </p>
                            <h2>
                                Recent Incidents
                            </h2>
                        </div>
                    </div>

                    {data.incidents.length === 0 ? (
                        <EmptyState message="No incidents have been detected." />
                    ) : (
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
                                    {data.incidents.slice(0, 6).map(incident => (
                                        <tr
                                            key={incident.incident_id}
                                            onClick={() => onSelectIncident(incident)}
                                        >
                                            <td>
                                                <strong>{formatLabel(incident.incident_type)}</strong>
                                            </td>
                                            <td>
                                                <span className={`severity-tag severity-${(incident.severity || "unknown").toLowerCase()}`}>
                                                    {incident.severity}
                                                </span>
                                            </td>
                                            <td>{getIncidentSources(incident)}</td>
                                            <td>{formatLabel(incident.status)}</td>
                                            <td>{formatTimestamp(incident.updated_at)}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </article>

                <article className="panel">
                    <div className="panel-heading">
                        <div>
                            <p className="section-eyebrow">
                                Defensive Activity
                            </p>
                            <h2>
                                Recent Responses
                            </h2>
                        </div>
                    </div>

                    <div className="activity-list">
                        {data.responses.length === 0 ? (
                            <EmptyState message="No responses recorded." />
                        ) : (
                            data.responses.slice(0, 5).map(response => (
                                <div className="activity-item" key={response.response_id}>
                                    <span className="activity-icon">◆</span>
                                    <div>
                                        <strong>{formatLabel(response.action)}</strong>
                                        <p>{formatLabel(response.status)}</p>
                                    </div>
                                    <span className="activity-time">{formatTimestamp(response.response_timestamp)}</span>
                                </div>
                            ))
                        )}
                    </div>
                </article>
            </section>
        </>
    );
}

/* ==========================================================================
   INCIDENTS VIEW
   ========================================================================== */

function IncidentsView({
    incidents,
    searchTerm,
    severityFilter,
    onSearch,
    onSeverityChange,
    onSelectIncident
}) {
    const filteredIncidents = incidents.filter(incident => {
        const searchableText = [
            incident.incident_id,
            incident.incident_type,
            incident.severity,
            incident.status,
            getIncidentSources(incident)
        ]
            .join(" ")
            .toLowerCase();

        const matchesSearch = searchableText.includes(searchTerm.toLowerCase());
        const matchesSeverity = severityFilter === "ALL" || incident.severity === severityFilter;

        return matchesSearch && matchesSeverity;
    });

    return (
        <section className="panel full-panel">
            <div className="panel-heading responsive-heading">
                <div>
                    <p className="section-eyebrow">
                        Correlated Threats
                    </p>
                    <h2>
                        Security Incidents
                    </h2>
                </div>

                <div className="filters">
                    <input
                        type="search"
                        placeholder="Search incidents..."
                        value={searchTerm}
                        onChange={event => onSearch(event.target.value)}
                    />

                    <select
                        value={severityFilter}
                        onChange={event => onSeverityChange(event.target.value)}
                    >
                        <option value="ALL">All Severities</option>
                        <option value="CRITICAL">Critical</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low</option>
                    </select>
                </div>
            </div>

            {filteredIncidents.length === 0 ? (
                <EmptyState message="No incidents match the selected filters." />
            ) : (
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
                            {filteredIncidents.map(incident => (
                                <tr
                                    key={incident.incident_id}
                                    onClick={() => onSelectIncident(incident)}
                                >
                                    <td className="id-cell">{incident.incident_id}</td>
                                    <td>
                                        <strong>{formatLabel(incident.incident_type)}</strong>
                                    </td>
                                    <td>
                                        <span className={severityClass(incident.severity)}>
                                            {incident.severity}
                                        </span>
                                    </td>
                                    <td>{Math.round(incident.confidence * 100)}%</td>
                                    <td>{getIncidentSources(incident)}</td>
                                    <td>{formatLabel(incident.status)}</td>
                                    <td>{formatTimestamp(incident.updated_at)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </section>
    );
}

/* ==========================================================================
   EVENTS VIEW
   ========================================================================== */

function EventsView({ events }) {
    return (
        <section className="panel full-panel">
            <div className="panel-heading">
                <div>
                    <p className="section-eyebrow">
                        Raw Telemetry
                    </p>
                    <h2>
                        Recent Security Events
                    </h2>
                </div>
            </div>

            {events.length === 0 ? (
                <EmptyState message="No events have been stored." />
            ) : (
                <div className="event-grid">
                    {events.map(event => (
                        <article className="event-card" key={event.event_id}>
                            <div>
                                <span className="event-type">{formatLabel(event.event_type)}</span>
                                <span className="event-time">{formatTimestamp(event.event_timestamp)}</span>
                            </div>
                            <p>{getEventDetails(event)}</p>
                        </article>
                    ))}
                </div>
            )}
        </section>
    );
}

/* ==========================================================================
   RESPONSES VIEW
   ========================================================================== */

function ResponsesView({ decisions, responses }) {
    return (
        <section className="dashboard-grid">
            <article className="panel">
                <div className="panel-heading">
                    <div>
                        <p className="section-eyebrow">
                            Decision Agent
                        </p>
                        <h2>
                            Recent Decisions
                        </h2>
                    </div>
                </div>

                <div className="activity-list">
                    {decisions.length === 0 ? (
                        <EmptyState message="No decisions recorded." />
                    ) : (
                        decisions.map(decision => (
                            <div className="activity-item" key={decision.decision_id}>
                                <span className="activity-icon">◇</span>
                                <div>
                                    <strong>{formatLabel(decision.recommended_action)}</strong>
                                    <p>Incident: {decision.incident_id}</p>
                                </div>
                                <span className={decision.automatic ? "mode-badge automatic" : "mode-badge manual"}>
                                    {decision.automatic ? "Automatic" : "Manual"}
                                </span>
                            </div>
                        ))
                    )}
                </div>
            </article>

            <article className="panel">
                <div className="panel-heading">
                    <div>
                        <p className="section-eyebrow">
                            Response Agent
                        </p>
                        <h2>
                            Executed Responses
                        </h2>
                    </div>
                </div>

                <div className="activity-list">
                    {responses.length === 0 ? (
                        <EmptyState message="No responses recorded." />
                    ) : (
                        responses.map(response => (
                            <div className="activity-item" key={response.response_id}>
                                <span className="activity-icon">◆</span>
                                <div>
                                    <strong>{formatLabel(response.action)}</strong>
                                    <p>{formatLabel(response.status)}</p>
                                </div>
                                <span className="activity-time">{formatTimestamp(response.response_timestamp)}</span>
                            </div>
                        ))
                    )}
                </div>
            </article>
        </section>
    );
}

/* ==========================================================================
   AUDIT LOG VIEW
   ========================================================================== */

function AuditView({ records }) {
    return (
        <section className="panel full-panel">
            <div className="panel-heading">
                <div>
                    <p className="section-eyebrow">
                        Policy Enforcement & Safety
                    </p>
                    <h2>
                        Audit Trail
                    </h2>
                </div>
            </div>

            {records.length === 0 ? (
                <EmptyState message="No audit records available." />
            ) : (
                <div className="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Action</th>
                                <th>Policy Status</th>
                                <th>Incident</th>
                                <th>Reason</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>

                        <tbody>
                            {records.map(record => (
                                <tr key={record.audit_id}>
                                    <td>
                                        <strong>{formatLabel(record.action)}</strong>
                                    </td>
                                    <td>
                                        <span className="policy-badge">{formatLabel(record.policy_status)}</span>
                                    </td>
                                    <td className="id-cell">{record.incident_id || "None"}</td>
                                    <td>{record.policy_reason}</td>
                                    <td>{formatTimestamp(record.audit_timestamp)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </section>
    );
}

/* ==========================================================================
   INCIDENT INVESTIGATION & TRIAGE DRAWER
   ========================================================================== */

function IncidentDrawer({ incident, onClose }) {
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
        <div className="drawer-backdrop" onClick={onClose}>
            <aside className="triage-drawer" onClick={event => event.stopPropagation()}>
                <div className="drawer-header">
                    <div>
                        <span className="drawer-breadcrumb">Incident Investigation // Triage</span>
                        <h2>{formatLabel(incident.incident_type)}</h2>
                        <div className="drawer-tags-row">
                            <span className={`severity-tag severity-${severity}`}>
                                {incident.severity}
                            </span>
                            <span className="meta-pill">
                                Confidence: {Math.round((incident.confidence || 0) * 100)}%
                            </span>
                            <span className="meta-pill">
                                Status: {formatLabel(incident.status)}
                            </span>
                        </div>
                    </div>

                    <button className="btn-close" onClick={onClose} aria-label="Close incident details">
                        <CloseIcon />
                    </button>
                </div>

                <div className="drawer-body">
                    {/* Metadata Grid */}
                    <div className="triage-meta-grid">
                        <div className="triage-meta-cell">
                            <span className="meta-label">Incident ID</span>
                            <strong className="meta-value monospace">{incident.incident_id}</strong>
                        </div>

                        <div className="triage-meta-cell">
                            <span className="meta-label">Detection Engines</span>
                            <strong className="meta-value">
                                {(payload.detection_methods || []).map(formatLabel).join(", ") || "Rule Engine"}
                            </strong>
                        </div>

                        <div className="triage-meta-cell">
                            <span className="meta-label">Affected Entity</span>
                            <strong className="meta-value monospace">{getIncidentSources(incident)}</strong>
                        </div>

                        <div className="triage-meta-cell">
                            <span className="meta-label">Correlated Alerts</span>
                            <strong className="meta-value">{payload.alerts?.length || 0} telemetry triggers</strong>
                        </div>
                    </div>

                    {/* Timeline */}
                    <div className="triage-timeline">
                        <div className="timeline-item">
                            <span className="timeline-marker" />
                            <div>
                                <span className="timeline-title">First Detected</span>
                                <span className="timeline-stamp">{formatTimestamp(incident.created_at)}</span>
                            </div>
                        </div>
                        <div className="timeline-line" />
                        <div className="timeline-item">
                            <span className="timeline-marker active" />
                            <div>
                                <span className="timeline-title">Last Observed</span>
                                <span className="timeline-stamp">{formatTimestamp(incident.updated_at)}</span>
                            </div>
                        </div>
                    </div>

                    {/* AI Incident Analysis */}
                    <div className="ai-section">
                        <div className="ai-section-header">
                            <div>
                                <h3>Autonomous Incident Analysis</h3>
                                <p>LLM correlation and mitigation rationale synthesis</p>
                            </div>
                            <button
                                className="btn btn-secondary btn-sm"
                                onClick={handleExplain}
                                disabled={explaining}
                            >
                                <BrainIcon /> {explaining ? "Analyzing..." : explanation ? "Re-Analyze" : "Analyze Incident"}
                            </button>
                        </div>

                        {explainError && (
                            <div className="status-banner status-banner-error" style={{ marginBottom: 12 }}>
                                {explainError}
                            </div>
                        )}

                        {explaining && (
                            <div className="ai-loading-box">
                                <div className="loading-spinner" />
                                <div>
                                    <strong>Consulting Security Model...</strong>
                                    <p>Correlating multi-source telemetry signals and synthesizing playbooks.</p>
                                </div>
                            </div>
                        )}

                        {explanation && !explaining && (
                            <div className="ai-results">
                                <div className="ai-provider-badge">
                                    {explanation.source === "ollama"
                                        ? `Provider: Ollama (${explanation.model || "llama3.2"})`
                                        : "Provider: Local Heuristic Engine"}
                                    {explanation.why_flagged?.primary_detector && (
                                        <span> • Vector: {explanation.why_flagged.primary_detector}</span>
                                    )}
                                </div>

                                <div className="ai-report-card">
                                    <h4>Incident Summary</h4>
                                    <p>{explanation.summary}</p>
                                </div>

                                <div className="ai-report-card">
                                    <h4>Root Cause Analysis</h4>
                                    <p>{explanation.why_flagged?.plain_explanation || explanation.root_cause}</p>
                                    {explanation.why_flagged?.key_signals && explanation.why_flagged.key_signals.length > 0 && (
                                        <ul className="signals-list">
                                            {explanation.why_flagged.key_signals.map((sig, idx) => (
                                                <li key={idx}>Signal {idx + 1}: {sig}</li>
                                            ))}
                                        </ul>
                                    )}
                                </div>

                                <div className="ai-report-card">
                                    <h4>Mitigation Rationale</h4>
                                    <p>{explanation.why_response_chosen}</p>
                                </div>

                                <div className="ai-report-card">
                                    <h4>Recommended Countermeasures</h4>
                                    <ul className="measures-list">
                                        {explanation.recommended_measures?.map((measure, idx) => (
                                            <li key={idx}>
                                                <span className="check-bullet">•</span>
                                                <span>{measure}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            </div>
                        )}
                    </div>
                </div>

                <div className="drawer-footer">
                    <button className="btn btn-secondary" style={{ width: "100%" }} onClick={onClose}>
                        Close Investigation [ESC]
                    </button>
                </div>
            </aside>
        </div>
    );
}

/* ==========================================================================
   APP MAIN SHELL
   ========================================================================== */

function App() {
    const [booting, setBooting] = useState(() => import.meta.env?.MODE !== "test");
    const [data, setData] = useState(EMPTY_DATA);
    const [activeView, setActiveView] = useState("overview");
    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [error, setError] = useState("");
    const [lastUpdated, setLastUpdated] = useState(null);
    const [selectedIncident, setSelectedIncident] = useState(null);
    const [searchTerm, setSearchTerm] = useState("");
    const [severityFilter, setSeverityFilter] = useState("ALL");
    const [simulationBusy, setSimulationBusy] = useState(false);
    const [simulationMessage, setSimulationMessage] = useState("");
    const [simulationError, setSimulationError] = useState("");
    const [resetting, setResetting] = useState(false);

    const [liveMode, setLiveMode] = useState({
        is_running: false,
        seed: null,
        events_generated: 0,
        attacks_injected: 0
    });

    const [showConsole, setShowConsole] = useState(false);
    const [liveLog, setLiveLog] = useState([]);
    const [toasts, setToasts] = useState([]);
    const [utcTime, setUtcTime] = useState(() => new Date().toISOString().substring(11, 19));

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
            setUtcTime(new Date().toISOString().substring(11, 19));
        }, 1000);
        return () => clearInterval(timer);
    }, []);

    useEffect(() => {
        const handleKeyDown = (e) => {
            if (e.key === "Escape") {
                setBooting(false);
                setSelectedIncident(null);
                setShowConsole(false);
            }
        };
        window.addEventListener("keydown", handleKeyDown);
        return () => window.removeEventListener("keydown", handleKeyDown);
    }, []);

    const threatStatus = useMemo(() => {
        if (!data.incidents || data.incidents.length === 0) {
            return { level: "status-normal", label: "Threat Level: Normal" };
        }
        if (data.incidents.some(i => i.severity === "CRITICAL")) {
            return { level: "status-critical", label: "Threat Level: Critical" };
        }
        if (data.incidents.some(i => i.severity === "HIGH")) {
            return { level: "status-elevated", label: "Threat Level: Elevated" };
        }
        return { level: "status-normal", label: "Threat Level: Guarded" };
    }, [data.incidents]);

    const loadData = useCallback(async (silent = false, signal) => {
        if (silent) {
            setRefreshing(true);
        } else {
            setLoading(true);
        }

        try {
            const dashboardData = await fetchDashboardData(signal);
            setData(dashboardData);
            setError("");
            setLastUpdated(new Date());
        } catch (requestError) {
            if (requestError.name !== "AbortError") {
                setError(requestError.message);
            }
        } finally {
            setLoading(false);
            setRefreshing(false);
        }
    }, []);

    const runSimulation = async (simulationFunction, ...args) => {
        if (simulationBusy) {
            return;
        }

        setSimulationBusy(true);
        setSimulationMessage("");
        setSimulationError("");

        try {
            const result = await simulationFunction(...args);
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
            setSimulationError(requestError.message);
            addToast("error", "SIMULATION FAULT", requestError.message || "Failed to execute simulation");
        } finally {
            setSimulationBusy(false);
        }
    };

    const handleRunDemo = async (seed = 42) => {
        await runSimulation(runDemoSimulation, seed);
    };

    const handleResetDatabase = async () => {
        if (!window.confirm("Purge all security telemetry, incidents, and mitigations? Database will be reset to 0 for a clean demonstration.")) {
            return;
        }

        setResetting(true);
        try {
            await resetDatabase();
            addToast("info", "DATABASE PURGED", "All security operations data reset to 0.");
            await loadData(false);
        } catch (err) {
            addToast("error", "RESET FAILED", err.message || "Failed to reset database");
        } finally {
            setResetting(false);
        }
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
            addToast("live", "LIVE INGESTION ENGAGED", `Real-time telemetry active (Seed: ${seed ?? "Random"})`);
            await loadData(true);
        } catch (err) {
            setSimulationError(err.message || "Failed to start live simulation");
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
            addToast("info", "LIVE INGESTION TERMINATED", "Background telemetry collection stopped.");
            await loadData(true);
        } catch (err) {
            setSimulationError(err.message || "Failed to stop live simulation");
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

    useEffect(() => {
        if (!showConsole) return;
        const pollLog = async () => {
            try {
                const logData = await fetchLiveLog();
                setLiveLog(logData.entries || []);
                if (liveMode.is_running) {
                    setLiveMode(prev => ({
                        ...prev,
                        events_generated: logData.events_generated ?? prev.events_generated,
                        attacks_injected: logData.attacks_injected ?? prev.attacks_injected,
                    }));
                }
            } catch (e) { void e; }
        };
        pollLog();
        const interval = setInterval(pollLog, 1500);
        return () => clearInterval(interval);
    }, [showConsole, liveMode.is_running]);

    useEffect(() => {
        const controller = new AbortController();

        const initialLoadTimer = window.setTimeout(() => {
            loadData(false, controller.signal);
        }, 0);

        const refreshInterval = window.setInterval(() => {
            loadData(true, controller.signal);
        }, 15000);

        return () => {
            controller.abort();
            window.clearTimeout(initialLoadTimer);
            window.clearInterval(refreshInterval);
        };
    }, [loadData]);

    function renderActiveView() {
        let content;
        if (activeView === "incidents") {
            content = (
                <IncidentsView
                    incidents={data.incidents}
                    searchTerm={searchTerm}
                    severityFilter={severityFilter}
                    onSearch={setSearchTerm}
                    onSeverityChange={setSeverityFilter}
                    onSelectIncident={setSelectedIncident}
                />
            );
        } else if (activeView === "events") {
            content = (
                <EventsView
                    events={data.events}
                />
            );
        } else if (activeView === "responses") {
            content = (
                <ResponsesView
                    decisions={data.decisions}
                    responses={data.responses}
                />
            );
        } else if (activeView === "audit") {
            content = (
                <AuditView
                    records={data.auditRecords}
                />
            );
        } else {
            content = (
                <Overview
                    data={data}
                    onSelectIncident={setSelectedIncident}
                    simulationBusy={simulationBusy}
                    simulationMessage={simulationMessage}
                    simulationError={simulationError}
                    liveMode={liveMode}
                    onNormalTraffic={count => runSimulation(generateNormalTraffic, count)}
                    onAttack={attackType => runSimulation(injectAttack, attackType)}
                    onRandomAttack={() => runSimulation(injectRandomAttack)}
                    onRunDemo={handleRunDemo}
                    onStartLive={handleStartLive}
                    onStopLive={handleStopLive}
                    onViewConsole={() => setShowConsole(true)}
                />
            );
        }

        return <div key={activeView} className="view-animated">{content}</div>;
    }

    return (
        <div className="app-root-container">
            {/* Ambient animated glowing cyber background */}
            <div className="ambient-background" aria-hidden="true">
                <div className="bg-orb bg-orb-1" />
                <div className="bg-orb bg-orb-2" />
                <div className="bg-orb bg-orb-3" />
                <div className="bg-orb bg-orb-4" />
                <div className="cyber-grid-overlay" />
                <div className="scanline-overlay" />
            </div>

            <div className="app-shell">
                <aside className="sidebar">
                <div
                    className="brand"
                    onClick={() => setBooting(true)}
                    style={{ cursor: "pointer" }}
                    title="Click to replay system initialization sequence"
                >
                    <div className="brand-icon-box">
                        <ShieldIcon />
                    </div>

                    <div className="brand-text">
                        <span className="brand-title">Aegis SecOps</span>
                        <span className="brand-subtitle">Autonomous Defense</span>
                    </div>
                </div>

                <nav>
                    {NAVIGATION_ITEMS.map(item => (
                        <button
                            key={item.id}
                            className={activeView === item.id ? "nav-item active" : "nav-item"}
                            onClick={() => setActiveView(item.id)}
                        >
                            <NavIcon type={item.icon} />
                            <span>{item.label}</span>
                        </button>
                    ))}
                </nav>

                <div className="sidebar-status">
                    <span className="status-dot-green" />
                    <div>
                        <strong>System: Operational</strong>
                        <p>API: {API_BASE_URL}</p>
                    </div>
                </div>
            </aside>

            <main className="main-content">
                <header className="topbar">
                    <div className="topbar-left">
                        <p className="section-eyebrow">
                            Security Operations Console
                        </p>

                        <h1>
                            {NAVIGATION_ITEMS.find(item => item.id === activeView)?.label}
                        </h1>
                    </div>

                    <div className="topbar-actions">
                        <div className={`threat-status-badge ${threatStatus.level}`}>
                            <span className="status-dot-indicator" />
                            {threatStatus.label}
                        </div>

                        <div className="clock-metric">
                            <span>UTC TIME</span>
                            <strong>{utcTime}</strong>
                        </div>

                        <div className="clock-metric">
                            <span>LAST TELEMETRY SYNC</span>
                            <strong>
                                {lastUpdated ? lastUpdated.toLocaleTimeString() : "PENDING"}
                            </strong>
                        </div>

                        <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => loadData(true)}
                            disabled={refreshing}
                        >
                            <span className={refreshing ? "refreshing-icon" : ""}><RefreshIcon /></span>
                            <span>{refreshing ? "Syncing..." : "Sync Telemetry"}</span>
                        </button>

                        <button
                            className="btn btn-outline btn-sm btn-reset-db"
                            onClick={handleResetDatabase}
                            disabled={resetting || refreshing || simulationBusy}
                            title="Purge all database records to 0 for a clean demo"
                        >
                            <TrashIcon />
                            <span>{resetting ? "Purging..." : "Reset DB"}</span>
                        </button>
                    </div>
                </header>

                {error ? (
                    <section className="status-banner status-banner-error" style={{ marginBottom: 20 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <div>
                                <strong>Backend unavailable</strong>
                                <p style={{ margin: "2px 0 0 0", color: "#fca5a5" }}>{error}</p>
                            </div>
                            <button className="btn btn-outline btn-sm" onClick={() => loadData()}>
                                Retry
                            </button>
                        </div>
                    </section>
                ) : null}

                {loading ? (
                    <section className="loading-state">
                        <span className="loader" />
                        <p>Loading security operations data...</p>
                    </section>
                ) : (
                    renderActiveView()
                )}
            </main>

            <IncidentDrawer
                incident={selectedIncident}
                onClose={() => setSelectedIncident(null)}
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
                        <div className="toast-progress" />
                        <div className="toast-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                            <span className="technique-tag" style={{ fontSize: 9 }}>{toast.type.toUpperCase()}</span>
                            <button
                                className="btn-close"
                                style={{ width: 18, height: 18, fontSize: 11 }}
                                onClick={(e) => {
                                    e.stopPropagation();
                                    dismissToast(toast.id);
                                }}
                            >
                                <CloseIcon size={9} />
                            </button>
                        </div>
                        <strong style={{ fontSize: 12, color: "var(--text-primary)", display: "block" }}>{toast.title}</strong>
                        <p style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 2 }}>{toast.message}</p>
                    </div>
                ))}
            </div>
            {booting && (
                <BootSequence onComplete={() => setBooting(false)} />
            )}
        </div>
    </div>
    );
}

export default App;
