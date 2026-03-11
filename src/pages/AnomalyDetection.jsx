import React, { useState, useEffect } from 'react';
import { ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Legend, Cell } from 'recharts';
import { ShieldAlert, Activity, Eye, AlertTriangle, Search, Filter, ArrowUpRight, X, Lightbulb, CheckCircle } from 'lucide-react';
import { logActivity } from '../utils/activityLogger';

const SOLUTIONS_DB = {
    "Port Scan": {
        category: "Security Anomaly",
        method: "Rule-Based",
        actions: [
            "Block the source IP address immediately via Firewall.",
            "Implement rate limiting logic (e.g., fail2ban) for incoming connections.",
            "Audit open ports and close any unused services on the target."
        ]
    },
    "High Traffic Volume": {
        category: "Traffic Anomaly",
        method: "Statistical (AI)",
        actions: [
            "Enable DDoS protection measures on the gateway.",
            "Analyze traffic patterns to check for botnet signatures.",
            "Temporarily throttle bandwidth for the suspicious Source IP."
        ]
    },
    "Packet Anomaly": {
        category: "Traffic Anomaly",
        method: "Deep Packet Inspection",
        actions: [
            "Inspect packet payloads for malformed headers or potential exploits.",
            "Update Intrusion Detection System (IDS) signatures.",
            "Verify if the application protocol is compliant with RFC standards."
        ]
    },
    "Data Exfiltration": {
        category: "Security Anomaly",
        method: "Behavioral Analysis",
        actions: [
            "ISOLATE the compromised host from the network immediately.",
            "Review outbound traffic logs for sensitive file transfers.",
            "Reset credentials for all accounts associated with the source."
        ]
    },
    "DDoS Attack": {
        category: "Traffic Anomaly",
        method: "Rate Threshold",
        actions: [
            "Activate upstream DDoS mitigation and traffic scrubbing immediately.",
            "Block or rate-limit the top abusive source IPs at edge firewall.",
            "Enable autoscaling and tighten connection limits on exposed services."
        ]
    },
    "Brute Force Attempt": {
        category: "Security Anomaly",
        method: "Sensitive Port + Rate Rule",
        actions: [
            "Block the source IP and enforce temporary lockout policy.",
            "Enable MFA and increase login monitoring on targeted services.",
            "Review authentication logs and reset potentially exposed credentials."
        ]
    },
    "Abnormal Packet Size": {
        category: "Traffic Anomaly",
        method: "Packet Size Threshold",
        actions: [
            "Inspect packet captures for malformed or oversized payload patterns.",
            "Drop abnormal packet sizes at IDS/IPS or firewall policy level.",
            "Validate MTU/network path settings to reduce fragmentation abuse."
        ]
    },
    "Malware Signature": {
        category: "Security Anomaly",
        method: "Known IOC Port Signature",
        actions: [
            "Isolate the suspected endpoint and initiate malware triage.",
            "Block known C2 ports and destinations at perimeter controls.",
            "Run EDR scan and collect host-level forensic artifacts."
        ]
    },
    "Critical System Load": {
        category: "Performance Anomaly",
        method: "Resource Threshold",
        actions: [
            "Identify top CPU/RAM consumers and terminate abnormal processes.",
            "Scale compute resources and optimize overloaded services.",
            "Validate whether load spike is caused by malicious traffic."
        ]
    },
    "System Load": {
        category: "Performance Anomaly",
        method: "Resource Monitoring",
        actions: [
            "Check for runaway processes consuming CPU/RAM.",
            "Scale up server resources or optimize application code.",
            "Investigate potential crypto-mining malware."
        ]
    },
    "Default": {
        category: "Unknown Anomaly",
        method: "Heuristic",
        actions: [
            "Monitor the source IP closely for further suspicious activity.",
            "Cross-reference the IP with external Threat Intelligence feeds.",
            "Review system logs for any correlated authentication failures."
        ]
    }
};

const ANOMALY_DETAILS_DB = {
    "Port Scan": {
        reason: "One source IP attempted connections to many destination ports in a short window, matching reconnaissance behavior.",
        impacts: [
            "Indicates active attacker reconnaissance and mapping of exposed services.",
            "Increases probability of follow-up exploit attempts on discovered open ports.",
            "Can reveal weakly configured services and expand attack surface risk."
        ]
    },
    "High Traffic Volume": {
        reason: "Packet-per-second rate crossed the configured flood threshold for a source host.",
        impacts: [
            "Service latency and packet loss can increase for legitimate users.",
            "May saturate links or compute resources, reducing service availability.",
            "Can mask stealth attacks by generating high telemetry noise."
        ]
    },
    "DDoS Attack": {
        reason: "Traffic rate exceeded the critical DDoS threshold, indicating potential volumetric abuse.",
        impacts: [
            "High risk of service disruption or outage.",
            "Can exhaust bandwidth, firewall state tables, or server capacity.",
            "Business operations and customer-facing SLAs may be impacted."
        ]
    },
    "Brute Force Attempt": {
        reason: "High-rate access attempts were observed on sensitive ports associated with remote access and authentication services.",
        impacts: [
            "Increases risk of account compromise and unauthorized access.",
            "Can lead to lateral movement after successful credential abuse.",
            "Security operations workload increases due to incident triage and resets."
        ]
    },
    "Abnormal Packet Size": {
        reason: "Observed packet length exceeded normal expected bounds and matched abnormal packet-size rule.",
        impacts: [
            "May indicate malformed traffic, evasive payloads, or protocol abuse.",
            "Can degrade network performance through fragmentation/reassembly pressure.",
            "Raises risk of IDS evasion and parser-related vulnerabilities."
        ]
    },
    "Malware Signature": {
        reason: "Traffic matched known suspicious control/signature ports commonly linked with malware or C2 channels.",
        impacts: [
            "Possible endpoint compromise and outbound command-and-control activity.",
            "Risk of data exfiltration, persistence, and spread to other hosts.",
            "Requires immediate containment to reduce blast radius."
        ]
    },
    "Critical System Load": {
        reason: "CPU or RAM usage crossed critical thresholds during monitoring interval.",
        impacts: [
            "System response times degrade and monitoring accuracy may drop.",
            "Higher risk of service instability or failed security controls.",
            "Can be symptomatic of attack activity or resource exhaustion."
        ]
    },
    "Default": {
        reason: "The event triggered heuristic anomaly rules based on unusual traffic behavior.",
        impacts: [
            "Represents a potential emerging threat pattern requiring investigation.",
            "May affect reliability, confidentiality, or operational continuity.",
            "Should be correlated with endpoint and authentication logs."
        ]
    }
};

const resolveAnomalyKey = (type) => {
    const normalized = (type || '').toLowerCase();
    if (normalized.includes('port scan')) return 'Port Scan';
    if (normalized.includes('ddos')) return 'DDoS Attack';
    if (normalized.includes('high traffic')) return 'High Traffic Volume';
    if (normalized.includes('brute force')) return 'Brute Force Attempt';
    if (normalized.includes('malware')) return 'Malware Signature';
    if (normalized.includes('abnormal packet size')) return 'Abnormal Packet Size';
    if (normalized.includes('system load')) return 'Critical System Load';
    return 'Default';
};

const AnomalyDetection = () => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedAnomaly, setSelectedAnomaly] = useState(null);
    const [selectedDescription, setSelectedDescription] = useState(null);
    const [uiNotice, setUiNotice] = useState(null);
    const showNotice = (type, message) => setUiNotice({ type, message, id: Date.now() });

    // Track page visit
    useEffect(() => { logActivity('PAGE_VIEW', 'Anomaly Detection'); }, []);

    // Track search
    useEffect(() => {
        if (searchTerm) logActivity('SEARCH', 'Anomaly Detection', `Query: ${searchTerm}`);
    }, [searchTerm]);
    useEffect(() => {
        if (!uiNotice) return;
        const timer = setTimeout(() => setUiNotice(null), 4000);
        return () => clearTimeout(timer);
    }, [uiNotice]);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const res = await fetch('http://localhost:8000/anomalies');
                const json = await res.json();
                setData(json);
                setLoading(false);
            } catch (e) {
                console.error("Failed to fetch anomalies:", e);
                setLoading(false);
            }
        };
        fetchData();
        const refreshRate = parseInt(localStorage.getItem('refreshRate') || '5000');
        const interval = setInterval(fetchData, refreshRate);
        return () => clearInterval(interval);
    }, []);

    if (loading || !data) {
        return <div className="p-8 text-slate-400">Initializing Anomaly Detection Models...</div>;
    }

    const { summary, scatter_data, score_distribution, forensics } = data;
    const getSolutionData = (type) => SOLUTIONS_DB[resolveAnomalyKey(type)] || SOLUTIONS_DB.Default;
    const getDetailsData = (type) => ANOMALY_DETAILS_DB[resolveAnomalyKey(type)] || ANOMALY_DETAILS_DB.Default;
    const selectedSolutionData = selectedAnomaly ? getSolutionData(selectedAnomaly.type) : null;
    const selectedDetailData = selectedDescription ? getDetailsData(selectedDescription.type) : null;

    // Filter Logic
    const filteredLogs = data && data.forensics ? data.forensics.filter(log => {
        const term = searchTerm.toLowerCase();
        return (
            (log.source_ip || '').toLowerCase().includes(term) ||
            (log.destination_ip || '').toLowerCase().includes(term) ||
            (log.type || '').toLowerCase().includes(term) ||
            (log.protocol || '').toLowerCase().includes(term)
        );
    }) : [];

    const handleExport = () => {
        if (!data || !data.forensics) return;
        logActivity('EXPORT', 'Anomaly Detection', `Rows: ${filteredLogs.length || data.forensics.length}`);

        const htmlEscape = (value) => {
            if (value === null || value === undefined) return "";
            let text = String(value);
            if (/^[=+\-@]/.test(text)) { text = `'${text}`; }
            return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
        };

        const rowsToExport = filteredLogs.length ? filteredLogs : data.forensics;
        const priorityFromSeverity = (s) => s === "Critical" ? "P1" : s === "High" ? "P2" : s === "Medium" ? "P3" : "P4";
        const priorityClass = (p) => p === "P1" ? "p1" : p === "P2" ? "p2" : p === "P3" ? "p3" : "p4";

        const htmlRows = rowsToExport.map((row) => {
            const priority = priorityFromSeverity(row.severity);
            return `<tr><td>${htmlEscape(row.timestamp)}</td><td>${htmlEscape(row.source_ip)}</td><td>${htmlEscape(row.destination_ip)}</td><td>${htmlEscape(row.protocol)}</td><td>${htmlEscape(row.type)}</td><td>${htmlEscape(row.anomaly_score)}</td><td>${htmlEscape(row.severity)}</td><td class="${priorityClass(priority)}">${priority}</td><td>${htmlEscape(row.action_taken)}</td></tr>`;
        }).join("");

        const htmlContent = `<html><head><meta charset="utf-8"/><style>table{border-collapse:collapse;font-family:Calibri,Arial,sans-serif;font-size:11pt;}th,td{border:1px solid #d9d9d9;padding:6px 8px;}th{background:#1f4e78;color:#fff;font-weight:bold;}.p1{background:#f8d7da;color:#842029;}.p2{background:#fff3cd;color:#664d03;}.p3{background:#d1ecf1;color:#0c5460;}.p4{background:#e2e3e5;color:#41464b;}</style></head><body><div style="font-size:14pt;font-weight:bold;color:#1f4e78;padding-bottom:8px">Anomaly Detection Report</div><div style="color:#444;padding-bottom:6px">Generated: ${htmlEscape(new Date().toLocaleString())}</div><table><thead><tr><th>Timestamp</th><th>Source IP</th><th>Destination IP</th><th>Protocol</th><th>Type</th><th>Anomaly Score</th><th>Severity</th><th>Priority</th><th>Action Taken</th></tr></thead><tbody>${htmlRows}</tbody></table></body></html>`;

        const blob = new Blob([`\uFEFF${htmlContent}`], { type: "application/vnd.ms-excel;charset=utf-8;" });
        const link = document.createElement("a");
        const url = URL.createObjectURL(blob);
        link.setAttribute("href", url);
        link.setAttribute("download", `Anomaly_Report_${new Date().toISOString().slice(0, 10)}.xls`);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    };

    return (
        <div className="space-y-6 animate-fade-in">
            {/* 1. Detection Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <KPICard title="Total Anomalies" value={summary.total_anomalies} icon={<ShieldAlert className="text-red-400" />} sub="Detected Records" />
                <KPICard title="Anomaly Percentage" value={summary.anomaly_percentage} icon={<Activity className="text-orange-400" />} sub="% of Total Traffic" />
                <KPICard title="High Severity Alerts" value={summary.high_severity_count} icon={<AlertTriangle className="text-yellow-400" />} sub="Critical Threats" />
                <KPICard
                    title="Current Risk Level"
                    value={summary.risk_level}
                    icon={<Eye className="text-blue-400" />}
                    sub={`Score: ${summary.risk_score}/100`}
                    color={summary.risk_score >= 70 ? 'text-red-500' : summary.risk_score >= 30 ? 'text-yellow-500' : 'text-green-500'}
                />
            </div>

            {/* 2. Anomaly Visualization (Scatter Plot) */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 glass-panel p-6 relative overflow-hidden">
                    <div className="flex items-center justify-between mb-6">
                        <div>
                            <h2 className="text-lg font-semibold text-slate-100">Anomaly Detection Visualization</h2>
                            <p className="text-xs text-slate-400 mt-1">Rule-Based + Heuristic Anomaly Scoring (Live Data)</p>
                        </div>
                        <div className="flex items-center space-x-4 text-xs font-mono">
                            <span className="flex items-center"><span className="w-2 h-2 rounded-full bg-blue-500 mr-2"></span>Normal</span>
                            <span className="flex items-center"><span className="w-2 h-2 rounded-full bg-red-500 mr-2"></span>Anomaly</span>
                        </div>
                    </div>
                    <div className="h-80 w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                                <XAxis type="number" dataKey="x" name="Packet Size" stroke="#94a3b8" label={{ value: 'Packet Size (Bytes)', position: 'bottom', fill: '#64748b' }} />
                                <YAxis type="number" dataKey="y" name="Frequency" stroke="#94a3b8" label={{ value: 'Frequency Score', angle: -90, position: 'left', fill: '#64748b' }} />
                                <Tooltip cursor={{ strokeDasharray: '3 3' }} content={<CustomTooltip />} />
                                <Scatter name="Traffic" data={scatter_data} fill="#8884d8">
                                    {scatter_data.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.type === 'Anomaly' ? '#ef4444' : '#3b82f6'} />
                                    ))}
                                </Scatter>
                            </ScatterChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* 3. Anomaly Score Distribution */}
                <div className="glass-panel p-6">
                    <h2 className="text-lg font-semibold mb-4 text-slate-100">Score Distribution</h2>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={score_distribution} layout="vertical" margin={{ left: 10 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={true} vertical={false} />
                                <XAxis type="number" hide />
                                <YAxis dataKey="range" type="category" stroke="#94a3b8" width={50} tick={{ fontSize: 11 }} />
                                <Tooltip cursor={{ fill: 'transparent' }} contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155' }} />
                                <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} barSize={20} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>

            {/* 4. Suspicious Activity Table */}
            <div className="glass-panel p-6">
                <div className="flex items-center justify-between mb-6">
                    <h2 className="text-lg font-semibold text-slate-100">Suspicious Activity Log</h2>
                    <div className="flex space-x-2">
                        <div className="relative">
                            <Search className="absolute left-2.5 top-1.5 text-slate-500" size={14} />
                            <input
                                type="text"
                                placeholder="Search IPs, Type..."
                                className="bg-slate-900 border border-slate-700 rounded pl-8 pr-3 py-1 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                            />
                        </div>
                        <button onClick={handleExport} className="flex items-center space-x-2 bg-blue-600 hover:bg-blue-700 text-white px-3 py-1.5 rounded-lg text-sm font-medium cursor-pointer transition-colors">
                            <ArrowUpRight size={14} className="mr-1" /> Export
                        </button>
                    </div>
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="text-slate-400 text-xs border-b border-slate-700">
                                <th className="p-3 font-semibold">Time</th>
                                <th className="p-3 font-semibold">Source IP</th>
                                <th className="p-3 font-semibold">Destination IP</th>
                                <th className="p-3 font-semibold">Type</th>
                                <th className="p-3 font-semibold">Protocol</th>
                                <th className="p-3 font-semibold">Score</th>
                                <th className="p-3 font-semibold">Severity</th>
                                <th className="p-3 font-semibold">Description</th>
                                <th className="p-3 font-semibold">Solution</th>
                            </tr>
                        </thead>
                        <tbody className="text-sm">
                            {filteredLogs.map((log, index) => (
                                <tr key={index} className="border-b border-slate-700 hover:bg-slate-800 transition-colors">
                                    <td className="p-3 text-slate-400">{log.timestamp}</td>
                                    <td className="p-3 text-blue-400 font-mono">{log.source_ip}</td>
                                    <td className="p-3 text-slate-300 font-mono">{log.destination_ip}</td>
                                    <td className="p-3 text-slate-300">{log.type}</td>
                                    <td className="p-3"><span className="bg-slate-800 text-slate-400 px-2 py-0.5 rounded text-xs">{log.protocol}</span></td>
                                    <td className="p-3 font-medium text-orange-400">{log.anomaly_score}</td>
                                    <td className="p-3">
                                        <span className={`px-2 py-1 rounded text-xs font-semibold ${log.severity === 'Critical' ? 'bg-red-500/10 text-red-500' : log.severity === 'High' ? 'bg-orange-500/10 text-orange-500' : 'bg-yellow-500/10 text-yellow-500'}`}>
                                            {log.severity}
                                        </span>
                                    </td>
                                    <td className="p-3">
                                        <button
                                            onClick={() => {
                                                setSelectedAnomaly(null);
                                                setSelectedDescription(log);
                                                logActivity('VIEW_DESCRIPTION', 'Anomaly Detection', `Type: ${log.type} | IP: ${log.source_ip}`);
                                            }}
                                            className="text-amber-400 hover:text-amber-300 text-xs font-medium border border-amber-500/30 px-2 py-1 rounded hover:bg-amber-500/10"
                                        >
                                            View Details
                                        </button>
                                    </td>
                                    <td className="p-3">
                                        <button
                                            onClick={() => {
                                                setSelectedDescription(null);
                                                setSelectedAnomaly(log);
                                                logActivity('VIEW_SOLUTION', 'Anomaly Detection', `Type: ${log.type} | IP: ${log.source_ip}`);
                                            }}
                                            className="text-blue-400 hover:text-blue-300 text-xs font-medium border border-blue-500/30 px-2 py-1 rounded hover:bg-blue-500/10 flex items-center"
                                        >
                                            <Lightbulb size={12} className="mr-1" /> View Solution
                                        </button>
                                    </td>
                                </tr>
                            ))}
                            {forensics.length === 0 && (
                                <tr>
                                    <td colSpan="9" className="p-8 text-center text-slate-500 text-sm">
                                        No suspicious activity detected.
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Description Modal */}
            {selectedDescription && selectedDetailData && (
                <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4 animate-fade-in">
                    <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl max-w-lg w-full overflow-hidden">
                        <div className="p-4 border-b border-slate-700 bg-slate-800 flex justify-between items-center">
                            <h3 className="text-lg font-bold text-slate-100 flex items-center">
                                <AlertTriangle className="mr-2 text-amber-400" size={20} />
                                Anomaly Details
                            </h3>
                            <button onClick={() => setSelectedDescription(null)} className="text-slate-400 hover:text-white transition-colors">
                                <X size={20} />
                            </button>
                        </div>

                        <div className="p-6 space-y-4">
                            <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
                                <p className="text-xs uppercase tracking-wider text-slate-400 font-bold mb-2">Detected Event</p>
                                <h4 className="text-xl font-semibold text-white mb-1">{selectedDescription.type}</h4>
                                <p className="text-sm text-slate-400 font-mono">Source: <span className="text-blue-400">{selectedDescription.source_ip}</span></p>
                                <p className="text-sm text-slate-400 font-mono">Destination: <span className="text-slate-300">{selectedDescription.destination_ip}</span></p>
                            </div>

                            <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
                                <h5 className="text-sm font-semibold text-slate-200 mb-2">Reason for Raised Anomaly</h5>
                                <p className="text-sm text-slate-300 leading-relaxed">{selectedDetailData.reason}</p>
                            </div>

                            <div>
                                <h5 className="text-sm font-semibold text-slate-200 mb-3">Impact</h5>
                                <ul className="space-y-2">
                                    {selectedDetailData.impacts.map((impact, idx) => (
                                        <li key={idx} className="flex items-start text-sm text-slate-300 bg-slate-800 p-2 rounded">
                                            <span className="w-5 h-5 rounded-full bg-amber-500/20 text-amber-400 flex items-center justify-center text-xs font-bold mr-3 mt-0.5">{idx + 1}</span>
                                            {impact}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        </div>

                        <div className="p-4 bg-slate-800 border-t border-slate-700 flex justify-end">
                            <button onClick={() => setSelectedDescription(null)} className="px-4 py-2 rounded text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-700 transition-colors">
                                Close
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Solution Modal */}
            {selectedAnomaly && (
                <div className="fixed inset-0 bg-black/70  z-50 flex items-center justify-center p-4 animate-fade-in">
                    <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl max-w-lg w-full overflow-hidden">
                        <div className="p-4 border-b border-slate-700 bg-slate-800 flex justify-between items-center">
                            <h3 className="text-lg font-bold text-slate-100 flex items-center">
                                <ShieldAlert className="mr-2 text-red-400" size={20} />
                                Anomaly Remediation
                            </h3>
                            <button onClick={() => setSelectedAnomaly(null)} className="text-slate-400 hover:text-white transition-colors">
                                <X size={20} />
                            </button>
                        </div>

                        <div className="p-6 space-y-4">
                            <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
                                <div className="flex justify-between items-start mb-2">
                                    <span className="text-slate-400 text-xs uppercase tracking-wider font-bold">Detected Threat</span>
                                    <div className="flex space-x-2">
                                        <span className={`text-xs font-bold px-2 py-0.5 rounded border ${(selectedSolutionData?.category || 'Unknown') === 'Security Anomaly' ? 'bg-red-500/10 text-red-400 border-red-500/20' : 'bg-blue-500/10 text-blue-400 border-blue-500/20'}`}>
                                            {selectedSolutionData?.category || 'Anomaly'}
                                        </span>
                                        <span className={`text-xs font-bold px-2 py-0.5 rounded ${selectedAnomaly.severity === 'Critical' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}`}>
                                            {selectedAnomaly.severity} Severity
                                        </span>
                                    </div>
                                </div>
                                <h4 className="text-xl font-semibold text-white mb-1">{selectedAnomaly.type}</h4>
                                <p className="text-sm text-slate-400 font-mono">Source: <span className="text-blue-400">{selectedAnomaly.source_ip}</span></p>
                                <div className="mt-3 flex items-center">
                                    <div className="flex-1 h-2 bg-slate-700 rounded-full overflow-hidden">
                                        <div
                                            className={`h-full ${selectedAnomaly.anomaly_score > 0.8 ? 'bg-red-500' : 'bg-orange-400'}`}
                                            style={{ width: `${selectedAnomaly.anomaly_score * 100}%` }}
                                        ></div>
                                    </div>
                                    <span className="ml-3 text-xs font-bold text-slate-300">{(selectedAnomaly.anomaly_score * 100).toFixed(1)}% Confidence</span>
                                </div>
                            </div>

                            <div>
                                <h5 className="text-sm font-semibold text-slate-200 mb-3 flex items-center">
                                    <CheckCircle size={16} className="text-green-400 mr-2" /> Recommended Actions
                                </h5>
                                <ul className="space-y-2">
                                    {(selectedSolutionData?.actions || SOLUTIONS_DB.Default.actions).map((step, idx) => (
                                        <li key={idx} className="flex items-start text-sm text-slate-300 bg-slate-800 p-2 rounded hover:bg-slate-800 transition-colors">
                                            <span className="w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-xs font-bold mr-3 mt-0.5">{idx + 1}</span>
                                            {step}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        </div>

                        <div className="p-4 bg-slate-800 border-t border-slate-700 flex justify-end space-x-3">
                            <button onClick={() => setSelectedAnomaly(null)} className="px-4 py-2 rounded text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-700 transition-colors">
                                Close
                            </button>
                            <button
                                onClick={async () => {
                                    try {
                                        const res = await fetch('http://localhost:8000/anomalies/fix', {
                                            method: 'POST',
                                            headers: { 'Content-Type': 'application/json' },
                                            body: JSON.stringify({ source_ip: selectedAnomaly.source_ip, anomaly_type: selectedAnomaly.type })
                                        });
                                        const result = await res.json();
                                        if (result.resolved) {
                                            logActivity('APPLY_FIX', 'Anomaly Detection', `Type: ${selectedAnomaly.type} | IP: ${selectedAnomaly.source_ip}`);
                                            showNotice('success', result.message);
                                            setSelectedAnomaly(null);
                                        } else {
                                            showNotice('error', "Failed: " + (result.message || "Unknown error"));
                                        }
                                    } catch (e) {
                                        showNotice('error', "Connection Error: " + e.message);
                                    }
                                }}
                                className="px-4 py-2 rounded text-sm font-medium bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-500/20 transition-all transform active:scale-95"
                            >
                                Apply Fix
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {uiNotice && (
                <ThemedNotice
                    type={uiNotice.type}
                    message={uiNotice.message}
                    onClose={() => setUiNotice(null)}
                />
            )}
        </div>
    );
};

const KPICard = ({ title, value, icon, sub, color = "text-slate-100" }) => (
    <div className="glass-panel p-6 border-l-2 border-transparent hover:border-blue-500/50 transition-all">
        <div className="flex items-center justify-between mb-4">
            <h3 className="text-slate-400 text-sm font-medium">{title}</h3>
            {icon}
        </div>
        <div>
            <div className={`text-3xl font-bold ${color}`}>{value}</div>
            <div className="text-xs text-slate-500 mt-1">{sub}</div>
        </div>
    </div>
);

const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
        const data = payload[0].payload;
        return (
            <div className="bg-slate-800 border border-slate-700 p-3 rounded shadow-xl text-xs">
                <p className={`font-bold mb-1 ${data.type === 'Anomaly' ? 'text-red-400' : 'text-blue-400'}`}>{data.type}</p>
                <p className="text-slate-300">Size: {data.x} bytes</p>
                <p className="text-slate-300">Freq: {data.y}</p>
                <p className="text-slate-400 mt-1">Score: {data.score.toFixed(4)}</p>
            </div>
        );
    }
    return null;
};

const ThemedNotice = ({ type = 'info', message, onClose }) => {
    const toneClass = type === 'success'
        ? 'border-cyan-400 bg-[#062a37] text-cyan-100'
        : type === 'error'
            ? 'border-red-400 bg-[#2a0b12] text-red-100'
            : 'border-blue-400 bg-[#0b1f38] text-blue-100';
    return (
        <div className="fixed inset-0 z-[60] flex items-start justify-center pt-24 bg-black/28 backdrop-blur-[2px] animate-fade-in">
            <div className={`hud-box w-[min(92vw,680px)] rounded-2xl border-2 px-5 py-4 shadow-[0_0_34px_rgba(34,211,238,0.35)] ${toneClass}`}>
                <div className="flex items-start justify-between gap-3">
                    <p className="text-base font-semibold leading-relaxed">{message}</p>
                    <button onClick={onClose} className="text-slate-300 hover:text-white text-sm">Close</button>
                </div>
            </div>
        </div>
    );
};

export default AnomalyDetection;
