import React, { useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Legend, Cell } from 'recharts';
import { ShieldCheck, AlertTriangle, Activity, Users, Globe, Zap, Filter, Clock } from 'lucide-react';
import { logActivity } from '../utils/activityLogger';

const getRangeWindowMs = (range) => {
    if (range === 'Last 1 Hour') return 60 * 60 * 1000;
    if (range === 'Last 24 Hours') return 24 * 60 * 60 * 1000;
    return Infinity;
};

const parseTrendPointTime = (point) => {
    if (!point) return null;
    if (point.timestamp) {
        const parsed = new Date(point.timestamp);
        if (!Number.isNaN(parsed.getTime())) return parsed;
    }
    if (point.name || point.time) {
        const label = point.name || point.time;
        const parsed = new Date();
        const parts = String(label).split(':');
        if (parts.length >= 2) {
            parsed.setHours(parseInt(parts[0], 10), parseInt(parts[1], 10), parseInt(parts[2] || '0', 10), 0);
            if (!Number.isNaN(parsed.getTime())) return parsed;
        }
    }
    return null;
};

const Dashboard = () => {
    const [timeRange, setTimeRange] = useState('Last 24 Hours');
    const [selectedProtocol, setSelectedProtocol] = useState('All Protocols');
    const [selectedSeverity, setSelectedSeverity] = useState('All Severities');
    const [stats, setStats] = useState({
        total_packets: 0,
        unique_ips: 0,
        alerts: []
    });
    const [trafficData, setTrafficData] = useState([]);
    const [uiNotice, setUiNotice] = useState(null);
    const refreshRate = parseInt(localStorage.getItem('refreshRate') || '2000', 10);
    const oneHourPoints = Math.max(1, Math.floor((60 * 60 * 1000) / Math.max(refreshRate, 1)));
    const recentAlertsLimit = Math.max(1, parseInt(localStorage.getItem('alertsDisplayLimit') || '10', 10));

    const showNotice = (type, message) => setUiNotice({ type, message, id: Date.now() });

    // Track page visit on mount
    useEffect(() => { logActivity('PAGE_VIEW', 'Dashboard'); }, []);

    // Track filter changes
    useEffect(() => { logActivity('FILTER_CHANGED', 'Dashboard', `Time Range: ${timeRange}`); }, [timeRange]);
    useEffect(() => { logActivity('FILTER_CHANGED', 'Dashboard', `Protocol: ${selectedProtocol}`); }, [selectedProtocol]);
    useEffect(() => { logActivity('FILTER_CHANGED', 'Dashboard', `Severity: ${selectedSeverity}`); }, [selectedSeverity]);
    useEffect(() => {
        if (!uiNotice) return;
        const timer = setTimeout(() => setUiNotice(null), 4000);
        return () => clearTimeout(timer);
    }, [uiNotice]);

    // Filter Logic - MUST be defined before threatData
    const filteredAlerts = stats.alerts ? stats.alerts.filter(alert => {
        // 1. Time Calculation
        // 1. Time Calculation
        let matchTime = true;
        try {
            const now = new Date();
            let alertDate = new Date();

            // Handle "HH:MM:SS" (Today) vs Full Date string
            if (alert.Timestamp && alert.Timestamp.includes(":") && alert.Timestamp.length <= 8) {
                const parts = alert.Timestamp.split(':');
                alertDate.setHours(parseInt(parts[0]), parseInt(parts[1]), parseInt(parts[2] || 0));
            } else if (alert.Timestamp) {
                alertDate = new Date(alert.Timestamp);
            }

            // Validate date
            if (isNaN(alertDate.getTime())) {
                matchTime = true; // Safe fallback
            } else {
                const diffMs = now - alertDate;
                // Allow up to 5 mins of future drift (diffMs > -300000)
                if (diffMs > -300000) {
                    if (timeRange === 'Last 1 Hour') matchTime = diffMs <= 3600000;
                    else if (timeRange === 'Last 24 Hours') matchTime = diffMs <= 86400000;
                    else if (timeRange === 'Last 7 Days') matchTime = diffMs <= 604800000;
                } else {
                    // Alert is significantly in future? Keep it visible just in case for debugging
                    matchTime = true;
                }
            }
        } catch { matchTime = true; }

        const matchSeverity = selectedSeverity === 'All Severities' || alert.Severity === selectedSeverity;
        const matchProtocol = selectedProtocol === 'All Protocols' ||
            (alert.Protocol && alert.Protocol.toUpperCase() === selectedProtocol.toUpperCase()) ||
            (alert.Type && alert.Type.toUpperCase().includes(selectedProtocol.toUpperCase()));

        return matchSeverity && matchProtocol && matchTime;
    }) : [];

    // Dynamic Threat Data Calculation based on Filtered Alerts
    const threatData = React.useMemo(() => {
        // Count specific threat types dynamically
        const counts = {};

        if (filteredAlerts.length > 0) {
            filteredAlerts.forEach(alert => {
                const t = alert.Type || 'Unknown';
                counts[t] = (counts[t] || 0) + 1;
            });
        }

        // Define color mapping for known types
        const colorMap = {
            'DDoS Attack': '#ef4444',     // Red
            'High Traffic Volume': '#ef4444',
            'Port Scan': '#f97316',       // Orange
            'Brute Force': '#eab308',     // Yellow
            'Malware Signature': '#6366f1', // Indigo
            'Suspicious Payload': '#8b5cf6', // Violet
            'Large Packet': '#3b82f6',    // Blue
            'Abnormal Packet Size': '#3b82f6',
        };

        return Object.keys(counts).map(type => ({
            name: type,
            count: counts[type],
            fill: colorMap[type] || '#94a3b8' // Default Gray
        }));
    }, [filteredAlerts]);

    // Fetch data from Python Backend
    useEffect(() => {
        const fetchData = async () => {
            try {
                // Fetch KPI Stats (now includes traffic_trend)
                const statsRes = await fetch('http://localhost:8000/stats');
                const statsJson = await statsRes.json();
                setStats(statsJson);

                // Transform traffic data for Recharts
                if (statsJson.traffic_trend) {
                    const formattedTraffic = statsJson.traffic_trend.map(item => ({
                        name: item.time,
                        packets: item.packets,
                        alerts: 0,
                        timestamp: item.timestamp || null
                    }));
                    setTrafficData(formattedTraffic);
                }

            } catch (error) {
                console.error("Failed to fetch backend data:", error);
            }
        };

        // Initial Fetch
        fetchData();

        // Polling (User Preference or Default 2s)
        const interval = setInterval(fetchData, refreshRate);
        return () => clearInterval(interval);
    }, [refreshRate]);

    // Filtered Traffic Data for Chart (Time Range)
    const chartData = React.useMemo(() => {
        const windowMs = getRangeWindowMs(timeRange);
        if (!Number.isFinite(windowMs)) return trafficData;
        if (trafficData.length === 0) return trafficData;

        const latestPointTime = parseTrendPointTime(trafficData[trafficData.length - 1]);
        if (!latestPointTime) return trafficData;
        const referenceMs = latestPointTime.getTime();

        const filtered = trafficData.filter((point) => {
            const pointTime = parseTrendPointTime(point);
            if (!pointTime) return true;
            const diffMs = referenceMs - pointTime.getTime();
            return diffMs >= 0 && diffMs <= windowMs;
        });

        // If history is shorter than 1h, timestamp filtering can return the full series.
        // Provide a stable fallback slice so 1h visibly differs from 24h in active sessions.
        if (timeRange === 'Last 1 Hour' && filtered.length === trafficData.length) {
            const fallbackPoints = Math.max(60, Math.floor(oneHourPoints / 6));
            if (trafficData.length > fallbackPoints) {
                return trafficData.slice(-fallbackPoints);
            }
        }
        return filtered;
    }, [timeRange, trafficData, oneHourPoints]);

    const suspiciousTrend = React.useMemo(() => {
        if (filteredAlerts.length < 2) return "Stable";
        const recent = filteredAlerts.slice(0, recentAlertsLimit).length;
        const older = filteredAlerts.slice(recentAlertsLimit, recentAlertsLimit * 2).length;
        if (recent > older) return "Rising";
        if (recent < older) return "Falling";
        return "Stable";
    }, [filteredAlerts, recentAlertsLimit]);

    const dominantProtocol = React.useMemo(() => {
        const entries = Object.entries(stats.protocols || {}).filter(([, count]) => Number(count) > 0);
        if (entries.length === 0) return "Protocol";
        entries.sort((a, b) => Number(b[1]) - Number(a[1]));
        return entries[0][0];
    }, [stats.protocols]);

    const primaryCardTitle = React.useMemo(() => {
        if (selectedProtocol !== 'All Protocols') return `${selectedProtocol} Packets`;
        if (stats.monitoring_mode === 'Imported Data Analysis') return dominantProtocol;
        return "Total Network Packets";
    }, [selectedProtocol, stats.monitoring_mode, dominantProtocol]);

    const scopedPacketValue = React.useMemo(() => {
        const windowTotal = chartData.reduce((sum, point) => sum + Number(point.packets || 0), 0);
        const protocolCounts = Object.values(stats.protocols || {}).reduce((sum, v) => sum + Number(v || 0), 0);
        const selectedCount = Number((stats.protocols && stats.protocols[selectedProtocol]) || 0);

        let scoped = windowTotal;
        if (selectedProtocol !== 'All Protocols' && protocolCounts > 0) {
            scoped = Math.round(windowTotal * (selectedCount / protocolCounts));
        }

        if (scoped > 0) return scoped.toLocaleString();
        if (selectedProtocol === 'All Protocols') return Number(stats.total_packets || 0).toLocaleString();
        return selectedCount.toLocaleString();
    }, [chartData, selectedProtocol, stats.protocols, stats.total_packets]);

    return (
        <div className="space-y-6">
            {/* Quick Filters */}
            <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-800 p-4 rounded-xl border border-slate-700 ">
                <div className="flex items-center space-x-2 text-slate-400">
                    <Filter size={18} />
                    <span className="text-sm font-medium">Filters:</span>
                </div>

                <div className="flex space-x-2">
                    {/* Import Data Button */}
                    <div className="relative">
                        <input
                            type="file"
                            accept=".csv,.json,.pcap,.pcapng,.cap"
                            className="hidden"
                            id="file-upload"
                            onChange={async (e) => {
                                const file = e.target.files[0];
                                if (!file) return;
                                const ext = (file.name.split('.').pop() || '').toLowerCase();
                                const allowed = new Set(['csv', 'json', 'pcap', 'pcapng', 'cap']);
                                if (!allowed.has(ext)) {
                                    showNotice('error', "The selected file format is not supported. Please upload a valid file (CSV/JSON/PCAP/PCAPNG/CAP).");
                                    e.target.value = '';
                                    return;
                                }
                                logActivity('FILE_IMPORT', 'Dashboard', `File: ${file.name}`);
                                showNotice('info', "Please wait while your file is being uploaded and validated.");

                                const formData = new FormData();
                                formData.append("file", file);

                                try {
                                    const res = await fetch('http://localhost:8000/upload', {
                                        method: 'POST',
                                        body: formData
                                    });
                                    const result = await res.json();

                                    if (result.error) {
                                        showNotice('error', "Import failed: " + result.error);
                                    }
                                } catch (err) {
                                    showNotice('error', "Upload error: " + err.message);
                                }
                            }}
                        />
                        <label
                            htmlFor="file-upload"
                            className="flex items-center space-x-2 bg-blue-600 hover:bg-blue-700 text-white px-3 py-1.5 rounded-lg text-sm font-medium cursor-pointer transition-colors"
                        >
                            <span className="hidden sm:inline">Import Data</span>
                        </label>
                    </div>

                    {stats.monitoring_mode === 'Imported Data Analysis' && (
                        <button
                            onClick={async () => {
                                try {
                                    await fetch('http://localhost:8000/clear_import', { method: 'POST' });
                                    setStats({ ...stats, monitoring_mode: 'Live Packet Capture' });
                                    logActivity('RESET_TO_LIVE', 'Dashboard');
                                    showNotice('success', "Switched to Live Packet Capture mode.");
                                } catch (e) {
                                    console.error("Failed to reset:", e);
                                    showNotice('error', "Failed to reset to live mode.");
                                }
                            }}
                            className="flex items-center space-x-2 bg-red-600 hover:bg-red-700 text-white px-3 py-1.5 rounded-lg text-sm font-medium cursor-pointer transition-colors"
                        >
                            <span>Reset to Live</span>
                        </button>
                    )}


                    <select
                        className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:border-blue-500"
                        value={timeRange}
                        onChange={(e) => setTimeRange(e.target.value)}
                    >
                        <option>Last 1 Hour</option>
                        <option>Last 24 Hours</option>
                    </select>
                    <select
                        className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:border-blue-500"
                        value={selectedProtocol}
                        onChange={(e) => setSelectedProtocol(e.target.value)}
                    >
                        <option>All Protocols</option>
                        {stats.protocols && Object.keys(stats.protocols).sort().map(p => (
                            <option key={p} value={p}>{p}</option>
                        ))}
                    </select>
                    <select
                        className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:border-blue-500"
                        value={selectedSeverity}
                        onChange={(e) => setSelectedSeverity(e.target.value)}
                    >
                        <option>All Severities</option>
                        <option>High</option>
                        <option>Medium</option>
                        <option>Low</option>
                    </select>
                </div>
            </div>

            {/* KPI Cards Row */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatCard
                    title={primaryCardTitle}
                    value={scopedPacketValue}
                    icon={<Activity className="text-blue-400" />}
                    trend="+Live"
                    subtitle="Packets Captured"
                />
                <StatCard
                    title="Unique Source IPs"
                    value={stats.unique_ips}
                    icon={<Globe className="text-purple-400" />}
                    trend="Active"
                    subtitle="Distinct Hosts"
                />
                <StatCard
                    title="Suspicious Events"
                    value={filteredAlerts.length}
                    icon={<Zap className="text-orange-400" />}
                    trend={suspiciousTrend}
                    isNegative
                    subtitle={selectedSeverity === 'All Severities' ? "Total Anomalies" : `${selectedSeverity} Sev. Alerts`}
                />
                <StatCard
                    title="Protocol Distribution"
                    value={stats.protocols ? Object.keys(stats.protocols).length : 0}
                    icon={<ShieldCheck className="text-green-400" />}
                    trend="Stable"
                    subtitle="Active Protocols"
                />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Main Traffic Graph */}
                <div className="lg:col-span-2 glass-panel p-6">
                    <div className="flex items-center justify-between mb-6">
                        <h2 className="text-lg font-semibold text-slate-100">Live Traffic Volume</h2>
                        <span className="text-xs text-slate-400">Real-time Packets</span>
                    </div>
                    <div className="h-80">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={chartData}>
                                <defs>
                                    <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                                <XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 12 }} />
                                <YAxis stroke="#94a3b8" tick={{ fontSize: 12 }} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#f8fafc' }}
                                    itemStyle={{ color: '#f8fafc' }}
                                />
                                <Area type="monotone" dataKey="packets" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorPackets)" />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Right Column Container */}
                <div className="space-y-6">

                    {/* Threat Distribution Panel */}
                    <div className="glass-panel p-6">
                        <h2 className="text-lg font-semibold mb-4 text-slate-100">Threat Distribution</h2>
                        <div className="h-48">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={threatData} layout="vertical" margin={{ top: 5, right: 30, left: 40, bottom: 5 }}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={true} vertical={false} />
                                    <XAxis type="number" hide />
                                    <YAxis dataKey="name" type="category" stroke="#94a3b8" width={110} tick={{ fontSize: 11 }} />
                                    <Tooltip cursor={{ fill: 'transparent' }} contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155' }} />
                                    <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={20}>
                                        {
                                            threatData.map((entry, index) => (
                                                <Cell key={`cell-${index}`} fill={entry.fill} />
                                            ))
                                        }
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    </div>

                    {/* Recent Alerts Panel */}
                    <div className="glass-panel p-6">
                        <h2 className="text-lg font-semibold mb-4 text-slate-100">Recent Alerts</h2>
                        <div className="space-y-4 max-h-64 overflow-y-auto custom-scrollbar">
                            {filteredAlerts && filteredAlerts.length > 0 ? (
                                filteredAlerts.slice(0, recentAlertsLimit).map((alert, index) => (
                                    <AlertItem
                                        key={index}
                                        severity={alert.Severity.toLowerCase()}
                                        message={`${alert.Type} from ${alert.Source}`}
                                        time={alert.Timestamp}
                                    />
                                ))
                            ) : (
                                <p className="text-slate-500 text-sm text-center py-4">No recent alerts</p>
                            )}
                        </div>
                    </div>

                </div>
            </div>

            {uiNotice && (
                <ThemedNotice
                    type={uiNotice.type}
                    message={uiNotice.message}
                    onClose={() => setUiNotice(null)}
                />
            )}
        </div >
    );
};

const StatCard = ({ title, value, icon, trend, isNegative, subtitle }) => (
    <div className="glass-panel p-6 hover:bg-slate-800 transition-colors border-l-2 border-transparent hover:border-blue-500/50">
        <div className="flex items-center justify-between mb-3">
            <h3 className="text-slate-400 text-sm font-medium">{title}</h3>
            {icon}
        </div>
        <div className="flex items-end justify-between">
            <div>
                <div className="text-2xl font-bold text-slate-100">{value}</div>
                <div className="text-xs text-slate-500 mt-1">{subtitle}</div>
            </div>
            <div className={`text-xs font-medium px-2 py-1 rounded ${isNegative ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'}`}>
                {trend}
            </div>
        </div>
    </div>
);

const AlertItem = ({ severity, message, time }) => {
    const getSeverityColor = (sev) => {
        switch (sev) {
            case 'critical': return 'bg-red-500';
            case 'high': return 'bg-orange-500';
            case 'medium': return 'bg-yellow-500';
            default: return 'bg-blue-500';
        }
    };

    return (
        <div className="flex items-start space-x-3 p-3 rounded-lg bg-slate-800 hover:bg-slate-700 transition-colors cursor-pointer border border-slate-800 hover:border-slate-700">
            <div className={`mt-1.5 w-2.5 h-2.5 rounded-full ${getSeverityColor(severity)} flex-shrink-0 animate-pulse`}></div>
            <div className="flex-1">
                <p className="text-sm font-medium text-slate-200">{message}</p>
                <div className="flex items-center mt-1 space-x-2">
                    <Clock size={12} className="text-slate-500" />
                    <span className="text-xs text-slate-500">{time}</span>
                </div>
            </div>
        </div>
    );
};

const ThemedNotice = ({ type = 'info', message, onClose }) => {
    const toneClass = type === 'success'
        ? 'border-cyan-400 bg-[#062a37] text-cyan-100'
        : type === 'error'
            ? 'border-red-400 bg-[#2a0b12] text-red-100'
            : 'border-blue-400 bg-[#0b1f38] text-blue-100';
    return (
        <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 bg-black/28 backdrop-blur-[2px] animate-fade-in">
            <div className={`hud-box w-[min(92vw,680px)] rounded-2xl border-2 px-5 py-4 shadow-[0_0_34px_rgba(34,211,238,0.35)] ${toneClass}`}>
                <div className="flex items-start justify-between gap-3">
                    <p className="text-base font-semibold leading-relaxed">{message}</p>
                    <button onClick={onClose} className="text-slate-300 hover:text-white text-sm">Close</button>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
