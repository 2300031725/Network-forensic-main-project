import React, { useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { FileText, Download, Fingerprint, Clock, AlertOctagon, Shield, Search, Filter } from 'lucide-react';
import { logActivity } from '../utils/activityLogger';

const ForensicsLogs = () => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');

    // Track page visit
    useEffect(() => { logActivity('PAGE_VIEW', 'Forensics'); }, []);

    // Track search
    useEffect(() => {
        if (searchTerm) logActivity('SEARCH', 'Forensics', `Query: ${searchTerm}`);
    }, [searchTerm]);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const res = await fetch('http://localhost:8000/forensics');
                const json = await res.json();
                setData(json);
                setLoading(false);
            } catch (e) {
                console.error("Failed to fetch forensics:", e);
                setLoading(false);
            }
        };
        fetchData();
        const refreshRate = parseInt(localStorage.getItem('refreshRate') || '5000');
        const interval = setInterval(fetchData, refreshRate);
        return () => clearInterval(interval);
    }, []);

    // Filter Logic
    const logsData = data && data.logs ? data.logs : [];
    const filteredLogs = logsData.filter(log => {
        const term = searchTerm.toLowerCase();
        const src = (log.source_ip || "Unknown").toLowerCase();
        const dst = (log.destination_ip || "Unknown").toLowerCase();
        const type = (log.attack_type || "Unknown").toLowerCase();
        const proto = (log.protocol || "Unknown").toLowerCase();
        return src.includes(term) || dst.includes(term) || type.includes(term) || proto.includes(term);
    });

    const handleExport = () => {
        if (!data) return;
        logActivity('EXPORT', 'Forensics', `Rows: ${filteredLogs.length || logsData.length}`);

        const htmlEscape = (value) => {
            if (value === null || value === undefined) return "";
            let text = String(value);
            if (/^[=+\-@]/.test(text)) { text = `'${text}`; }
            return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
        };
        const priorityFromSeverity = (severity) => {
            if (severity === "Critical") return "P1";
            if (severity === "High") return "P2";
            if (severity === "Medium") return "P3";
            return "P4";
        };
        const priorityClass = (priority) => {
            if (priority === "P1") return "p1";
            if (priority === "P2") return "p2";
            if (priority === "P3") return "p3";
            return "p4";
        };
        const rowsToExport = filteredLogs.length ? filteredLogs : logsData;
        const htmlRows = rowsToExport.map((l) => {
            const priority = priorityFromSeverity(l.severity);
            return `<tr><td>${htmlEscape(l.timestamp)}</td><td>${htmlEscape(l.source_ip)}</td><td>${htmlEscape(l.destination_ip)}</td><td>${htmlEscape(l.protocol)}</td><td>${htmlEscape(l.attack_type)}</td><td>${htmlEscape(l.severity)}</td><td class="${priorityClass(priority)}">${priority}</td><td>${htmlEscape(l.action_taken)}</td></tr>`;
        }).join("");

        const htmlContent = `<html><head><meta charset="utf-8"/><style>table{border-collapse:collapse;font-family:Calibri,Arial,sans-serif;font-size:11pt;}th,td{border:1px solid #d9d9d9;padding:6px 8px;white-space:nowrap;text-align:left;}th{background:#1f4e78;color:#ffffff;font-weight:bold;}.title{font-size:14pt;font-weight:bold;color:#1f4e78;border:none;padding:0 0 8px 0;}.meta{border:none;color:#444;padding:0 0 6px 0;}.p1{background:#f8d7da;color:#842029;font-weight:bold;}.p2{background:#fff3cd;color:#664d03;font-weight:bold;}.p3{background:#d1ecf1;color:#0c5460;font-weight:bold;}.p4{background:#e2e3e5;color:#41464b;font-weight:bold;}</style></head><body><div class="title">Forensic Evidence Log</div><div class="meta">Generated: ${htmlEscape(new Date().toLocaleString())}</div><div class="meta">Rows Exported: ${rowsToExport.length}</div><div class="meta">Priority Map: P1=Critical, P2=High, P3=Medium, P4=Low</div><table><thead><tr><th>Timestamp</th><th>Source IP</th><th>Destination IP</th><th>Protocol</th><th>Attack Type</th><th>Severity</th><th>Priority</th><th>Action Taken</th></tr></thead><tbody>${htmlRows}</tbody></table></body></html>`;

        const blob = new Blob([`\uFEFF${htmlContent}`], { type: "application/vnd.ms-excel;charset=utf-8;" });
        const link = document.createElement("a");
        const url = URL.createObjectURL(blob);
        link.setAttribute("href", url);
        link.setAttribute("download", "forensic_logs.xls");
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    };

    if (loading) return <div className="text-slate-400 p-10">Loading forensic data...</div>;

    const safeData = data || {};
    const {
        case_info = { id: "PENDING", time_range: "N/A", critical_events: 0, most_active_threat: "None" },
        timeline = [],
    } = safeData;

    const safeTimeline = timeline.length > 0 ? timeline : [{ time: "00:00", incidents: 0 }];

    return (
        <div className="space-y-6 animate-fade-in">
            {/* Header */}
            <div className="flex flex-col md:flex-row justify-between items-center">
                <div>
                    <h2 className="text-2xl font-bold text-slate-100 flex items-center">
                        <Fingerprint className="mr-3 text-blue-500" />
                        Forensic Investigation
                    </h2>
                    <p className="text-slate-400 text-sm mt-1">Active Case File • Digital Evidence Log</p>
                </div>
                <button
                    onClick={handleExport}
                    className="flex items-center bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded shadow-lg transition-all"
                >
                    <Download size={16} className="mr-2" />
                    Export Evidence
                </button>
            </div>

            {/* Investigation Summary Panel */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 bg-slate-800 p-4 rounded-xl border border-slate-700">
                <CaseStat label="Investigation ID" value={case_info.id} icon={<FileText size={16} className="text-blue-400" />} />
                <CaseStat label="Time Range" value={case_info.time_range} icon={<Clock size={16} className="text-purple-400" />} />
                <CaseStat label="Critical Events" value={case_info.critical_events} icon={<AlertOctagon size={16} className="text-red-400" />} />
                <CaseStat label="Most Active Threat" value={case_info.most_active_threat} icon={<Shield size={16} className="text-orange-400" />} />
            </div>

            {/* Incident Timeline */}
            <div className="glass-panel p-6">
                <h3 className="text-lg font-semibold text-slate-200 mb-4">Incident Timeline</h3>
                <div className="h-48 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={safeTimeline}>
                            <defs>
                                <linearGradient id="colorIncidents" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                            <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 12 }} />
                            <YAxis stroke="#94a3b8" tick={{ fontSize: 12 }} />
                            <Tooltip contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155' }} />
                            <Area type="monotone" dataKey="incidents" stroke="#3b82f6" fillOpacity={1} fill="url(#colorIncidents)" />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Detailed Forensic Log Table */}
            <div className="glass-panel overflow-hidden">
                <div className="p-4 border-b border-slate-700 flex justify-between items-center">
                    <h3 className="text-lg font-semibold text-slate-200">Detailed Evidence Log</h3>
                    <div className="relative">
                        <Search className="absolute left-3 top-2.5 text-slate-500" size={16} />
                        <input
                            type="text"
                            placeholder="Search Logs..."
                            className="bg-slate-900 border border-slate-700 rounded-lg pl-10 pr-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-blue-500 w-64"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </div>
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-slate-800 text-slate-400 text-sm">
                                <th className="p-4 font-semibold">Timestamp</th>
                                <th className="p-4 font-semibold">Source</th>
                                <th className="p-4 font-semibold">Destination</th>
                                <th className="p-4 font-semibold">Protocol</th>
                                <th className="p-4 font-semibold">Attack Type</th>
                                <th className="p-4 font-semibold">Severity</th>
                                <th className="p-4 font-semibold">Action</th>
                            </tr>
                        </thead>
                        <tbody className="text-sm divide-y divide-slate-700/50">
                            {filteredLogs.map((log, index) => (
                                <tr key={index} className="hover:bg-slate-800 transition-colors">
                                    <td className="p-4 text-slate-400 whitespace-nowrap">{log.timestamp}</td>
                                    <td className="p-4 font-mono text-blue-400">{log.source_ip}</td>
                                    <td className="p-4 font-mono text-slate-300">{log.destination_ip}</td>
                                    <td className="p-4"><span className="bg-slate-800 px-2 py-1 rounded text-xs text-slate-400 border border-slate-700 hud-no-corner">{log.protocol}</span></td>
                                    <td className="p-4 text-slate-200 font-medium">{log.attack_type}</td>
                                    <td className="p-4">
                                        <span className={`px-2 py-1 rounded-full text-xs font-semibold ${log.severity === 'Critical' ? 'bg-red-500/10 text-red-500' : log.severity === 'High' ? 'bg-orange-500/10 text-orange-500' : 'bg-blue-500/10 text-blue-500'}`}>
                                            {log.severity}
                                        </span>
                                    </td>
                                    <td className="p-4 text-slate-400">{log.action_taken}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

const CaseStat = ({ label, value, icon }) => (
    <div className="flex items-center space-x-3 p-2">
        <div className="bg-slate-900 p-2 rounded-lg border border-slate-700">{icon}</div>
        <div>
            <div className="text-xs text-slate-500 uppercase font-semibold">{label}</div>
            <div className="text-slate-100 font-bold">{value}</div>
        </div>
    </div>
);

export default ForensicsLogs;
