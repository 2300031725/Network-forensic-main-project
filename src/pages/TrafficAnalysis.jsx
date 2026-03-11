import React, { useState, useEffect } from 'react';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Filter } from 'lucide-react';
import { logActivity } from '../utils/activityLogger';

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8'];

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
    if (point.time) {
        const parsed = new Date();
        const parts = String(point.time).split(':');
        if (parts.length >= 2) {
            parsed.setHours(parseInt(parts[0], 10), parseInt(parts[1], 10), parseInt(parts[2] || '0', 10), 0);
            if (!Number.isNaN(parsed.getTime())) return parsed;
        }
    }
    return null;
};

const TrafficAnalysis = () => {
    const [analytics, setAnalytics] = useState({
        traffic_trend: [],
        top_sources: [],
        top_destinations: [],
        protocol_breakdown: [],
        packet_sizes: []
    });

    useEffect(() => {
        const fetchAnalytics = async () => {
            try {
                const res = await fetch('http://localhost:8000/analytics');
                const data = await res.json();
                setAnalytics(data);
            } catch (error) {
                console.error("Failed to fetch analytics:", error);
            }
        };

        fetchAnalytics();
        const refreshRate = parseInt(localStorage.getItem('refreshRate') || '2000');
        const interval = setInterval(fetchAnalytics, refreshRate);
        return () => clearInterval(interval);
    }, []);

    const [timeRange, setTimeRange] = useState('Last 24 Hours');
    const [selectedProtocol, setSelectedProtocol] = useState('All Protocols');

    // Activity tracking
    useEffect(() => { logActivity('PAGE_VIEW', 'Traffic Analysis'); }, []);
    useEffect(() => { logActivity('FILTER_CHANGED', 'Traffic Analysis', `Time: ${timeRange}`); }, [timeRange]);
    useEffect(() => { logActivity('FILTER_CHANGED', 'Traffic Analysis', `Protocol: ${selectedProtocol}`); }, [selectedProtocol]);

    // Filter Logic
    const filteredTrend = React.useMemo(() => {
        let data = [...analytics.traffic_trend];

        if (selectedProtocol !== 'All Protocols' && analytics.protocol_breakdown.length > 0) {
            const total = analytics.protocol_breakdown.reduce((sum, p) => sum + p.value, 0);
            const target = analytics.protocol_breakdown.find(p => p.name === selectedProtocol);
            const ratio = target && total > 0 ? (target.value / total) : 0;
            data = data.map(pt => ({ ...pt, packets: Math.floor(pt.packets * ratio) }));
        }

        const windowMs = getRangeWindowMs(timeRange);
        if (!Number.isFinite(windowMs)) return data;
        if (data.length === 0) return data;

        const latestPointTime = parseTrendPointTime(data[data.length - 1]);
        if (!latestPointTime) return data;
        const referenceMs = latestPointTime.getTime();

        return data.filter((point) => {
            const pointTime = parseTrendPointTime(point);
            if (!pointTime) return true;
            const diffMs = referenceMs - pointTime.getTime();
            return diffMs >= 0 && diffMs <= windowMs;
        });
    }, [analytics, timeRange, selectedProtocol]);

    const filteredProtocols = analytics.protocol_breakdown.filter(p => {
        if (selectedProtocol === 'All Protocols') return true;
        return p.name === selectedProtocol;
    });

    return (
        <div className="space-y-6 animate-fade-in">
            <div className="flex justify-between items-center">
                <h2 className="text-2xl font-bold text-slate-100">Traffic Trend Analysis</h2>

                <div className="flex items-center space-x-2 bg-slate-800 p-2 rounded-lg border border-slate-700">
                    <Filter size={16} className="text-slate-400" />
                    <select
                        className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-slate-300 focus:outline-none focus:border-blue-500"
                        value={timeRange}
                        onChange={(e) => setTimeRange(e.target.value)}
                    >
                        <option className="bg-slate-900">Last 1 Hour</option>
                        <option className="bg-slate-900">Last 24 Hours</option>
                    </select>
                    <select
                        className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-slate-300 focus:outline-none focus:border-blue-500"
                        value={selectedProtocol}
                        onChange={(e) => setSelectedProtocol(e.target.value)}
                    >
                        <option className="bg-slate-900">All Protocols</option>
                        {analytics.protocol_breakdown.map(p => p.name).sort().map(p => (
                            <option key={p} value={p} className="bg-slate-900">{p}</option>
                        ))}
                    </select>
                </div>
            </div>

            {/* Row 1: Traffic Trend Analysis (Full Width) */}
            <div className="glass-panel p-6">
                <h3 className="text-lg font-semibold mb-4 text-slate-200">Traffic Volume (Packets/Sec)</h3>
                <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={filteredTrend} margin={{ top: 10, right: 20, left: 20, bottom: 5 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                            <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 11 }} />
                            <YAxis stroke="#94a3b8" width={80} tick={{ fontSize: 11 }} tickFormatter={(v) => (typeof v === 'number' ? v.toLocaleString() : v)} />
                            <Tooltip contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155' }} />
                            <Line type="monotone" dataKey="packets" stroke="#3b82f6" strokeWidth={3} dot={false} activeDot={{ r: 8 }} />
                        </LineChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Row 2: Top IPs (Side by Side) */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="glass-panel p-6">
                    <h3 className="text-lg font-semibold mb-4 text-slate-200">Top Source IPs</h3>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={analytics.top_sources} layout="vertical" margin={{ top: 5, right: 30, left: 40, bottom: 5 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={true} vertical={false} />
                                <XAxis type="number" hide />
                                <YAxis dataKey="name" type="category" stroke="#94a3b8" width={100} tick={{ fontSize: 11 }} />
                                <Tooltip cursor={{ fill: 'transparent' }} contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155' }} />
                                <Bar dataKey="value" fill="#8884d8" radius={[0, 4, 4, 0]} barSize={20} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
                <div className="glass-panel p-6">
                    <h3 className="text-lg font-semibold mb-4 text-slate-200">Top Targeted Hosts</h3>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={analytics.top_destinations} layout="vertical" margin={{ top: 5, right: 30, left: 40, bottom: 5 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={true} vertical={false} />
                                <XAxis type="number" hide />
                                <YAxis dataKey="name" type="category" stroke="#94a3b8" width={120} tick={{ fontSize: 11 }} />
                                <Tooltip cursor={{ fill: 'transparent' }} contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155' }} />
                                <Bar dataKey="value" fill="#82ca9d" radius={[0, 4, 4, 0]} barSize={20} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>

            {/* Row 3: Protocol & Packet Size */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="glass-panel p-6">
                    <h3 className="text-lg font-semibold mb-4 text-slate-200">Protocol Breakdown</h3>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                <Pie
                                    data={filteredProtocols}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={60}
                                    outerRadius={80}
                                    fill="#8884d8"
                                    paddingAngle={5}
                                    dataKey="value"
                                >
                                    {filteredProtocols.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                    ))}
                                </Pie>
                                <Tooltip contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155' }} />
                                <Legend />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="glass-panel p-6">
                    <h3 className="text-lg font-semibold mb-4 text-slate-200">Packet Size Behavior</h3>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={analytics.packet_sizes}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                                <XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 11 }} />
                                <YAxis stroke="#94a3b8" width={80} tick={{ fontSize: 11 }} tickFormatter={(v) => (typeof v === 'number' ? v.toLocaleString() : v)} />
                                <Tooltip cursor={{ fill: 'transparent' }} contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155' }} />
                                <Bar dataKey="value" fill="#ffc658" radius={[4, 4, 0, 0]} barSize={40} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>

        </div>
    );
};

export default TrafficAnalysis;
