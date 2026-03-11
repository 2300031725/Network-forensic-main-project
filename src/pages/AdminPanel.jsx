import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    ShieldCheck, ShieldOff, Users, Clock, CheckCircle, XCircle,
    RefreshCw, Building2, Phone, Mail, Briefcase, User, Calendar,
    Search, Filter, ChevronDown, AlertTriangle, Settings, FileText,
    Lock, Unlock, RotateCcw, Download, Bell, Activity, Shield,
    LayoutDashboard, Trash2, Eye, MoreVertical, CheckSquare, Square,
    ChevronUp, Info, X, Save, ToggleLeft, ToggleRight, Zap
} from 'lucide-react';

const API = 'http://127.0.0.1:8000';

// ─── Status badge helper ──────────────────────────────────────────────────────
const STATUS_CFG = {
    pending: { bg: 'bg-yellow-500/15', text: 'text-yellow-400', border: 'border-yellow-500/30', label: 'Pending' },
    approved: { bg: 'bg-green-500/15', text: 'text-green-400', border: 'border-green-500/30', label: 'Approved' },
    rejected: { bg: 'bg-red-500/15', text: 'text-red-400', border: 'border-red-500/30', label: 'Rejected' },
    suspended: { bg: 'bg-orange-500/15', text: 'text-orange-400', border: 'border-orange-500/30', label: 'Suspended' },
};
const StatusBadge = ({ s }) => {
    const c = STATUS_CFG[s] || STATUS_CFG.pending;
    return <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${c.bg} ${c.text} ${c.border}`}>{c.label}</span>;
};

// ─── SLA helper ───────────────────────────────────────────────────────────────
const sla = (created_at) => {
    if (!created_at) return '—';
    const diff = Date.now() - new Date(created_at).getTime();
    const hrs = Math.floor(diff / 3600000);
    if (hrs < 1) return `${Math.floor(diff / 60000)}m waiting`;
    if (hrs < 24) return `${hrs}h waiting`;
    return `${Math.floor(hrs / 24)}d waiting`;
};
const slaColor = (created_at) => {
    if (!created_at) return 'text-slate-400';
    const hrs = (Date.now() - new Date(created_at).getTime()) / 3600000;
    if (hrs > 48) return 'text-red-400';
    if (hrs > 24) return 'text-orange-400';
    return 'text-yellow-400';
};

const ROLES = ['Analyst', 'Security Engineer', 'Network Admin', 'SOC Manager', 'Auditor', 'Admin', 'Other'];

// ─── Toast ────────────────────────────────────────────────────────────────────
const Toast = ({ msg, type = 'info', onClose }) => {
    const colors = { info: 'border-blue-500/40 bg-blue-600/20 text-blue-300', success: 'border-green-500/40 bg-green-600/20 text-green-300', error: 'border-red-500/40 bg-red-600/20 text-red-300' };
    return (
        <div className={`fixed top-20 right-6 z-[999] flex items-center gap-3 px-4 py-3 rounded-lg border shadow-xl text-sm animate-fade-in ${colors[type] || colors.info}`}>
            <span>{msg}</span>
            <button onClick={onClose} className="opacity-60 hover:opacity-100"><X size={14} /></button>
        </div>
    );
};

// ─── Confirm Modal ────────────────────────────────────────────────────────────
const ConfirmModal = ({ title, message, onConfirm, onCancel, danger = false, children }) => (
    <div className="fixed inset-0 bg-black/70  z-[100] flex items-center justify-center p-4">
        <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-slate-100">{title}</h3>
            <p className="text-slate-400 text-sm">{message}</p>
            {children}
            <div className="flex gap-3 justify-end pt-2">
                <button onClick={onCancel} className="px-4 py-2 text-sm text-slate-300 hover:bg-slate-700 rounded transition-colors">Cancel</button>
                <button onClick={onConfirm} className={`px-4 py-2 text-sm text-white rounded transition-colors ${danger ? 'bg-red-600 hover:bg-red-500' : 'bg-blue-600 hover:bg-blue-500'}`}>Confirm</button>
            </div>
        </div>
    </div>
);

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN COMPONENT
// ═══════════════════════════════════════════════════════════════════════════════

const AdminPanel = () => {
    const navigate = useNavigate();
    const currentUser = JSON.parse(localStorage.getItem('user') || '{}');
    const adminName = currentUser.username || 'admin';
    const isAdmin = currentUser.role === 'Admin';

    // ── Global state ──────────────────────────────────────────────────────────
    const [activeTab, setActiveTab] = useState('overview');
    const [users, setUsers] = useState([]);
    const [auditLog, setAuditLog] = useState([]);
    const [userActivity, setUserActivity] = useState([]);
    const [alerts, setAlerts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [toast, setToast] = useState(null);
    const [confirmModal, setConfirmModal] = useState(null);

    // Users tab state
    const [search, setSearch] = useState('');
    const [filterStatus, setFilterStatus] = useState('all');
    const [filterRole, setFilterRole] = useState('all');
    const [sortOrder, setSortOrder] = useState('desc');       // 'asc' | 'desc'
    const [selectedIds, setSelectedIds] = useState([]);
    const [detailUser, setDetailUser] = useState(null);

    // Modals
    const [rejectModal, setRejectModal] = useState(null);         // {userId, username, isBulk}
    const [approveModal, setApproveModal] = useState(null);         // {userId, username, isBulk}
    const [rejectReason, setRejectReason] = useState('');
    const [approveNote, setApproveNote] = useState('');
    const [roleModal, setRoleModal] = useState(null);         // {userId, username, currentRole}
    const [newRole, setNewRole] = useState('');

    // Settings state
    const [settings, setSettings] = useState({
        rateLimitThreshold: 1000,
        anomalySensitivity: 75,
        dataRetentionDays: 30,
        maintenanceMode: false,
        emailNotifications: true,
        webhookUrl: '',
    });

    // ── Helpers ───────────────────────────────────────────────────────────────
    const showToast = (msg, type = 'info') => {
        setToast({ msg, type });
        setTimeout(() => setToast(null), 4000);
    };

    const api = useCallback(async (path, opts = {}) => {
        const res = await fetch(`${API}${path}`, {
            headers: { 'Content-Type': 'application/json' },
            ...opts,
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Request failed');
        return data;
    }, []);

    // ── Data fetchers ─────────────────────────────────────────────────────────
    const fetchUsers = useCallback(async () => {
        try {
            const data = await api('/auth/admin/users');
            setUsers(Array.isArray(data) ? data : []);
        } catch { showToast('Failed to load users', 'error'); }
    }, [api]);

    const fetchAuditLog = useCallback(async () => {
        try {
            const data = await api('/auth/admin/audit-log');
            setAuditLog(Array.isArray(data) ? data : []);
        } catch { setAuditLog([]); }
    }, [api]);

    const fetchUserActivity = useCallback(async () => {
        try {
            const data = await api('/auth/admin/user-activity');
            setUserActivity(Array.isArray(data) ? data : []);
        } catch { setUserActivity([]); }
    }, [api]);

    const fetchAlerts = useCallback(async () => {
        try {
            const data = await api('/api/alerts');
            setAlerts(Array.isArray(data) ? data : []);
        } catch { setAlerts([]); }
    }, [api]);

    useEffect(() => {
        if (!isAdmin) return;
        setLoading(true);
        Promise.all([fetchUsers(), fetchAuditLog(), fetchUserActivity(), fetchAlerts()]).finally(() => setLoading(false));
    }, []);

    const refresh = () => {
        setLoading(true);
        Promise.all([fetchUsers(), fetchAuditLog(), fetchUserActivity(), fetchAlerts()]).finally(() => setLoading(false));
        showToast('Data refreshed', 'success');
    };

    // ── User actions ──────────────────────────────────────────────────────────
    const doApprove = async (userId, username, notes = '') => {
        await api(`/auth/admin/approve/${userId}`, {
            method: 'POST',
            body: JSON.stringify({ notes, admin_username: adminName }),
        });
        showToast(`✅ ${username} approved`, 'success');
        setApproveModal(null); setApproveNote('');
        fetchUsers(); fetchAuditLog();
    };

    const doReject = async (userId, username, reason = '') => {
        if (!reason.trim()) { showToast('Rejection reason is required', 'error'); return; }
        await api(`/auth/admin/reject/${userId}`, {
            method: 'POST',
            body: JSON.stringify({ reason, admin_username: adminName }),
        });
        showToast(`❌ ${username} rejected`, 'info');
        setRejectModal(null); setRejectReason('');
        fetchUsers(); fetchAuditLog();
    };

    const doBulk = async (action) => {
        if (!selectedIds.length) { showToast('No users selected', 'error'); return; }
        if (action === 'reject' && !rejectReason.trim()) { showToast('Rejection reason required', 'error'); return; }
        const data = await api('/auth/admin/bulk-action', {
            method: 'POST',
            body: JSON.stringify({ user_ids: selectedIds, action, notes: rejectReason || approveNote, admin_username: adminName }),
        });
        showToast(data.message, 'success');
        setSelectedIds([]); setRejectModal(null); setApproveModal(null);
        setRejectReason(''); setApproveNote('');
        fetchUsers(); fetchAuditLog();
    };

    const doUpdateRole = async () => {
        if (!roleModal || !newRole) return;
        await api(`/auth/admin/update-role/${roleModal.userId}`, {
            method: 'POST',
            body: JSON.stringify({ role: newRole, admin_username: adminName }),
        });
        showToast(`Role updated → ${newRole}`, 'success');
        setRoleModal(null); setNewRole('');
        fetchUsers(); fetchAuditLog();
    };

    const doSuspend = async (userId, username) => {
        await api(`/auth/admin/suspend/${userId}`, {
            method: 'POST',
            body: JSON.stringify({ admin_username: adminName }),
        });
        showToast(`🔒 ${username} suspended`, 'info');
        setConfirmModal(null); setDetailUser(null);
        fetchUsers(); fetchAuditLog();
    };

    const doReactivate = async (userId, username) => {
        await api(`/auth/admin/reactivate/${userId}`, {
            method: 'POST',
            body: JSON.stringify({ admin_username: adminName }),
        });
        showToast(`🔓 ${username} reactivated`, 'success');
        setConfirmModal(null); setDetailUser(null);
        fetchUsers(); fetchAuditLog();
    };

    // ── Derived data ──────────────────────────────────────────────────────────
    const counts = {
        total: users.length,
        pending: users.filter(u => u.status === 'pending').length,
        approved: users.filter(u => u.status === 'approved').length,
        rejected: users.filter(u => u.status === 'rejected').length,
        suspended: users.filter(u => u.status === 'suspended').length,
    };

    const filteredUsers = users
        .filter(u => filterStatus === 'all' || u.status === filterStatus)
        .filter(u => filterRole === 'all' || u.role === filterRole)
        .filter(u => !search || [u.username, u.email, u.full_name, u.organization]
            .some(f => (f || '').toLowerCase().includes(search.toLowerCase())))
        .sort((a, b) => sortOrder === 'desc'
            ? new Date(b.created_at) - new Date(a.created_at)
            : new Date(a.created_at) - new Date(b.created_at));

    const pendingUsers = users.filter(u => u.status === 'pending');
    const toggleSelect = (id) => setSelectedIds(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
    const toggleAll = () => setSelectedIds(selectedIds.length === filteredUsers.length ? [] : filteredUsers.map(u => u.id));

    const exportAuditCSV = () => {
        const rows = [['ID', 'Admin', 'Action', 'Target User', 'Notes', 'Date'], ...auditLog.map(l => [l.id, l.admin_username, l.action, l.target_username, l.notes, l.created_at])];
        const csv = rows.map(r => r.join(',')).join('\n');
        const a = document.createElement('a');
        a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
        a.download = 'audit_log.csv'; a.click();
    };

    // ── Access guard ──────────────────────────────────────────────────────────
    if (!isAdmin) {
        return (
            <div className="min-h-screen bg-slate-900 flex flex-col items-center justify-center space-y-4 text-center p-4">
                <div className="bg-red-500/10 border border-red-500/30 rounded-full p-6">
                    <ShieldOff size={48} className="text-red-400" />
                </div>
                <h2 className="text-2xl font-bold text-slate-100">Access Denied</h2>
                <p className="text-slate-400 max-w-sm">Only <span className="text-red-400 font-semibold">Admin</span> accounts can view this page.</p>
                <button onClick={() => { localStorage.clear(); navigate('/login'); }}
                    className="px-6 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm transition-colors">
                    Go to Login
                </button>
            </div>
        );
    }

    const handleLogout = () => { localStorage.clear(); navigate('/login'); };

    // ══════════════════════════════════════════════════════════════════════════
    // RENDER
    // ══════════════════════════════════════════════════════════════════════════
    return (
        <div className="min-h-screen bg-slate-900 text-slate-100">

            {/* ── Toast ── */}
            {toast && <Toast msg={toast.msg} type={toast.type} onClose={() => setToast(null)} />}

            {/* ── Confirm Modal ── */}
            {confirmModal && (
                <ConfirmModal
                    title={confirmModal.title}
                    message={confirmModal.message}
                    danger={confirmModal.danger}
                    onConfirm={confirmModal.onConfirm}
                    onCancel={() => setConfirmModal(null)}
                />
            )}

            {/* ── Approve Modal ── */}
            {approveModal && (
                <ConfirmModal title="Approve User" message={`Approve ${approveModal.isBulk ? `${selectedIds.length} selected users` : approveModal.username}?`}
                    onConfirm={() => approveModal.isBulk ? doBulk('approve') : doApprove(approveModal.userId, approveModal.username, approveNote)}
                    onCancel={() => { setApproveModal(null); setApproveNote(''); }}>
                    <textarea value={approveNote} onChange={e => setApproveNote(e.target.value)}
                        placeholder="Optional approval notes..." rows={2}
                        className="w-full bg-slate-800 border border-slate-600 rounded px-3 py-2 text-sm text-slate-200 placeholder-slate-500 resize-none focus:outline-none focus:border-blue-500" />
                </ConfirmModal>
            )}

            {/* ── Reject Modal ── */}
            {rejectModal && (
                <ConfirmModal title="Reject User" danger
                    message={`Reject ${rejectModal.isBulk ? `${selectedIds.length} selected users` : rejectModal.username}? A reason is required.`}
                    onConfirm={() => rejectModal.isBulk ? doBulk('reject') : doReject(rejectModal.userId, rejectModal.username, rejectReason)}
                    onCancel={() => { setRejectModal(null); setRejectReason(''); }}>
                    <textarea value={rejectReason} onChange={e => setRejectReason(e.target.value)}
                        placeholder="Rejection reason (required)..." rows={2}
                        className="w-full bg-slate-800 border border-red-600/40 rounded px-3 py-2 text-sm text-slate-200 placeholder-slate-500 resize-none focus:outline-none focus:border-red-500" />
                </ConfirmModal>
            )}

            {/* ── Role Modal ── */}
            {roleModal && (
                <ConfirmModal title="Change Role" message={`Change role for @${roleModal.username}`}
                    onConfirm={doUpdateRole} onCancel={() => { setRoleModal(null); setNewRole(''); }}>
                    <select value={newRole} onChange={e => setNewRole(e.target.value)}
                        className="w-full bg-slate-800 border border-slate-600 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500">
                        <option value="">— Select new role —</option>
                        {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                    </select>
                </ConfirmModal>
            )}

            {/* ── User Detail Drawer ── */}
            {detailUser && (
                <div className="fixed inset-0 bg-black/70  z-50 flex items-center justify-center p-4">
                    <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl max-w-lg w-full overflow-hidden">
                        <div className="p-4 border-b border-slate-700 bg-slate-800 flex justify-between items-center">
                            <h3 className="font-bold text-slate-100 flex items-center gap-2"><User size={16} className="text-blue-400" /> User Profile</h3>
                            <button onClick={() => setDetailUser(null)} className="text-slate-400 hover:text-white"><X size={18} /></button>
                        </div>
                        <div className="p-6 space-y-3 text-sm">
                            {[
                                [<User size={14} />, 'Full Name', detailUser.full_name || '—'],
                                [<User size={14} />, 'Username', `@${detailUser.username}`],
                                [<Mail size={14} />, 'Email', detailUser.email],
                                [<Phone size={14} />, 'Phone', detailUser.phone || '—'],
                                [<Building2 size={14} />, 'Org', detailUser.organization || '—'],
                                [<Briefcase size={14} />, 'Role', detailUser.role || 'Analyst'],
                                [<Calendar size={14} />, 'Joined', detailUser.created_at ? detailUser.created_at.split(' ')[0] : '—'],
                                [<Clock size={14} />, 'Last Login', detailUser.last_login ? detailUser.last_login.split(' ')[0] : 'Never'],
                            ].map(([icon, label, val]) => (
                                <div key={label} className="flex items-center gap-3">
                                    <span className="text-slate-500 w-5">{icon}</span>
                                    <span className="text-slate-400 w-24 flex-shrink-0">{label}</span>
                                    <span className="text-slate-200 font-medium">{val}</span>
                                </div>
                            ))}
                            <div className="flex items-center gap-3">
                                <span className="text-slate-500 w-5"><ShieldCheck size={14} /></span>
                                <span className="text-slate-400 w-24 flex-shrink-0">Status</span>
                                <StatusBadge s={detailUser.status} />
                            </div>
                            {detailUser.reject_reason && (
                                <div className="mt-2 p-3 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-300">
                                    <strong>Rejection reason:</strong> {detailUser.reject_reason}
                                </div>
                            )}
                        </div>
                        <div className="p-4 bg-slate-800 border-t border-slate-700 flex flex-wrap gap-2 justify-end">
                            {detailUser.status !== 'approved' &&
                                <button onClick={() => { setApproveModal({ userId: detailUser.id, username: detailUser.username }); setDetailUser(null); }}
                                    className="px-3 py-1.5 text-xs bg-green-600 hover:bg-green-500 text-white rounded flex items-center gap-1 transition-colors"><CheckCircle size={12} /> Approve</button>}
                            {detailUser.status !== 'rejected' &&
                                <button onClick={() => { setRejectModal({ userId: detailUser.id, username: detailUser.username }); setDetailUser(null); }}
                                    className="px-3 py-1.5 text-xs bg-red-600 hover:bg-red-500 text-white rounded flex items-center gap-1 transition-colors"><XCircle size={12} /> Reject</button>}
                            {detailUser.status !== 'suspended' &&
                                <button onClick={() => setConfirmModal({ title: 'Suspend User', message: `Suspend @${detailUser.username}?`, danger: true, onConfirm: () => doSuspend(detailUser.id, detailUser.username) })}
                                    className="px-3 py-1.5 text-xs bg-orange-600 hover:bg-orange-500 text-white rounded flex items-center gap-1 transition-colors"><Lock size={12} /> Suspend</button>}
                            {detailUser.status === 'suspended' &&
                                <button onClick={() => setConfirmModal({ title: 'Reactivate User', message: `Reactivate @${detailUser.username}?`, danger: false, onConfirm: () => doReactivate(detailUser.id, detailUser.username) })}
                                    className="px-3 py-1.5 text-xs bg-blue-600 hover:bg-blue-500 text-white rounded flex items-center gap-1 transition-colors"><Unlock size={12} /> Reactivate</button>}
                            <button onClick={() => { setRoleModal({ userId: detailUser.id, username: detailUser.username, currentRole: detailUser.role }); setNewRole(detailUser.role); setDetailUser(null); }}
                                className="px-3 py-1.5 text-xs bg-slate-600 hover:bg-slate-500 text-white rounded flex items-center gap-1 transition-colors"><Briefcase size={12} /> Change Role</button>
                        </div>
                    </div>
                </div>
            )}

            {/* ── Top Header ── */}
            <header className="border-b border-slate-700 bg-slate-800 sticky top-0 z-40">
                <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className="bg-red-600/20 border border-red-500/40 rounded-lg p-1.5">
                            <ShieldCheck size={20} className="text-red-400" />
                        </div>
                        <span className="text-lg font-bold bg-gradient-to-r from-red-400 to-orange-400 bg-clip-text text-transparent">Admin Dashboard</span>
                        <span className="hidden md:flex items-center gap-1 text-xs text-slate-500 bg-slate-800 px-2 py-1 rounded-full border border-slate-700">
                            <div className="w-1.5 h-1.5 rounded-full bg-green-400" /> Live
                        </span>
                    </div>
                    <div className="flex items-center gap-3">
                        <button onClick={refresh} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white px-3 py-1.5 rounded-lg hover:bg-slate-700 border border-slate-700 transition-colors">
                            <RefreshCw size={13} /> Refresh
                        </button>
                        <span className="text-sm text-slate-400 hidden sm:block">
                            <span className="text-white font-medium">{adminName}</span>
                        </span>
                        <button onClick={handleLogout}
                            className="px-3 py-1.5 text-xs rounded-lg border border-slate-600 text-slate-300 hover:bg-red-600 hover:border-red-600 hover:text-white transition-all">
                            Logout
                        </button>
                    </div>
                </div>

                {/* Tabs */}
                <div className="max-w-7xl mx-auto px-6 flex gap-1 pb-0">
                    {[
                        { id: 'overview', label: 'Overview', icon: <LayoutDashboard size={14} /> },
                        { id: 'users', label: 'Users', icon: <Users size={14} /> },
                        { id: 'security', label: 'Audit Log', icon: <Shield size={14} /> },
                        { id: 'alerts', label: 'Alerts', icon: <Bell size={14} /> },
                        { id: 'settings', label: 'Settings', icon: <Settings size={14} /> },
                    ].map(tab => (
                        <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                            className={`flex items-center gap-1.5 px-4 py-2.5 text-sm border-b-2 transition-all ${activeTab === tab.id
                                ? 'border-red-500 text-red-400 font-semibold'
                                : 'border-transparent text-slate-400 hover:text-slate-200'
                                }`}>
                            {tab.icon} {tab.label}
                            {tab.id === 'users' && counts.pending > 0 &&
                                <span className="bg-yellow-500 text-black text-xs font-bold px-1.5 py-0.5 rounded-full">{counts.pending}</span>}
                        </button>
                    ))}
                </div>
            </header>

            {/* ── Page Content ── */}
            <main className="max-w-7xl mx-auto px-6 py-8">

                {/* ════════ OVERVIEW TAB ════════ */}
                {activeTab === 'overview' && (
                    <div className="space-y-6">
                        {/* KPI Cards */}
                        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                            {[
                                { label: 'Total', value: counts.total, icon: <Users size={18} />, color: 'text-blue-400', s: 'all' },
                                { label: 'Pending', value: counts.pending, icon: <Clock size={18} />, color: 'text-yellow-400', s: 'pending' },
                                { label: 'Approved', value: counts.approved, icon: <CheckCircle size={18} />, color: 'text-green-400', s: 'approved' },
                                { label: 'Rejected', value: counts.rejected, icon: <XCircle size={18} />, color: 'text-red-400', s: 'rejected' },
                                { label: 'Suspended', value: counts.suspended, icon: <Lock size={18} />, color: 'text-orange-400', s: 'suspended' },
                            ].map(c => (
                                <button key={c.label} onClick={() => { setActiveTab('users'); setFilterStatus(c.s); }}
                                    className="glass-panel p-5 text-left hover:bg-slate-700 transition-all rounded-xl border border-slate-700">
                                    <div className={`${c.color} mb-2`}>{c.icon}</div>
                                    <div className="text-2xl font-bold">{c.value}</div>
                                    <div className="text-xs text-slate-400 mt-1">{c.label}</div>
                                </button>
                            ))}
                        </div>

                        {/* Pending Approvals Queue */}
                        <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
                            <h2 className="text-base font-semibold text-slate-100 mb-4 flex items-center gap-2">
                                <Clock size={16} className="text-yellow-400" /> Pending Approvals
                                {pendingUsers.length > 0 && <span className="bg-yellow-500 text-black text-xs font-bold px-2 py-0.5 rounded-full">{pendingUsers.length}</span>}
                            </h2>
                            {pendingUsers.length === 0 ? (
                                <p className="text-slate-500 text-sm text-center py-6">🎉 No pending approvals</p>
                            ) : (
                                <div className="space-y-3">
                                    {pendingUsers.map(u => (
                                        <div key={u.id} className="flex items-center justify-between bg-slate-800 border border-yellow-500/20 rounded-lg p-4">
                                            <div className="flex items-center gap-3">
                                                <div className="w-9 h-9 rounded-full bg-blue-500/20 border border-blue-500/30 flex items-center justify-center text-blue-400 font-bold text-sm">
                                                    {(u.full_name || u.username).charAt(0).toUpperCase()}
                                                </div>
                                                <div>
                                                    <div className="font-medium text-slate-100 text-sm">{u.full_name || u.username}</div>
                                                    <div className="text-xs text-slate-400">{u.email} · {u.organization || '—'} · {u.role}</div>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-3">
                                                <span className={`text-xs ${slaColor(u.created_at)}`}>{sla(u.created_at)}</span>
                                                <button onClick={() => setApproveModal({ userId: u.id, username: u.username })}
                                                    className="px-3 py-1.5 text-xs bg-green-600/20 text-green-400 border border-green-500/30 hover:bg-green-600/40 rounded flex items-center gap-1 transition-colors">
                                                    <CheckCircle size={11} /> Approve
                                                </button>
                                                <button onClick={() => setRejectModal({ userId: u.id, username: u.username })}
                                                    className="px-3 py-1.5 text-xs bg-red-600/20 text-red-400 border border-red-500/30 hover:bg-red-600/40 rounded flex items-center gap-1 transition-colors">
                                                    <XCircle size={11} /> Reject
                                                </button>
                                                <button onClick={() => setDetailUser(u)} className="text-slate-500 hover:text-blue-400 transition-colors"><Eye size={15} /></button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>

                        {/* Recent Audit Log */}
                        <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
                            <h2 className="text-base font-semibold text-slate-100 mb-4 flex items-center gap-2">
                                <FileText size={16} className="text-blue-400" /> Recent Activity
                            </h2>
                            {auditLog.slice(0, 5).length === 0 ? <p className="text-slate-500 text-sm text-center py-6">No activity yet</p> : (
                                <div className="space-y-2">
                                    {auditLog.slice(0, 5).map(log => (
                                        <div key={log.id} className="flex items-center justify-between text-sm py-2 border-b border-slate-700">
                                            <div className="flex items-center gap-2">
                                                <span className="text-blue-400 font-medium">{log.admin_username}</span>
                                                <span className="text-slate-500">→</span>
                                                <span className="text-slate-300">{log.action}</span>
                                                {log.target_username && <span className="text-slate-400">on <span className="text-white">@{log.target_username}</span></span>}
                                            </div>
                                            <span className="text-slate-500 text-xs">{log.created_at?.split(' ')[0]}</span>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>
                )}

                {/* ════════ USERS TAB ════════ */}
                {activeTab === 'users' && (
                    <div className="space-y-4">
                        {/* Toolbar */}
                        <div className="flex flex-wrap gap-3 items-center justify-between">
                            <div className="flex flex-wrap gap-2 items-center">
                                {/* Search */}
                                <div className="relative">
                                    <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                                    <input value={search} onChange={e => setSearch(e.target.value)}
                                        placeholder="Search users..."
                                        className="bg-slate-800 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 w-52" />
                                </div>
                                {/* Status filter */}
                                <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
                                    className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-blue-500">
                                    {['all', 'pending', 'approved', 'rejected', 'suspended'].map(s => <option key={s} value={s}>{s === 'all' ? 'All Statuses' : s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
                                </select>
                                {/* Role filter */}
                                <select value={filterRole} onChange={e => setFilterRole(e.target.value)}
                                    className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-blue-500">
                                    <option value="all">All Roles</option>
                                    {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                                </select>
                                {/* Sort */}
                                <button onClick={() => setSortOrder(o => o === 'desc' ? 'asc' : 'desc')}
                                    className="flex items-center gap-1.5 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-300 hover:text-white transition-colors">
                                    {sortOrder === 'desc' ? <ChevronDown size={14} /> : <ChevronUp size={14} />} Date
                                </button>
                            </div>

                            {/* Bulk actions */}
                            {selectedIds.length > 0 && (
                                <div className="flex items-center gap-2 bg-slate-800 border border-blue-500/30 px-3 py-2 rounded-lg">
                                    <span className="text-xs text-blue-400 font-medium">{selectedIds.length} selected</span>
                                    <button onClick={() => setApproveModal({ isBulk: true })}
                                        className="px-2 py-1 text-xs bg-green-600/20 text-green-400 border border-green-500/30 hover:bg-green-600/40 rounded flex items-center gap-1 transition-colors"><CheckCircle size={10} /> Approve All</button>
                                    <button onClick={() => setRejectModal({ isBulk: true })}
                                        className="px-2 py-1 text-xs bg-red-600/20 text-red-400 border border-red-500/30 hover:bg-red-600/40 rounded flex items-center gap-1 transition-colors"><XCircle size={10} /> Reject All</button>
                                    <button onClick={() => setSelectedIds([])} className="text-slate-500 hover:text-white"><X size={14} /></button>
                                </div>
                            )}
                        </div>

                        {/* Table */}
                        <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
                            <div className="overflow-x-auto">
                                <table className="w-full text-left text-sm">
                                    <thead className="border-b border-slate-700">
                                        <tr className="text-xs text-slate-400 uppercase tracking-wide">
                                            <th className="p-3 w-10">
                                                <button onClick={toggleAll}>
                                                    {selectedIds.length === filteredUsers.length && filteredUsers.length > 0
                                                        ? <CheckSquare size={15} className="text-blue-400" />
                                                        : <Square size={15} className="text-slate-600" />}
                                                </button>
                                            </th>
                                            <th className="p-3">User</th>
                                            <th className="p-3">Contact</th>
                                            <th className="p-3">Organization</th>
                                            <th className="p-3">Role</th>
                                            <th className="p-3">Joined</th>
                                            <th className="p-3">Last Login</th>
                                            <th className="p-3">SLA</th>
                                            <th className="p-3">Status</th>
                                            <th className="p-3">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {loading ? (
                                            <tr><td colSpan={10} className="text-center py-12 text-slate-400">Loading...</td></tr>
                                        ) : filteredUsers.length === 0 ? (
                                            <tr><td colSpan={10} className="text-center py-12 text-slate-500">No users found.</td></tr>
                                        ) : filteredUsers.map(u => (
                                            <tr key={u.id} className="border-b border-slate-700 hover:bg-slate-800 transition-colors">
                                                <td className="p-3">
                                                    <button onClick={() => toggleSelect(u.id)}>
                                                        {selectedIds.includes(u.id)
                                                            ? <CheckSquare size={15} className="text-blue-400" />
                                                            : <Square size={15} className="text-slate-600" />}
                                                    </button>
                                                </td>
                                                <td className="p-3">
                                                    <div className="font-medium text-slate-100">{u.full_name || u.username}</div>
                                                    <div className="text-xs text-slate-500">@{u.username}</div>
                                                </td>
                                                <td className="p-3">
                                                    <div className="text-slate-300 text-xs">{u.email}</div>
                                                    <div className="text-slate-500 text-xs">{u.phone || '—'}</div>
                                                </td>
                                                <td className="p-3 text-slate-300 text-xs">{u.organization || '—'}</td>
                                                <td className="p-3">
                                                    <button onClick={() => { setRoleModal({ userId: u.id, username: u.username }); setNewRole(u.role); }}
                                                        className="bg-slate-700 hover:bg-slate-600 text-slate-300 px-2 py-0.5 rounded text-xs flex items-center gap-1 transition-colors">
                                                        {u.role || 'Analyst'} <ChevronDown size={10} />
                                                    </button>
                                                </td>
                                                <td className="p-3 text-xs text-slate-400">{u.created_at?.split(' ')[0] || '—'}</td>
                                                <td className="p-3 text-xs text-slate-400">{u.last_login ? u.last_login.split(' ')[0] : 'Never'}</td>
                                                <td className="p-3 text-xs">
                                                    {u.status === 'pending' ? <span className={slaColor(u.created_at)}>{sla(u.created_at)}</span> : <span className="text-slate-600">—</span>}
                                                </td>
                                                <td className="p-3"><StatusBadge s={u.status} /></td>
                                                <td className="p-3">
                                                    <div className="flex gap-1.5">
                                                        {u.status !== 'approved' &&
                                                            <button onClick={() => setApproveModal({ userId: u.id, username: u.username })}
                                                                className="p-1 rounded text-green-400 hover:bg-green-500/20 transition-colors" title="Approve"><CheckCircle size={14} /></button>}
                                                        {u.status !== 'rejected' &&
                                                            <button onClick={() => setRejectModal({ userId: u.id, username: u.username })}
                                                                className="p-1 rounded text-red-400 hover:bg-red-500/20 transition-colors" title="Reject"><XCircle size={14} /></button>}
                                                        {u.status !== 'suspended' && u.status === 'approved' &&
                                                            <button onClick={() => setConfirmModal({ title: 'Suspend', message: `Suspend @${u.username}?`, danger: true, onConfirm: () => doSuspend(u.id, u.username) })}
                                                                className="p-1 rounded text-orange-400 hover:bg-orange-500/20 transition-colors" title="Suspend"><Lock size={14} /></button>}
                                                        {u.status === 'suspended' &&
                                                            <button onClick={() => setConfirmModal({ title: 'Reactivate', message: `Reactivate @${u.username}?`, danger: false, onConfirm: () => doReactivate(u.id, u.username) })}
                                                                className="p-1 rounded text-blue-400 hover:bg-blue-500/20 transition-colors" title="Reactivate"><Unlock size={14} /></button>}
                                                        <button onClick={() => setDetailUser(u)}
                                                            className="p-1 rounded text-slate-400 hover:text-blue-400 hover:bg-blue-500/20 transition-colors" title="View Profile"><Eye size={14} /></button>
                                                    </div>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                            <div className="px-4 py-3 border-t border-slate-700 text-xs text-slate-500">
                                Showing {filteredUsers.length} of {users.length} users
                            </div>
                        </div>
                    </div>
                )}

                {/* ════════ AUDIT LOG TAB ════════ */}
                {activeTab === 'security' && (
                    <div className="space-y-6">

                        {/* ── User Activity Feed ── */}
                        <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
                            <div className="flex justify-between items-center p-4 border-b border-slate-700">
                                <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                                    <Activity size={16} className="text-green-400" /> User Activity Feed
                                </h2>
                                <button onClick={fetchUserActivity} className="flex items-center gap-2 px-3 py-1.5 text-xs bg-slate-700 border border-slate-600 text-slate-300 hover:text-white rounded-lg transition-colors">
                                    <RefreshCw size={11} /> Refresh
                                </button>
                            </div>
                            <div className="overflow-x-auto">
                                <table className="w-full text-sm text-left">
                                    <thead className="border-b border-slate-700">
                                        <tr className="text-xs text-slate-400 uppercase tracking-wide">
                                            <th className="p-3">User</th>
                                            <th className="p-3">Action</th>
                                            <th className="p-3">Page</th>
                                            <th className="p-3">Details</th>
                                            <th className="p-3">Timestamp</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {userActivity.length === 0 ? (
                                            <tr><td colSpan={5} className="text-center py-8 text-slate-500">No user activity yet. Activity will appear as users navigate the app.</td></tr>
                                        ) : userActivity.map(a => (
                                            <tr key={a.id} className="border-b border-slate-700/20 hover:bg-slate-800 transition-colors">
                                                <td className="p-3 text-blue-400 font-medium">{a.username}</td>
                                                <td className="p-3">
                                                    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${a.action === 'PAGE_VIEW' ? 'bg-blue-500/15 text-blue-400' :
                                                            a.action === 'EXPORT' ? 'bg-purple-500/15 text-purple-400' :
                                                                a.action === 'SEARCH' ? 'bg-cyan-500/15 text-cyan-400' :
                                                                    a.action === 'FILE_IMPORT' ? 'bg-green-500/15 text-green-400' :
                                                                        a.action === 'FILTER_CHANGED' ? 'bg-yellow-500/15 text-yellow-400' :
                                                                            a.action === 'VIEW_SOLUTION' ? 'bg-orange-500/15 text-orange-400' :
                                                                                a.action === 'APPLY_FIX' ? 'bg-red-500/15 text-red-400' :
                                                                                    'bg-slate-700 text-slate-300'
                                                        }`}>{a.action}</span>
                                                </td>
                                                <td className="p-3 text-slate-300">{a.page || '—'}</td>
                                                <td className="p-3 text-slate-400 text-xs max-w-xs truncate">{a.details || '—'}</td>
                                                <td className="p-3 text-xs text-slate-500">{a.created_at}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        {/* ── Admin Audit Log ── */}
                        <div>
                            <div className="flex justify-between items-center mb-3">
                                <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2"><Shield size={16} className="text-blue-400" /> Admin Action Log</h2>
                                <button onClick={exportAuditCSV} className="flex items-center gap-2 px-4 py-2 text-sm bg-slate-800 border border-slate-700 text-slate-300 hover:text-white rounded-lg transition-colors">
                                    <Download size={14} /> Export CSV
                                </button>
                            </div>
                            <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
                                <table className="w-full text-sm text-left">
                                    <thead className="border-b border-slate-700">
                                        <tr className="text-xs text-slate-400 uppercase tracking-wide">
                                            <th className="p-3">#</th>
                                            <th className="p-3">Admin</th>
                                            <th className="p-3">Action</th>
                                            <th className="p-3">Target User</th>
                                            <th className="p-3">Notes / Reason</th>
                                            <th className="p-3">Timestamp</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {auditLog.length === 0 ? (
                                            <tr><td colSpan={6} className="text-center py-12 text-slate-500">No admin audit records yet.</td></tr>
                                        ) : auditLog.map(log => (
                                            <tr key={log.id} className="border-b border-slate-700/20 hover:bg-slate-800 transition-colors">
                                                <td className="p-3 text-slate-500 text-xs">{log.id}</td>
                                                <td className="p-3 text-blue-400 font-medium">{log.admin_username}</td>
                                                <td className="p-3">
                                                    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${log.action.includes('APPROVED') ? 'bg-green-500/15 text-green-400' : log.action.includes('REJECTED') ? 'bg-red-500/15 text-red-400' : log.action.includes('SUSPEND') ? 'bg-orange-500/15 text-orange-400' : 'bg-slate-700 text-slate-300'}`}>
                                                        {log.action}
                                                    </span>
                                                </td>
                                                <td className="p-3 text-slate-300">{log.target_username ? `@${log.target_username}` : '—'}</td>
                                                <td className="p-3 text-slate-400 text-xs max-w-xs truncate">{log.notes || '—'}</td>
                                                <td className="p-3 text-xs text-slate-500">{log.created_at}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                )}

                {/* ════════ ALERTS TAB ════════ */}
                {activeTab === 'alerts' && (
                    <div className="space-y-4">
                        <div className="flex justify-between items-center">
                            <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2"><Bell size={18} className="text-red-400" /> Alert Queue</h2>
                            <button onClick={fetchAlerts} className="flex items-center gap-2 px-3 py-2 text-sm bg-slate-800 border border-slate-700 text-slate-300 hover:text-white rounded-lg transition-colors">
                                <RefreshCw size={13} /> Refresh
                            </button>
                        </div>
                        {alerts.length === 0 ? (
                            <div className="bg-slate-800 border border-slate-700 rounded-xl p-12 text-center">
                                <CheckCircle size={40} className="text-green-400 mx-auto mb-3" />
                                <p className="text-slate-400">No active alerts. System looks healthy.</p>
                            </div>
                        ) : (
                            <div className="space-y-3">
                                {alerts.map((alert, i) => (
                                    <div key={i} className={`flex items-start justify-between bg-slate-800 border rounded-xl p-4 transition-all ${alert.severity === 'critical' || alert.severity === 'high' ? 'border-red-500/30' :
                                        alert.severity === 'medium' ? 'border-yellow-500/30' : 'border-slate-700'}`}>
                                        <div className="flex items-start gap-3">
                                            <AlertTriangle size={18} className={
                                                alert.severity === 'critical' || alert.severity === 'high' ? 'text-red-400 mt-0.5' :
                                                    alert.severity === 'medium' ? 'text-yellow-400 mt-0.5' : 'text-slate-400 mt-0.5'} />
                                            <div>
                                                <div className="font-medium text-slate-100 text-sm">{alert.type || alert.message || 'Alert'}</div>
                                                <div className="text-xs text-slate-400 mt-0.5">{alert.src_ip && `Source: ${alert.src_ip}`} {alert.timestamp || ''}</div>
                                                {alert.details && <div className="text-xs text-slate-500 mt-1">{alert.details}</div>}
                                            </div>
                                        </div>
                                        <span className={`px-2 py-0.5 rounded text-xs font-semibold flex-shrink-0 ${alert.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                                            alert.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                                                alert.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                                                    'bg-slate-700 text-slate-300'}`}>
                                            {alert.severity || 'info'}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                )}

                {/* ════════ SETTINGS TAB ════════ */}
                {activeTab === 'settings' && (
                    <div className="space-y-6 max-w-2xl">
                        <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2"><Settings size={18} className="text-slate-400" /> Settings Panel</h2>

                        {/* Detection Thresholds */}
                        <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 space-y-5">
                            <h3 className="font-semibold text-slate-200 flex items-center gap-2"><Zap size={16} className="text-yellow-400" /> Detection Thresholds</h3>
                            <div>
                                <label className="text-sm text-slate-300 flex justify-between mb-2">
                                    Rate Limit Threshold (packets/min)
                                    <span className="text-blue-400 font-mono">{settings.rateLimitThreshold}</span>
                                </label>
                                <input type="range" min={100} max={5000} value={settings.rateLimitThreshold}
                                    onChange={e => setSettings(s => ({ ...s, rateLimitThreshold: +e.target.value }))}
                                    className="w-full accent-blue-500" />
                            </div>
                            <div>
                                <label className="text-sm text-slate-300 flex justify-between mb-2">
                                    Anomaly Sensitivity (%)
                                    <span className="text-blue-400 font-mono">{settings.anomalySensitivity}%</span>
                                </label>
                                <input type="range" min={10} max={100} value={settings.anomalySensitivity}
                                    onChange={e => setSettings(s => ({ ...s, anomalySensitivity: +e.target.value }))}
                                    className="w-full accent-blue-500" />
                            </div>
                            <div>
                                <label className="text-sm text-slate-300 flex justify-between mb-2">
                                    Data Retention (days)
                                    <span className="text-blue-400 font-mono">{settings.dataRetentionDays}d</span>
                                </label>
                                <input type="range" min={7} max={365} value={settings.dataRetentionDays}
                                    onChange={e => setSettings(s => ({ ...s, dataRetentionDays: +e.target.value }))}
                                    className="w-full accent-blue-500" />
                            </div>
                        </div>

                        {/* Notifications */}
                        <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 space-y-4">
                            <h3 className="font-semibold text-slate-200 flex items-center gap-2"><Bell size={16} className="text-blue-400" /> Notifications</h3>
                            <div className="flex items-center justify-between">
                                <span className="text-sm text-slate-300">Email Notifications</span>
                                <button onClick={() => setSettings(s => ({ ...s, emailNotifications: !s.emailNotifications }))}
                                    className={`transition-colors ${settings.emailNotifications ? 'text-green-400' : 'text-slate-600'}`}>
                                    {settings.emailNotifications ? <ToggleRight size={28} /> : <ToggleLeft size={28} />}
                                </button>
                            </div>
                            <div>
                                <label className="text-sm text-slate-300 mb-2 block">Webhook URL</label>
                                <input value={settings.webhookUrl} onChange={e => setSettings(s => ({ ...s, webhookUrl: e.target.value }))}
                                    placeholder="https://hooks.example.com/..."
                                    className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500" />
                            </div>
                        </div>

                        {/* Maintenance */}
                        <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
                            <h3 className="font-semibold text-slate-200 mb-4 flex items-center gap-2"><AlertTriangle size={16} className="text-orange-400" /> System</h3>
                            <div className="flex items-center justify-between">
                                <div>
                                    <div className="text-sm text-slate-300">Maintenance Mode</div>
                                    <div className="text-xs text-slate-500">Blocks all non-admin logins</div>
                                </div>
                                <button onClick={() => setSettings(s => ({ ...s, maintenanceMode: !s.maintenanceMode }))}
                                    className={`transition-colors ${settings.maintenanceMode ? 'text-orange-400' : 'text-slate-600'}`}>
                                    {settings.maintenanceMode ? <ToggleRight size={28} /> : <ToggleLeft size={28} />}
                                </button>
                            </div>
                        </div>

                        <button onClick={() => showToast('Settings saved successfully', 'success')}
                            className="flex items-center gap-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors">
                            <Save size={15} /> Save Settings
                        </button>
                    </div>
                )}

            </main>
        </div>
    );
};

export default AdminPanel;
