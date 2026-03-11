import React from 'react';
import { LayoutDashboard, Activity, Zap, Search, FileText, Info, Settings, ShieldCheck } from 'lucide-react';
import { NavLink } from 'react-router-dom';

const Sidebar = () => {
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    const username = user.username || 'Guest';
    const initial = username.charAt(0).toUpperCase();
    const isAdmin = user.role === 'Admin';

    return (
        <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col">
            <div className="h-16 flex items-center justify-center border-b border-slate-800">
                <h1 className="text-xl font-semibold tracking-wide text-slate-100">
                    SecAnalytics
                </h1>
            </div>

            <nav className="flex-1 py-6 px-3 space-y-2">
                <SidebarItem to="/" icon={<LayoutDashboard size={20} />} text="Dashboard Overview" />
                <SidebarItem to="/traffic" icon={<Activity size={20} />} text="Traffic Analytics" />
                <SidebarItem to="/anomaly" icon={<Zap size={20} />} text="Anomaly Detection" />
                <SidebarItem to="/forensics" icon={<Search size={20} />} text="Forensic Investigation" />
                <SidebarItem to="/reports" icon={<FileText size={20} />} text="Reports" />
                <SidebarItem to="/about" icon={<Info size={20} />} text="About" />
                <SidebarItem to="/settings" icon={<Settings size={20} />} text="Settings" />

                {/* Admin Section - visible only to Admin role */}
                {isAdmin && (
                    <div className="pt-2 mt-2 border-t border-slate-800">
                        <p className="px-4 text-[11px] font-semibold uppercase tracking-widest text-slate-500 mb-2">Administration</p>
                        <SidebarItem to="/admin" icon={<ShieldCheck size={20} />} text="Admin Panel" />
                    </div>
                )}
            </nav>

            <div className="p-4 border-t border-slate-800">
                <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 rounded-full bg-emerald-500/15 flex items-center justify-center">
                        <span className="text-sm font-semibold text-emerald-300">{initial}</span>
                    </div>
                    <div>
                        <p className="text-sm font-medium text-slate-100">{username}</p>
                        <p className="text-xs text-slate-500">Online</p>
                    </div>
                </div>
            </div>
        </aside>
    );
};

const SidebarItem = ({ icon, text, to }) => {
    return (
        <NavLink
            to={to}
            className={({ isActive }) => `flex items-center space-x-3 px-4 py-3 rounded-xl cursor-pointer transition-colors ${isActive
                ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/20'
                : 'text-slate-400 hover:bg-slate-800 hover:text-slate-100'
                }`}
        >
            {icon}
            <span className="text-sm font-medium">{text}</span>
        </NavLink>
    );
};

export default Sidebar;
