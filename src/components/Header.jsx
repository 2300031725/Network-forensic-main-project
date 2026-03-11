import React from "react";
import ReactDOM from "react-dom";
import { Bell, Menu, X, ArrowLeft } from "lucide-react";

const Header = () => {
  const [systemHealth, setSystemHealth] = React.useState(98);
  const [dataMode, setDataMode] = React.useState("Initializing...");
  const [notifications, setNotifications] = React.useState([]);
  const [lastReadCount, setLastReadCount] = React.useState(0);
  const [showNotifications, setShowNotifications] = React.useState(false);
  const [viewMode, setViewMode] = React.useState("all");
  const [snapshotUnread, setSnapshotUnread] = React.useState(0);
  const hasInitialized = React.useRef(false);
  const dropdownRef = React.useRef(null);
  const clearedSetRef = React.useRef(new Set());

  const unreadCount = Math.max(0, notifications.length - lastReadCount);

  const makeAlertKey = (alert) =>
    `${alert.Timestamp || ""}|${alert.Type || ""}|${alert.Source || ""}|${alert.Destination || ""}`;

  const loadClearedSet = () => {
    try {
      const raw = localStorage.getItem("cleared_notifications") || "[]";
      const arr = JSON.parse(raw);
      clearedSetRef.current = new Set(arr);
    } catch {
      clearedSetRef.current = new Set();
    }
  };

  const persistClearedSet = () => {
    try {
      localStorage.setItem(
        "cleared_notifications",
        JSON.stringify(Array.from(clearedSetRef.current))
      );
    } catch {}
  };

  const handleClearAll = () => {
    loadClearedSet();
    notifications.forEach((a) => clearedSetRef.current.add(makeAlertKey(a)));
    // Keep the set from growing without bound.
    if (clearedSetRef.current.size > 5000) {
      clearedSetRef.current = new Set();
    }
    persistClearedSet();
    setNotifications([]);
    setLastReadCount(0);
  };

  // Fetch backend stats
  React.useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await fetch("http://localhost:8000/stats");
        const data = await res.json();

        if (data.monitoring_mode) setDataMode(data.monitoring_mode);
        if (data.alerts) {
          loadClearedSet();
          const filtered = data.alerts.filter(
            (a) => !clearedSetRef.current.has(makeAlertKey(a))
          );
          setNotifications(filtered);
          if (!hasInitialized.current) {
            setLastReadCount(filtered.length);
            hasInitialized.current = true;
          }
        }
        if (data.system_health) setSystemHealth(data.system_health);
      } catch (e) {
        setDataMode("Backend Offline");
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  // Close when clicking outside
  React.useEffect(() => {
    const handleClickOutside = (event) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target)
      ) {
        setShowNotifications(false);
      }
    };

    if (showNotifications) {
      document.addEventListener("mousedown", handleClickOutside);
    }

    return () =>
      document.removeEventListener("mousedown", handleClickOutside);
  }, [showNotifications]);

  return (
    <>
      <header className="h-16 bg-slate-900 border-b border-slate-800 flex items-center justify-between px-6 z-20">
        <div className="flex items-center space-x-4">
          <button className="text-slate-400 hover:text-white md:hidden">
            <Menu size={24} />
          </button>
        </div>

        <div className="flex items-center space-x-4">
          {localStorage.getItem("user") && (
            <button
              onClick={() => {
                localStorage.removeItem("user");
                window.location.href = "/login";
              }}
              className="text-sm font-medium text-slate-200 hover:text-white bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-lg transition-colors"
            >
              Sign Out
            </button>
          )}
          <div className="hidden lg:block text-xs mono px-2 py-1 rounded-md border border-slate-800 bg-slate-800 text-slate-400 hud-no-corner">
            DATA SOURCE:{" "}
            <span
              className={
                dataMode.includes("Simulated")
                  ? "text-amber-400"
                  : "text-emerald-300"
              }
            >
              {dataMode}
            </span>
          </div>

          {/* 🔔 Notification Bell */}
          <button
            onClick={() => {
              if (!showNotifications) {
                setSnapshotUnread(unreadCount);
                setLastReadCount(notifications.length);
                setViewMode("all");
              }
              setShowNotifications(!showNotifications);
            }}
            className="relative p-1 rounded-full hover:bg-slate-800 transition-colors"
          >
            <Bell
              className="text-slate-400 hover:text-white transition-colors"
              size={20}
            />
            {unreadCount > 0 && (
              <>
                <span className="absolute top-0 right-0 w-2.5 h-2.5 bg-red-500 rounded-full animate-ping"></span>
                <span className="absolute top-0 right-0 w-2.5 h-2.5 bg-red-500 rounded-full border-2 border-slate-900"></span>
              </>
            )}
          </button>

          <span
            className={`text-xs mono px-2 py-1 rounded-md border ${
              parseInt(systemHealth) < 50
                ? "text-red-300 bg-red-950/40 border-red-900/40"
                : "text-emerald-300 bg-emerald-950/40 border-emerald-900/40"
            }`}
          >
            SYSTEM HEALTH: {systemHealth}%
          </span>
        </div>
      </header>

      {/* 🚀 PORTAL DROPDOWN */}
      {showNotifications && (
  <div
    ref={dropdownRef}
    className="fixed inset-0 z-[99999] flex justify-end"
  >
    {/* Background overlay */}
    <div
      className="absolute inset-0 bg-black/30"
      onClick={() => setShowNotifications(false)}
    ></div>

    {/* Notification Box */}
    <div className="relative mt-20 mr-6 w-[520px] max-w-[92vw] bg-slate-900 border border-slate-800 rounded-xl shadow-2xl max-h-[80vh] overflow-hidden flex flex-col">
      
      <div className="p-3 border-b border-slate-800 flex justify-between items-center">
        <h3 className="font-semibold text-slate-200 text-sm">
          Notifications
        </h3>

        <button
          onClick={() => setShowNotifications(false)}
          className="text-slate-400 hover:text-white p-1"
        >
          <X size={14} />
        </button>
      </div>

      <div className="max-h-[70vh] overflow-y-auto custom-scrollbar">
        {notifications.length > 0 ? (
          notifications.slice(0, 50).map((alert, idx) => (
            <div
              key={idx}
              className="p-3 border-b border-slate-800 hover:bg-slate-800 transition-colors"
            >
              <div className="flex justify-between mb-1">
                <span className="text-xs font-bold px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  {alert.Severity}
                </span>
                <span className="text-[10px] text-slate-500">
                  {alert.Timestamp}
                </span>
              </div>

              <p className="text-sm text-slate-300 font-medium">
                {alert.Type}
              </p>

              <div className="text-xs text-slate-500 mt-1 break-all">
                Src: {alert.Source} → Dst: {alert.Destination || "Target"}
              </div>
            </div>
          ))
        ) : (
          <div className="p-8 text-center text-slate-500">
            No alerts found
          </div>
        )}
      </div>

      {notifications.length > 0 && (
        <div className="px-3 py-2 bg-slate-900 border-t border-slate-800 flex justify-between items-center hud-no-corner">
          <button
            onClick={handleClearAll}
            className="text-xs text-red-400 hover:text-red-300 font-medium hover:underline transition-colors leading-none"
          >
            Clear All
          </button>
          <a
            href="/forensics"
            className="text-xs text-emerald-300 hover:text-emerald-200 font-medium hover:underline leading-none"
          >
            View All
          </a>
        </div>
      )}
    </div>
  </div>
)}
    </>
  );
};

export default Header;
