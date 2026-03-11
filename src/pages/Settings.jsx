import React, { useState } from 'react';
import { Save } from 'lucide-react';

const Settings = () => {
    const [refreshRate, setRefreshRate] = useState(localStorage.getItem('refreshRate') || '5000');
    const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');
    const [saved, setSaved] = useState(false);

    const handleSave = () => {
        localStorage.setItem('refreshRate', refreshRate);
        localStorage.setItem('theme', theme);

        // Apply Theme Globally
        if (theme === 'light') {
            document.body.classList.add('theme-cyber');
            document.body.classList.add('light');
        } else {
            document.body.classList.add('theme-cyber');
            document.body.classList.remove('light');
        }

        setSaved(true);
        setTimeout(() => setSaved(false), 3000);
    };

    return (
        <div className="space-y-6 animate-fade-in">
            <h2 className="text-2xl font-bold text-slate-100">Settings</h2>

            <div className="glass-panel p-6 max-w-2xl relative">
                <h3 className="text-lg font-semibold mb-4 text-slate-200">System Preferences</h3>

                <div className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium text-slate-400 mb-1">Dashboard Refresh Rate</label>
                        <select
                            value={refreshRate}
                            onChange={(e) => setRefreshRate(e.target.value)}
                            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 w-full focus:outline-none focus:border-blue-500"
                        >
                            <option value="2000">2 seconds (Fast)</option>
                            <option value="5000">5 seconds (Standard)</option>
                            <option value="10000">10 seconds</option>
                            <option value="30000">30 seconds</option>
                            <option value="60000">1 minute</option>
                        </select>
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-slate-400 mb-1">Theme (UI Mode)</label>
                        <div className="flex space-x-4">
                            <label className="flex items-center space-x-2 cursor-pointer">
                                <input
                                    type="radio"
                                    name="theme"
                                    value="dark"
                                    checked={theme === 'dark'}
                                    onChange={(e) => setTheme(e.target.value)}
                                    className="form-radio text-blue-500"
                                />
                                <span className="text-slate-300">Dark Mode</span>
                            </label>
                            <label className="flex items-center space-x-2 cursor-pointer">
                                <input
                                    type="radio"
                                    name="theme"
                                    value="light"
                                    checked={theme === 'light'}
                                    onChange={(e) => setTheme(e.target.value)}
                                    className="form-radio text-blue-500"
                                />
                                <span className="text-slate-300">Light Mode</span>
                            </label>
                        </div>
                    </div>

                    <div className="pt-4 flex items-center space-x-4">
                        <button
                            onClick={handleSave}
                            className="flex items-center space-x-2 bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg transition-colors shadow-lg hover:shadow-blue-500/20"
                        >
                            <Save size={18} />
                            <span>Save Changes</span>
                        </button>

                        {saved && (
                            <span className="text-green-400 text-sm font-medium animate-pulse flex items-center">
                                - Settings Saved Successfully
                            </span>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Settings;
