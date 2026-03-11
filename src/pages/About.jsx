import React from 'react';

const About = () => {
    return (
        <div className="max-w-2xl mx-auto text-center space-y-6 pt-12">
            <div className="inline-block p-4 rounded-full bg-blue-500/10 mb-4">
                <div className="h-16 w-16 rounded-full bg-gradient-to-tr from-blue-500 to-green-500 animate-pulse"></div>
            </div>

            <h1 className="text-4xl font-bold text-white">Visual Security Analytics</h1>
            <p className="text-xl text-slate-400">Advanced Network Forensics Dashboard</p>

            <div className="glass-panel p-8 text-left space-y-4 mt-8">
                <p className="text-slate-300">
                    This application provides real-time visualization and analysis of network security data.
                    Designed for security operations centers (SOCs) and forensic analysts to detect, investigate,
                    and respond to active threats.
                </p>
                <div className="pt-4 border-t border-slate-700 flex justify-between text-sm text-slate-500">
                    <span>Version 1.0.0</span>
                    <span>© 2026 Security Corp</span>
                </div>
            </div>
        </div>
    );
};

export default About;
