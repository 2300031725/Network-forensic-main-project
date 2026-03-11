import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Lock, User, ArrowRight, Shield, Users } from 'lucide-react';

const Login = () => {
    const [tab, setTab] = useState('user'); // 'user' | 'admin'
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const handleLogin = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            const response = await fetch('http://127.0.0.1:8000/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password }),
            });

            const data = await response.json();

            if (response.ok) {
                const user = data.user;

                if (tab === 'admin') {
                    // Admin login: must have Admin role
                    if (user.role !== 'Admin') {
                        setError('Access denied. This account does not have Admin privileges.');
                        setLoading(false);
                        return;
                    }
                    localStorage.setItem('user', JSON.stringify(user));
                    navigate('/admin');
                } else {
                    // Regular user login
                    localStorage.setItem('user', JSON.stringify(user));
                    navigate('/');
                }
            } else {
                setError(data.detail || 'Login failed. Please check your credentials.');
            }
        } catch (err) {
            setError('Connection error. Please ensure the server is running.');
        }
        setLoading(false);
    };

    const isAdmin = tab === 'admin';

    return (
        <div className="flex min-h-screen items-center justify-center bg-transparent px-4 py-12 text-slate-100">
            <div className="w-full max-w-md space-y-6 rounded-2xl bg-slate-900 p-10 shadow-[0_24px_60px_-40px_rgba(0,0,0,0.9)] border border-slate-800">

                {/* Logo */}
                <div className="text-center">
                    <div className={`mx-auto flex h-14 w-14 items-center justify-center rounded-full transition-colors duration-300 ${isAdmin ? 'bg-red-600/20 border border-red-500/50' : 'bg-emerald-500/15 border border-emerald-500/40'}`}>
                        {isAdmin
                            ? <Shield className="h-7 w-7 text-red-400" />
                            : <Lock className="h-7 w-7 text-emerald-300" />
                        }
                    </div>
                    <h2 className="mt-4 text-3xl font-extrabold tracking-tight">
                        {isAdmin ? 'Admin Login' : 'Sign in'}
                    </h2>
                    <p className="mt-1 text-sm text-slate-400">
                        {isAdmin
                            ? 'Administrator access only'
                            : <>Don't have an account?{' '}
                                <Link to="/register" className="font-medium text-emerald-300 hover:text-emerald-200">Register</Link>
                            </>
                        }
                    </p>
                </div>

                {/* Tabs */}
                <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-800">
                    <button
                        type="button"
                        onClick={() => { setTab('user'); setError(''); }}
                        className={`flex flex-1 items-center justify-center gap-2 py-2 rounded-md text-sm font-medium transition-all ${!isAdmin
                                ? 'bg-emerald-500 text-slate-950 shadow'
                                : 'text-slate-400 hover:text-slate-200'
                            }`}
                    >
                        <Users size={15} /> User Login
                    </button>
                    <button
                        type="button"
                        onClick={() => { setTab('admin'); setError(''); }}
                        className={`flex flex-1 items-center justify-center gap-2 py-2 rounded-md text-sm font-medium transition-all ${isAdmin
                                ? 'bg-red-600 text-white shadow'
                                : 'text-slate-400 hover:text-slate-200'
                            }`}
                    >
                        <Shield size={15} /> Admin Login
                    </button>
                </div>

                {/* Error */}
                {error && (
                    <div className="bg-red-900/50 border border-red-500/60 text-red-200 px-4 py-3 rounded-lg text-sm">
                        {error}
                    </div>
                )}

                {/* Form */}
                <form className="space-y-4" onSubmit={handleLogin}>
                    <div className="relative">
                        <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
                            <User className="h-5 w-5 text-slate-400" />
                        </div>
                        <input
                            id="username"
                            type="text"
                            required
                        className={`block w-full rounded-md border bg-slate-700 px-3 py-2.5 pl-10 text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-1 sm:text-sm transition-colors ${isAdmin
                                    ? 'border-red-500/40 focus:border-red-500 focus:ring-red-500'
                                    : 'border-slate-600 focus:border-emerald-400 focus:ring-emerald-400'
                                }`}
                            placeholder={isAdmin ? 'Admin Username' : 'Username or Email'}
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                        />
                    </div>

                    <div className="relative">
                        <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
                            <Lock className="h-5 w-5 text-slate-400" />
                        </div>
                        <input
                            id="password"
                            type="password"
                            required
                        className={`block w-full rounded-md border bg-slate-700 px-3 py-2.5 pl-10 text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-1 sm:text-sm transition-colors ${isAdmin
                                    ? 'border-red-500/40 focus:border-red-500 focus:ring-red-500'
                                    : 'border-slate-600 focus:border-emerald-400 focus:ring-emerald-400'
                                }`}
                            placeholder="Password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                        />
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className={`group relative flex w-full justify-center items-center gap-2 rounded-md px-4 py-2.5 text-sm font-semibold text-white transition-all ${isAdmin
                                ? 'bg-red-600 hover:bg-red-500 shadow-lg shadow-red-500/20'
                                : 'bg-emerald-500 hover:bg-emerald-400 shadow-lg shadow-emerald-500/20 text-slate-950'
                            } disabled:opacity-60`}
                    >
                        {loading ? (
                            <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                        ) : (
                            <>
                                <ArrowRight size={16} />
                                {isAdmin ? 'Access Admin Dashboard' : 'Sign In'}
                            </>
                        )}
                    </button>
                </form>

                {/* Admin hint */}
                {isAdmin && (
                    <p className="text-center text-xs text-slate-500 border-t border-slate-800 pt-4">
                        - Admin access is restricted. Unauthorized attempts are logged.
                    </p>
                )}
            </div>
        </div>
    );
};

export default Login;
