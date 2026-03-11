import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Lock, User, Mail, Phone, Building2, Briefcase, ArrowRight, UserPlus, CheckCircle } from 'lucide-react';

const ROLES = ['Analyst', 'Security Engineer', 'Network Admin', 'SOC Manager', 'Auditor', 'Other'];

const Register = () => {
    const [form, setForm] = useState({
        username: '',
        email: '',
        password: '',
        confirmPassword: '',
        full_name: '',
        phone: '',
        organization: '',
        role: 'Analyst',
    });
    const [error, setError] = useState('');
    const [success, setSuccess] = useState(false);
    const navigate = useNavigate();

    const set = (field) => (e) => setForm({ ...form, [field]: e.target.value });

    const handleRegister = async (e) => {
        e.preventDefault();
        setError('');

        if (form.password !== form.confirmPassword) {
            setError("Passwords don't match");
            return;
        }

        try {
            const response = await fetch('http://127.0.0.1:8000/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: form.username,
                    email: form.email,
                    password: form.password,
                    full_name: form.full_name,
                    phone: form.phone,
                    organization: form.organization,
                    role: form.role,
                }),
            });

            const data = await response.json();
            if (response.ok) {
                setSuccess(true);
            } else {
                setError(data.detail || 'Registration failed');
            }
        } catch (err) {
            setError('Connection error. Please try again.');
        }
    };

    if (success) {
        return (
            <div className="flex min-h-screen items-center justify-center bg-transparent px-4">
                <div className="text-center space-y-4 max-w-md w-full bg-slate-900 p-10 rounded-2xl border border-slate-800 shadow-[0_24px_60px_-40px_rgba(0,0,0,0.9)]">
                    <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-emerald-500/15 border border-emerald-500/40">
                        <CheckCircle className="h-8 w-8 text-emerald-300" />
                    </div>
                    <h2 className="text-2xl font-bold text-slate-100">Registration Successful!</h2>
                    <p className="text-slate-400">
                        Your account is <span className="text-amber-300 font-semibold">pending admin approval</span>.
                        You will be able to log in once an administrator reviews and approves your account.
                    </p>
                    <button
                        onClick={() => navigate('/login')}
                        className="mt-4 w-full bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-medium py-2 px-4 rounded-md transition-colors"
                    >
                        Go to Login
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="flex min-h-screen items-center justify-center bg-transparent px-4 py-12 text-slate-100">
            <div className="w-full max-w-lg space-y-6 rounded-2xl bg-slate-900 p-10 shadow-[0_24px_60px_-40px_rgba(0,0,0,0.9)] border border-slate-800">
                <div className="text-center">
                    <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-emerald-500">
                        <UserPlus className="h-6 w-6 text-slate-950" />
                    </div>
                    <h2 className="mt-4 text-3xl font-extrabold tracking-tight">Create your account</h2>
                    <p className="mt-2 text-sm text-slate-400">
                        Already have an account?{' '}
                        <Link to="/login" className="font-medium text-emerald-300 hover:text-emerald-200">Sign in</Link>
                    </p>
                </div>

                {error && (
                    <div className="bg-red-950/40 border border-red-500 text-red-200 px-4 py-3 rounded">
                        {error}
                    </div>
                )}

                <form className="space-y-4" onSubmit={handleRegister}>
                    {/* Personal Details Section */}
                    <p className="text-xs font-semibold uppercase tracking-widest text-slate-500">Personal Information</p>

                    <InputField icon={<User />} id="full_name" placeholder="Full Name" value={form.full_name} onChange={set('full_name')} required />
                    <InputField icon={<User />} id="username" placeholder="Username" value={form.username} onChange={set('username')} required />
                    <InputField icon={<Mail />} id="email" type="email" placeholder="Email Address" value={form.email} onChange={set('email')} required />
                    <InputField icon={<Phone />} id="phone" type="tel" placeholder="Phone Number" value={form.phone} onChange={set('phone')} />

                    {/* Organization Details Section */}
                    <p className="text-xs font-semibold uppercase tracking-widest text-slate-500 pt-2">Organization Details</p>
                    <InputField icon={<Building2 />} id="organization" placeholder="Organization / Company" value={form.organization} onChange={set('organization')} />

                    <div className="relative">
                        <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-400">
                            <Briefcase className="h-5 w-5" />
                        </div>
                        <select
                            id="role"
                            value={form.role}
                            onChange={set('role')}
                            className="block w-full appearance-none rounded-md border border-slate-600 bg-slate-700 px-3 py-2 pl-10 text-slate-100 focus:border-emerald-400 focus:outline-none sm:text-sm"
                        >
                            {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                        </select>
                    </div>

                    {/* Security Section */}
                    <p className="text-xs font-semibold uppercase tracking-widest text-slate-500 pt-2">Security</p>
                    <InputField icon={<Lock />} id="password" type="password" placeholder="Password" value={form.password} onChange={set('password')} required />
                    <InputField icon={<Lock />} id="confirmPassword" type="password" placeholder="Confirm Password" value={form.confirmPassword} onChange={set('confirmPassword')} required />

                    <button
                        type="submit"
                        className="group relative flex w-full justify-center rounded-md bg-emerald-500 px-4 py-2.5 text-sm font-medium text-slate-950 hover:bg-emerald-400 focus:outline-none transition-colors mt-2"
                    >
                        <span className="absolute inset-y-0 left-0 flex items-center pl-3">
                            <ArrowRight className="h-5 w-5 text-emerald-200 group-hover:text-emerald-100" />
                        </span>
                        Register &amp; Await Approval
                    </button>
                </form>
            </div>
        </div>
    );
};

const InputField = ({ icon, id, type = 'text', placeholder, value, onChange, required = false }) => (
    <div className="relative">
        <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-400">
            {React.cloneElement(icon, { className: 'h-5 w-5' })}
        </div>
        <input
            id={id}
            name={id}
            type={type}
            required={required}
            className="block w-full appearance-none rounded-md border border-slate-600 bg-slate-700 px-3 py-2 pl-10 text-slate-100 placeholder-slate-400 focus:border-emerald-400 focus:outline-none focus:ring-emerald-400 sm:text-sm"
            placeholder={placeholder}
            value={value}
            onChange={onChange}
        />
    </div>
);

export default Register;
