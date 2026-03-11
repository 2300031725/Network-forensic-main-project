import React, { useState } from 'react';
import { FileText, Download, ShieldCheck, AlertTriangle } from 'lucide-react';

const Reports = () => {
    const [downloading, setDownloading] = useState(false);

    const handleDownload = async () => {
        setDownloading(true);
        try {
            const res = await fetch('http://localhost:8000/report');
            const data = await res.json();

            const htmlEscape = (value) => {
                if (value === null || value === undefined) return "";
                let text = String(value);
                if (/^[=+\-@]/.test(text)) {
                    text = `'${text}`;
                }
                return text
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;")
                    .replace(/"/g, "&quot;")
                    .replace(/'/g, "&#39;");
            };
            const priorityClass = (priority) => {
                if (priority === "Critical" || priority === "P1") return "p1";
                if (priority === "High" || priority === "P2") return "p2";
                if (priority === "Medium" || priority === "P3") return "p3";
                return "p4";
            };

            const keyFindingsRows = (data.key_findings || []).map((finding) => `
                <tr>
                    <td>${htmlEscape(finding.label)}</td>
                    <td>${htmlEscape(finding.value)}</td>
                    <td class="${priorityClass(finding.priority)}">${htmlEscape(finding.priority)}</td>
                </tr>
            `).join("");

            const threatRows = (data.threats.distribution || []).map((t) => `
                <tr>
                    <td>${htmlEscape(t.name)}</td>
                    <td>${htmlEscape(t.count)}</td>
                </tr>
            `).join("");

            const evidenceRows = (data.evidence || []).map((l) => `
                <tr>
                    <td>${htmlEscape(l.timestamp)}</td>
                    <td>${htmlEscape(l.source_ip)}</td>
                    <td>${htmlEscape(l.destination_ip)}</td>
                    <td>${htmlEscape(l.protocol)}</td>
                    <td>${htmlEscape(l.attack_type)}</td>
                    <td>${htmlEscape(l.anomaly_score)}</td>
                    <td>${htmlEscape(l.severity)}</td>
                    <td>${htmlEscape(l.action_taken)}</td>
                </tr>
            `).join("");

            const recommendationRows = (data.recommendations || []).map((rec, i) => `
                <tr>
                    <td>${i + 1}</td>
                    <td>${htmlEscape(rec)}</td>
                </tr>
            `).join("");

            const htmlContent = `
                <html>
                <head>
                    <meta charset="utf-8" />
                    <style>
                        body { font-family: Calibri, Arial, sans-serif; font-size: 11pt; color: #111; }
                        .title { font-size: 16pt; font-weight: 700; color: #1f4e78; margin-bottom: 8px; }
                        .meta { margin-bottom: 2px; color: #444; }
                        .section { margin-top: 14px; }
                        .section-title { font-size: 12pt; font-weight: 700; color: #1f4e78; margin: 10px 0 6px 0; }
                        table { border-collapse: collapse; width: 100%; }
                        th, td { border: 1px solid #d9d9d9; padding: 6px 8px; text-align: left; white-space: nowrap; }
                        th { background: #1f4e78; color: #fff; font-weight: 700; }
                        .p1 { background: #f8d7da; color: #842029; font-weight: 700; }
                        .p2 { background: #fff3cd; color: #664d03; font-weight: 700; }
                        .p3 { background: #d1ecf1; color: #0c5460; font-weight: 700; }
                        .p4 { background: #e2e3e5; color: #41464b; font-weight: 700; }
                    </style>
                </head>
                <body>
                    <div class="title">${htmlEscape(data.header.title)}</div>
                    <div class="meta"><b>Report ID:</b> ${htmlEscape(data.header.report_id)}</div>
                    <div class="meta"><b>Generated On:</b> ${htmlEscape(data.header.generated_on)}</div>
                    <div class="meta"><b>Time Range:</b> ${htmlEscape(data.header.time_range)}</div>
                    <div class="meta"><b>System Health:</b> ${htmlEscape(data.header.system_health)}</div>

                    <div class="section">
                        <div class="section-title">KEY FINDINGS (PRIORITIZED)</div>
                        <table>
                            <thead><tr><th>Attribute</th><th>Value</th><th>Priority</th></tr></thead>
                            <tbody>${keyFindingsRows}</tbody>
                        </table>
                    </div>

                    <div class="section">
                        <div class="section-title">INCIDENT SUMMARY</div>
                        <table>
                            <tbody>
                                <tr><th>Total Traffic Analyzed</th><td>${htmlEscape(data.summary.total_packets)}</td></tr>
                                <tr><th>Total Anomalies Detected</th><td>${htmlEscape(data.summary.total_anomalies)}</td></tr>
                                <tr><th>Anomaly Percentage</th><td>${htmlEscape(data.summary.anomaly_percentage)}</td></tr>
                                <tr><th>Critical Alerts Count</th><td>${htmlEscape(data.summary.critical_alerts)}</td></tr>
                                <tr><th>Overall Risk Level</th><td>${htmlEscape(data.summary.risk_level)}</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <div class="section">
                        <div class="section-title">THREAT ANALYSIS</div>
                        <table>
                            <tbody>
                                <tr><th>Top Threat Type</th><td>${htmlEscape(data.threats.top_threat)}</td></tr>
                            </tbody>
                        </table>
                        <table style="margin-top:6px;">
                            <thead><tr><th>Threat Category</th><th>Incidents</th></tr></thead>
                            <tbody>${threatRows}</tbody>
                        </table>
                    </div>

                    <div class="section">
                        <div class="section-title">TRAFFIC ANALYTICS SUMMARY</div>
                        <table>
                            <tbody>
                                <tr><th>Peak Traffic Time</th><td>${htmlEscape(data.traffic.peak_time)}</td></tr>
                                <tr><th>Dominant Protocol</th><td>${htmlEscape(data.traffic.dominant_protocol)}</td></tr>
                                <tr><th>Packet Size Behavior</th><td>${htmlEscape(data.traffic.packet_size_summary)}</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <div class="section">
                        <div class="section-title">FORENSIC INVESTIGATION FINDINGS</div>
                        <table>
                            <tbody>
                                <tr><th>Most Suspicious IP</th><td>${htmlEscape(data.forensics.suspicious_ip)}</td></tr>
                                <tr><th>Total Incidents</th><td>${htmlEscape(data.forensics.total_incidents)}</td></tr>
                                <tr><th>Primary Attack Type</th><td>${htmlEscape(data.forensics.primary_attack)}</td></tr>
                                <tr><th>Action Taken</th><td>${htmlEscape(data.forensics.action_taken)}</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <div class="section">
                        <div class="section-title">DETAILED EVIDENCE LOG</div>
                        <table>
                            <thead>
                                <tr><th>Timestamp</th><th>Source IP</th><th>Target</th><th>Protocol</th><th>Attack Type</th><th>Score</th><th>Severity</th><th>Action</th></tr>
                            </thead>
                            <tbody>${evidenceRows}</tbody>
                        </table>
                    </div>

                    <div class="section">
                        <div class="section-title">RECOMMENDATIONS</div>
                        <table>
                            <thead><tr><th>#</th><th>Recommendation</th></tr></thead>
                            <tbody>${recommendationRows}</tbody>
                        </table>
                    </div>
                </body>
                </html>
            `;

            const blob = new Blob([`\uFEFF${htmlContent}`], { type: "application/vnd.ms-excel;charset=utf-8;" });
            const link = document.createElement("a");
            const url = URL.createObjectURL(blob);
            link.setAttribute("href", url);
            link.setAttribute("download", `Security_Report_${data.header.report_id}.xls`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        } catch (e) {
            console.error("Report generation failed:", e);
            alert("Failed to generate report. Ensure backend is running.");
        }
        setDownloading(false);
    };

    return (
        <div className="flex flex-col items-center justify-center h-[80vh] space-y-8 animate-fade-in text-center">
            <div className="bg-slate-800 p-8 rounded-2xl border border-slate-700 shadow-2xl max-w-lg w-full">
                <div className="flex justify-center mb-6">
                    <div className="bg-blue-500/20 p-4 rounded-full text-blue-400 animate-pulse">
                        <FileText size={64} />
                    </div>
                </div>

                <h2 className="text-3xl font-bold text-slate-100 mb-2">Generate Security Report</h2>
                <p className="text-slate-400 mb-8">
                    Create a comprehensive investigation report including incident summaries, threat analysis, forensic logs, and actionable recommendations.
                </p>

                <button
                    onClick={handleDownload}
                    disabled={downloading}
                    className="w-full group relative flex items-center justify-center bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-bold py-4 px-8 rounded-xl shadow-lg transition-all transform hover:scale-[1.02] active:scale-[0.98]"
                >
                    {downloading ? (
                        <div className="w-6 h-6 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                    ) : (
                        <>
                            <Download className="mr-3 group-hover:animate-bounce" size={24} />
                            Download Comprehensive Report
                        </>
                    )}
                </button>

                <p className="text-xs text-slate-500 mt-4">
                    Format: Styled Excel (.xls) • Securely Generated • Investigation Ready
                </p>
            </div>
        </div>
    );
};

export default Reports;
