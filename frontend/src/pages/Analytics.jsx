import { useEffect, useMemo, useState } from 'react';
import { Activity, AlertTriangle, Bot, Download, Eye, Globe2, Lock, RefreshCw, ShieldCheck } from 'lucide-react';
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { jsPDF } from 'jspdf';
import { autoTable } from 'jspdf-autotable';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';
import toast from 'react-hot-toast';

function mergeDaily(activity = [], threats = []) {
  const rows = new Map();
  activity.forEach((item) => rows.set(item._id, {
    date: item._id, visits: item.visits || 0, secure: item.secure || 0,
    insecure: item.insecure || 0, threats: 0, blocked: 0,
  }));
  threats.forEach((item) => {
    const row = rows.get(item._id) || { date: item._id, visits: 0, secure: 0, insecure: 0 };
    rows.set(item._id, { ...row, threats: item.threats || 0, blocked: item.blocked || 0 });
  });
  return [...rows.values()].sort((a, b) => a.date.localeCompare(b.date));
}

function scoreColor(score) {
  if (score === null) return 'text-gray-400';
  if (score >= 80) return 'text-safe';
  if (score >= 55) return 'text-warning';
  return 'text-danger';
}

export default function Analytics() {
  const { user } = useAuth();
  const [days, setDays] = useState(30);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const response = await api.get('/api/dashboard/analytics', { params: { days } });
      setData(response.data.data);
    } catch (error) {
      toast.error(error.response?.data?.message || 'Could not load analytics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [days]);
  const daily = useMemo(() => mergeDaily(data?.dailyActivity, data?.dailyThreats), [data]);

  const askAssistant = (issue) => {
    window.dispatchEvent(new CustomEvent('netguard:assistant', { detail: { issue } }));
  };

  const downloadPdf = () => {
    if (!data) return;
    const doc = new jsPDF({ unit: 'mm', format: 'a4' });
    const date = new Date(data.generatedAt);
    const totals = data.totals;

    doc.setFillColor(15, 17, 23);
    doc.rect(0, 0, 210, 35, 'F');
    doc.setTextColor(79, 142, 247);
    doc.setFontSize(20);
    doc.text('NetGuard Security Analytics Report', 14, 16);
    doc.setTextColor(210, 220, 235);
    doc.setFontSize(10);
    doc.text(`Generated ${date.toLocaleString()} | Last ${data.periodDays} days`, 14, 24);
    doc.text(`Account: ${user?.email || 'NetGuard user'} | Privacy mode: domain-only`, 14, 30);

    doc.setTextColor(25, 30, 42);
    doc.setFontSize(15);
    doc.text(`Security score: ${data.securityScore ?? 'Not enough data'}`, 14, 47);

    autoTable(doc, {
      startY: 54,
      head: [['Visits', 'Domains', 'HTTPS', 'HTTP', 'Threats', 'Blocked', 'High risk', 'Trackers']],
      body: [[totals.visits, totals.uniqueDomains, totals.secureVisits, totals.insecureVisits,
        totals.threats, totals.blocked, totals.highRisk, totals.trackers]],
      styles: { fontSize: 8, halign: 'center' },
      headStyles: { fillColor: [79, 142, 247] },
    });

    let y = doc.lastAutoTable.finalY + 10;
    doc.setFontSize(13);
    doc.text('Recommended actions', 14, y);
    y += 7;
    doc.setFontSize(9);
    data.recommendations.forEach((recommendation, index) => {
      const lines = doc.splitTextToSize(`${index + 1}. ${recommendation}`, 180);
      doc.text(lines, 14, y);
      y += (lines.length * 5) + 2;
    });

    autoTable(doc, {
      startY: y + 3,
      head: [['Domain', 'Visits', 'HTTPS', 'HTTP', 'Threats', 'Last visited']],
      body: data.domains.map((domain) => [
        domain.domain,
        domain.visits,
        domain.secureVisits,
        domain.insecureVisits,
        domain.threats,
        domain.lastVisitedAt ? new Date(domain.lastVisitedAt).toLocaleString() : '-',
      ]),
      styles: { fontSize: 7 },
      headStyles: { fillColor: [31, 41, 55] },
      columnStyles: { 0: { cellWidth: 55 } },
      didDrawPage: () => {
        doc.setFontSize(7);
        doc.setTextColor(100);
        doc.text('Normal browsing analytics are domain-only. A detected threat may retain its affected URL as security evidence.', 14, 290);
      },
    });

    const pageCount = doc.getNumberOfPages();
    for (let page = 1; page <= pageCount; page += 1) {
      doc.setPage(page);
      doc.setFontSize(7);
      doc.setTextColor(120);
      doc.text(`Page ${page} of ${pageCount}`, 190, 290, { align: 'right' });
    }

    doc.save(`netguard-security-report-${date.toISOString().slice(0, 10)}.pdf`);
    toast.success('PDF security report downloaded');
  };

  if (loading) {
    return <div className="h-64 flex items-center justify-center"><div className="animate-spin rounded-full h-10 w-10 border-t-2 border-primary" /></div>;
  }

  if (!data) {
    return (
      <div className="card text-center py-12">
        <AlertTriangle className="w-10 h-10 text-warning mx-auto mb-3" />
        <p className="text-gray-400">Analytics could not be loaded.</p>
        <button onClick={load} className="btn-primary mt-4">Try again</button>
      </div>
    );
  }

  const totals = data.totals;
  return (
    <div className="space-y-6">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Browsing Security Analytics</h1>
          <p className="text-sm text-gray-500 mt-1">Privacy-preserving domain analytics and downloadable evidence for your project report.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select value={days} onChange={(event) => setDays(Number(event.target.value))} className="input-field">
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
          </select>
          <button onClick={load} className="btn-ghost inline-flex items-center gap-2"><RefreshCw className="w-4 h-4" /> Refresh</button>
          <button onClick={downloadPdf} className="btn-primary inline-flex items-center gap-2"><Download className="w-4 h-4" /> Download PDF</button>
        </div>
      </div>

      <div className="card border-safe/20 bg-safe/5 flex gap-3 items-start">
        <Lock className="w-5 h-5 text-safe mt-0.5" />
        <div>
          <div className="text-sm font-semibold text-gray-200">Domain-only privacy mode</div>
          <p className="text-xs text-gray-500 mt-1">Normal browsing analytics store hostnames and aggregate counts only—no paths, queries, hashes, or titles. A detected threat may retain its affected URL as security evidence.</p>
        </div>
      </div>

      <div className="grid grid-cols-2 xl:grid-cols-5 gap-4">
        <div className="stat-card"><ShieldCheck className="w-5 h-5 text-primary" /><span className="text-xs text-gray-500">Security score</span><strong className={`text-3xl ${scoreColor(data.securityScore)}`}>{data.securityScore ?? 'N/A'}</strong></div>
        <div className="stat-card"><Activity className="w-5 h-5 text-secondary" /><span className="text-xs text-gray-500">Page visits</span><strong className="text-3xl">{totals.visits}</strong></div>
        <div className="stat-card"><Globe2 className="w-5 h-5 text-primary" /><span className="text-xs text-gray-500">Unique domains</span><strong className="text-3xl">{totals.uniqueDomains}</strong></div>
        <div className="stat-card"><AlertTriangle className="w-5 h-5 text-danger" /><span className="text-xs text-gray-500">Threats</span><strong className="text-3xl">{totals.threats}</strong></div>
        <div className="stat-card"><Eye className="w-5 h-5 text-warning" /><span className="text-xs text-gray-500">Trackers</span><strong className="text-3xl">{totals.trackers}</strong></div>
      </div>

      <div className="card">
        <h2 className="font-semibold text-gray-200 mb-4">Visits and findings</h2>
        {daily.length ? (
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={daily}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2d3e" />
              <XAxis dataKey="date" stroke="#5a7a99" fontSize={11} tickFormatter={(value) => value.slice(5)} />
              <YAxis stroke="#5a7a99" fontSize={11} />
              <Tooltip contentStyle={{ background: '#1e2130', border: '1px solid #2a2d3e', borderRadius: 8 }} />
              <Legend />
              <Line type="monotone" dataKey="secure" name="HTTPS visits" stroke="#00e676" strokeWidth={2} />
              <Line type="monotone" dataKey="insecure" name="HTTP visits" stroke="#ffa726" strokeWidth={2} />
              <Line type="monotone" dataKey="threats" name="Threats" stroke="#ff3b5c" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        ) : <div className="h-48 flex items-center justify-center text-sm text-gray-600">Install and pair v3.4 of the extension to begin collecting domain-level analytics.</div>}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="card xl:col-span-2 overflow-hidden">
          <h2 className="font-semibold text-gray-200 mb-4">Most visited domains</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs uppercase text-gray-600 border-b border-border"><th className="py-3">Domain</th><th>Visits</th><th>HTTPS</th><th>HTTP</th><th>Threats</th></tr></thead>
              <tbody>{data.domains.map((domain) => (
                <tr key={domain.domain} className="border-b border-border/60">
                  <td className="py-3 text-gray-300">{domain.domain}</td><td>{domain.visits}</td><td className="text-safe">{domain.secureVisits}</td><td className="text-warning">{domain.insecureVisits}</td><td className={domain.threats ? 'text-danger' : 'text-gray-500'}>{domain.threats}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between mb-4"><h2 className="font-semibold text-gray-200">Recommended actions</h2><Bot className="w-5 h-5 text-primary" /></div>
          <div className="space-y-3">
            {data.recommendations.map((recommendation) => (
              <button key={recommendation} onClick={() => askAssistant(recommendation)} className="w-full text-left p-3 rounded-lg bg-surface hover:bg-primary/10 border border-border hover:border-primary/30 transition-all">
                <p className="text-sm text-gray-300">{recommendation}</p>
                <span className="text-xs text-primary mt-2 inline-block">Ask assistant to guide me →</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
