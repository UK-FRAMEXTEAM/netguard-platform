import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle, Bot, CheckCircle2, Download, FileBarChart, Globe2,
  MonitorSmartphone, RefreshCw, ServerCog, ShieldCheck,
} from 'lucide-react';
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { jsPDF } from 'jspdf';
import { autoTable } from 'jspdf-autotable';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';
import toast from 'react-hot-toast';

function scoreClass(score) {
  if (score === null || score === undefined) return 'text-gray-400';
  if (score >= 80) return 'text-safe';
  if (score >= 55) return 'text-warning';
  return 'text-danger';
}

function browserDaily(data) {
  const rows = new Map();
  (data?.dailyActivity || []).forEach((item) => rows.set(item._id, {
    date: item._id,
    secure: item.secure || 0,
    insecure: item.insecure || 0,
    threats: 0,
    blocked: 0,
  }));
  (data?.dailyThreats || []).forEach((item) => {
    const row = rows.get(item._id) || { date: item._id, secure: 0, insecure: 0 };
    rows.set(item._id, { ...row, threats: item.threats || 0, blocked: item.blocked || 0 });
  });
  return [...rows.values()].sort((a, b) => a.date.localeCompare(b.date));
}

function websiteDaily(data) {
  return (data?.daily || []).map((item) => ({
    date: item._id,
    events: item.events || 0,
    challenged: item.challenged || 0,
    throttled: item.throttled || 0,
    blocked: item.blocked || 0,
  }));
}

export default function Reports() {
  const { user } = useAuth();
  const [reportType, setReportType] = useState('browser');
  const [days, setDays] = useState(30);
  const [sites, setSites] = useState([]);
  const [siteId, setSiteId] = useState('');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get('/api/dashboard/sites').then((response) => {
      const nextSites = response.data.data || [];
      setSites(nextSites);
      if (nextSites.length) setSiteId((current) => current || nextSites[0]._id);
    }).catch(() => {});
  }, []);

  const loadReport = async () => {
    if (reportType === 'website' && !siteId) {
      setData(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const response = reportType === 'browser'
        ? await api.get('/api/dashboard/analytics', { params: { days } })
        : await api.get('/api/dashboard/website-report', { params: { days, siteId } });
      setData(response.data.data);
    } catch (error) {
      setData(null);
      toast.error(error.response?.data?.message || 'Could not generate report');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadReport(); }, [reportType, days, siteId]);

  const daily = useMemo(() => reportType === 'browser' ? browserDaily(data) : websiteDaily(data), [data, reportType]);

  const askAssistant = (recommendation) => {
    const label = reportType === 'browser' ? 'web browsing report' : `protected website report for ${data?.site?.siteName || 'the selected site'}`;
    window.dispatchEvent(new CustomEvent('netguard:assistant', {
      detail: { issue: `${label}: ${recommendation}` },
    }));
  };

  const downloadPdf = () => {
    if (!data) return;
    const website = reportType === 'website';
    const generated = new Date(data.generatedAt);
    const title = website ? 'Protected Website Security Report' : 'Web Browsing Security Report';
    const doc = new jsPDF({ unit: 'mm', format: 'a4' });

    doc.setFillColor(15, 17, 23);
    doc.rect(0, 0, 210, 38, 'F');
    doc.setTextColor(79, 142, 247);
    doc.setFontSize(19);
    doc.text(`NetGuard ${title}`, 14, 16);
    doc.setTextColor(210, 220, 235);
    doc.setFontSize(9);
    doc.text(`Generated ${generated.toLocaleString()} | Last ${data.periodDays} days`, 14, 25);
    doc.text(`Account: ${user?.email || 'NetGuard user'}${website ? ` | Site: ${data.site.siteUrl}` : ' | Privacy: domain-only browsing data'}`, 14, 31);

    doc.setTextColor(25, 30, 42);
    doc.setFontSize(14);
    doc.text(`Security score: ${data.securityScore ?? 'Not enough data'}`, 14, 49);

    const overviewHead = website
      ? ['Events', 'Network sources', 'Allowed', 'Challenged', 'Throttled', 'Blocked', 'CAPTCHA pass', 'CAPTCHA fail']
      : ['Visits', 'Domains', 'HTTPS', 'HTTP', 'Threats', 'Blocked', 'High risk', 'Trackers'];
    const totals = data.totals || {};
    const overviewBody = website
      ? [totals.monitoredEvents, totals.uniqueNetworkSources, totals.allowed, totals.challenged, totals.throttled, totals.blocked, totals.recaptchaPassed, totals.recaptchaFailed]
      : [totals.visits, totals.uniqueDomains, totals.secureVisits, totals.insecureVisits, totals.threats, totals.blocked, totals.highRisk, totals.trackers];
    autoTable(doc, { startY: 56, head: [overviewHead], body: [overviewBody], styles: { fontSize: 7.2, halign: 'center' }, headStyles: { fillColor: [79, 142, 247] } });

    let y = doc.lastAutoTable.finalY + 9;
    doc.setFontSize(12);
    doc.text('Recommended actions', 14, y);
    y += 6;
    doc.setFontSize(8.5);
    (data.recommendations || []).forEach((recommendation, index) => {
      const lines = doc.splitTextToSize(`${index + 1}. ${recommendation}`, 180);
      doc.text(lines, 14, y);
      y += lines.length * 4.4 + 1.5;
    });

    if (website && data.site.lastNetworkScan?.scannedAt) {
      const scan = data.site.lastNetworkScan;
      autoTable(doc, {
        startY: y + 3,
        head: [['TLS', 'Certificate days', 'HSTS', 'CSP', 'Frame protection', 'No-sniff', 'Referrer policy', 'Posture score']],
        body: [[scan.tlsAuthorized ? scan.tlsProtocol : 'Failed', scan.certificateDaysRemaining ?? 'N/A', scan.hsts ? 'Yes' : 'No', scan.contentSecurityPolicy ? 'Yes' : 'No', scan.frameProtection ? 'Yes' : 'No', scan.noSniff ? 'Yes' : 'No', scan.referrerPolicy ? 'Yes' : 'No', scan.securityHeaderScore ?? 'N/A']],
        styles: { fontSize: 6.8, halign: 'center' },
        headStyles: { fillColor: [79, 142, 247] },
      });
      y = doc.lastAutoTable.finalY + 5;
    }

    if (website) {
      autoTable(doc, {
        startY: y + 3,
        head: [['Anonymized source', 'Events', 'Challenges', 'Blocks', 'Last seen']],
        body: (data.networkSources || []).map((source) => [source.source, source.events, source.challenged, source.blocked, new Date(source.lastSeenAt).toLocaleString()]),
        styles: { fontSize: 7.5 }, headStyles: { fillColor: [31, 41, 55] },
      });
      autoTable(doc, {
        startY: doc.lastAutoTable.finalY + 8,
        head: [['Time', 'Type', 'Category', 'Severity', 'Action', 'Route', 'Source']],
        body: (data.recentEvents || []).map((event) => [new Date(event.createdAt).toLocaleString(), event.eventType, event.category, event.severity, event.action, event.route, event.source]),
        styles: { fontSize: 6.5 }, headStyles: { fillColor: [31, 41, 55] },
      });
    } else {
      autoTable(doc, {
        startY: y + 3,
        head: [['Domain', 'Visits', 'HTTPS', 'HTTP', 'Threats', 'High risk', 'Last visited']],
        body: (data.domains || []).map((domain) => [domain.domain, domain.visits, domain.secureVisits, domain.insecureVisits, domain.threats, domain.highRiskThreats, domain.lastVisitedAt ? new Date(domain.lastVisitedAt).toLocaleString() : '-']),
        styles: { fontSize: 7 }, headStyles: { fillColor: [31, 41, 55] }, columnStyles: { 0: { cellWidth: 45 } },
      });
      autoTable(doc, {
        startY: doc.lastAutoTable.finalY + 8,
        head: [['Time', 'Category', 'Severity', 'Action', 'Domain', 'Finding']],
        body: (data.recentThreats || []).map((item) => [new Date(item.createdAt).toLocaleString(), item.category, item.severity, item.action, item.domain || '-', item.detail]),
        styles: { fontSize: 6.5 }, headStyles: { fillColor: [31, 41, 55] },
      });
    }

    const pageCount = doc.getNumberOfPages();
    for (let page = 1; page <= pageCount; page += 1) {
      doc.setPage(page);
      doc.setFontSize(7);
      doc.setTextColor(110);
      const privacy = website ? 'Network source labels are keyed HMAC values. No raw IP/MAC or form values are included.' : 'Normal browsing entries contain domains only; threat evidence may retain the affected URL.';
      doc.text(privacy, 14, 289);
      doc.text(`Page ${page} of ${pageCount}`, 196, 289, { align: 'right' });
    }
    const slug = website ? `website-${data.site.siteName || 'site'}` : 'web-browsing';
    doc.save(`netguard-${slug.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${generated.toISOString().slice(0, 10)}.pdf`);
    toast.success('Full PDF report downloaded');
  };

  const statCards = reportType === 'browser' ? [
    [ShieldCheck, 'Security score', data?.securityScore ?? 'N/A', scoreClass(data?.securityScore)],
    [MonitorSmartphone, 'Page visits', data?.totals?.visits || 0, 'text-gray-100'],
    [Globe2, 'Unique domains', data?.totals?.uniqueDomains || 0, 'text-primary'],
    [AlertTriangle, 'Threats', data?.totals?.threats || 0, 'text-danger'],
    [CheckCircle2, 'Blocked', data?.totals?.blocked || 0, 'text-warning'],
  ] : [
    [ShieldCheck, 'Security score', data?.securityScore ?? 'N/A', scoreClass(data?.securityScore)],
    [ServerCog, 'Monitored events', data?.totals?.monitoredEvents || 0, 'text-gray-100'],
    [Globe2, 'Network sources', data?.totals?.uniqueNetworkSources || 0, 'text-primary'],
    [AlertTriangle, 'Challenges', data?.totals?.challenged || 0, 'text-warning'],
    [CheckCircle2, 'Blocked', data?.totals?.blocked || 0, 'text-danger'],
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col xl:flex-row xl:items-end justify-between gap-4">
        <div><h1 className="text-2xl font-bold text-gray-100">Security Reports</h1><p className="text-sm text-gray-500 mt-1">Generate full evidence-backed browser or protected-website reports from MongoDB.</p></div>
        <div className="flex flex-wrap gap-2">
          <select value={days} onChange={(event) => setDays(Number(event.target.value))} className="input-field"><option value={7}>Last 7 days</option><option value={30}>Last 30 days</option><option value={90}>Last 90 days</option></select>
          {reportType === 'website' && sites.length > 0 && <select value={siteId} onChange={(event) => setSiteId(event.target.value)} className="input-field max-w-56">{sites.map((site) => <option key={site._id} value={site._id}>{site.siteName}</option>)}</select>}
          <button onClick={loadReport} className="btn-ghost inline-flex items-center gap-2"><RefreshCw className="w-4 h-4" /> Refresh</button>
          <button onClick={downloadPdf} disabled={!data} className="btn-primary inline-flex items-center gap-2 disabled:opacity-40"><Download className="w-4 h-4" /> Download Full PDF</button>
        </div>
      </div>

      <div className="inline-flex p-1 bg-surface border border-border rounded-xl">
        <button onClick={() => setReportType('browser')} className={`px-5 py-2.5 rounded-lg text-sm font-medium inline-flex items-center gap-2 ${reportType === 'browser' ? 'bg-primary text-white' : 'text-gray-400'}`}><MonitorSmartphone className="w-4 h-4" /> Web Browsing Report</button>
        <button onClick={() => setReportType('website')} className={`px-5 py-2.5 rounded-lg text-sm font-medium inline-flex items-center gap-2 ${reportType === 'website' ? 'bg-primary text-white' : 'text-gray-400'}`}><Globe2 className="w-4 h-4" /> Protected Website Report</button>
      </div>

      {loading ? <div className="h-64 flex items-center justify-center"><div className="animate-spin rounded-full h-10 w-10 border-t-2 border-primary" /></div> : reportType === 'website' && !sites.length ? (
        <div className="card text-center py-14"><FileBarChart className="w-12 h-12 text-gray-700 mx-auto mb-3" /><h2 className="font-semibold text-gray-300">Register a website first</h2><p className="text-sm text-gray-500 mt-2 mb-5">A protected-website report needs a registered site and installed integration script.</p><Link to="/sites" className="btn-primary inline-block">Open Protected Sites</Link></div>
      ) : !data ? (
        <div className="card text-center py-14"><AlertTriangle className="w-10 h-10 text-warning mx-auto mb-3" /><p className="text-gray-400">The report could not be generated.</p></div>
      ) : (
        <>
          {reportType === 'website' && <div className="card py-4 flex flex-col md:flex-row md:items-center justify-between gap-3"><div><p className="text-sm font-semibold text-gray-200">{data.site.siteName}</p><p className="text-xs text-gray-500 mt-1">{data.site.siteUrl}</p></div><div className="flex gap-2"><span className={`badge ${data.site.integrationStatus === 'connected' ? 'badge-safe' : data.site.integrationStatus === 'offline' ? 'badge-danger' : 'badge-warning'}`}>{data.site.integrationStatus}</span><span className={`badge ${data.site.isActive ? 'badge-info' : 'badge-danger'}`}>{data.site.isActive ? 'Protection enabled' : 'Protection disabled'}</span></div></div>}

          <div className="grid grid-cols-2 xl:grid-cols-5 gap-4">{statCards.map(([Icon, label, value, color]) => <div key={label} className="stat-card"><Icon className="w-5 h-5 text-primary" /><span className="text-xs text-gray-500">{label}</span><strong className={`text-3xl ${color}`}>{value}</strong></div>)}</div>

          {reportType === 'website' && (
            <div className="card">
              <h2 className="font-semibold text-gray-200 mb-4">Network protection detail</h2>
              <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
                {[
                  ['Repeated submissions', data.totals.repeatSubmissions],
                  ['Bot signals', data.totals.botSignals],
                  ['Throttled', data.totals.throttled],
                  ['reCAPTCHA passed', data.totals.recaptchaPassed],
                  ['reCAPTCHA failed', data.totals.recaptchaFailed],
                  ['Average page load', data.totals.averageLoadMs === null ? 'N/A' : `${data.totals.averageLoadMs} ms`],
                ].map(([label, value]) => <div key={label} className="bg-surface rounded-lg p-3"><span className="block text-[11px] text-gray-600">{label}</span><strong className="text-lg text-gray-200 mt-1 block">{value}</strong></div>)}
              </div>
            </div>
          )}

          {reportType === 'website' && (
            <div className="card">
              <div className="flex items-center justify-between gap-3 mb-4"><h2 className="font-semibold text-gray-200">Stored TLS and security-header posture</h2><Link to="/sites" className="text-xs text-primary hover:underline">Run or refresh scan</Link></div>
              {data.site.lastNetworkScan?.scannedAt ? <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-3">{[
                ['TLS', data.site.lastNetworkScan.tlsAuthorized ? data.site.lastNetworkScan.tlsProtocol : 'Failed'],
                ['Certificate days', data.site.lastNetworkScan.certificateDaysRemaining ?? 'N/A'],
                ['HSTS', data.site.lastNetworkScan.hsts ? 'Enabled' : 'Missing'],
                ['CSP', data.site.lastNetworkScan.contentSecurityPolicy ? 'Enabled' : 'Missing'],
                ['Frame protection', data.site.lastNetworkScan.frameProtection ? 'Enabled' : 'Missing'],
                ['No-sniff', data.site.lastNetworkScan.noSniff ? 'Enabled' : 'Missing'],
                ['Referrer policy', data.site.lastNetworkScan.referrerPolicy ? 'Enabled' : 'Missing'],
                ['Posture score', data.site.lastNetworkScan.securityHeaderScore ?? 'N/A'],
              ].map(([label, value]) => <div key={label} className="bg-surface rounded-lg p-3"><span className="text-[11px] text-gray-600 block">{label}</span><strong className="text-sm text-gray-200 mt-1 block">{value}</strong></div>)}</div> : <div className="text-sm text-gray-600 py-6 text-center">No network posture scan is stored yet. Run it from Protected Sites to add real TLS/header evidence.</div>}
            </div>
          )}

          <div className="card"><h2 className="font-semibold text-gray-200 mb-4">{reportType === 'browser' ? 'Browsing and threat trend' : 'Protected website network trend'}</h2>{daily.length ? <ResponsiveContainer width="100%" height={300}><LineChart data={daily}><CartesianGrid strokeDasharray="3 3" stroke="#2a2d3e" /><XAxis dataKey="date" stroke="#5a7a99" fontSize={11} tickFormatter={(value) => value.slice(5)} /><YAxis stroke="#5a7a99" fontSize={11} /><Tooltip contentStyle={{ background: '#1e2130', border: '1px solid #2a2d3e', borderRadius: 8 }} /><Legend />{reportType === 'browser' ? <><Line type="monotone" dataKey="secure" name="HTTPS visits" stroke="#00e676" strokeWidth={2} /><Line type="monotone" dataKey="insecure" name="HTTP visits" stroke="#ffa726" strokeWidth={2} /><Line type="monotone" dataKey="threats" name="Threats" stroke="#ff3b5c" strokeWidth={2} /></> : <><Line type="monotone" dataKey="events" name="Monitored events" stroke="#4f8ef7" strokeWidth={2} /><Line type="monotone" dataKey="challenged" name="Challenges" stroke="#ffa726" strokeWidth={2} /><Line type="monotone" dataKey="blocked" name="Blocked" stroke="#ff3b5c" strokeWidth={2} /></>}</LineChart></ResponsiveContainer> : <div className="h-40 flex items-center justify-center text-sm text-gray-600">No events are available for this period.</div>}</div>

          <div className="grid xl:grid-cols-3 gap-6">
            <div className="card xl:col-span-2 overflow-hidden">
              <h2 className="font-semibold text-gray-200 mb-4">{reportType === 'browser' ? 'Domain evidence' : 'Anonymized network sources'}</h2>
              <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="text-left text-xs uppercase text-gray-600 border-b border-border">{reportType === 'browser' ? <><th className="py-3">Domain</th><th>Visits</th><th>HTTPS</th><th>HTTP</th><th>Threats</th></> : <><th className="py-3">Source</th><th>Events</th><th>Challenges</th><th>Blocks</th><th>Last seen</th></>}</tr></thead><tbody>{reportType === 'browser' ? (data.domains || []).map((domain) => <tr key={domain.domain} className="border-b border-border/60"><td className="py-3 text-gray-300">{domain.domain}</td><td>{domain.visits}</td><td className="text-safe">{domain.secureVisits}</td><td className="text-warning">{domain.insecureVisits}</td><td className="text-danger">{domain.threats}</td></tr>) : (data.networkSources || []).map((source) => <tr key={source.source} className="border-b border-border/60"><td className="py-3 text-primary font-mono text-xs">{source.source}</td><td>{source.events}</td><td className="text-warning">{source.challenged}</td><td className="text-danger">{source.blocked}</td><td className="text-gray-500 text-xs">{new Date(source.lastSeenAt).toLocaleString()}</td></tr>)}</tbody></table></div>
            </div>
            <div className="card"><div className="flex items-center justify-between mb-4"><h2 className="font-semibold text-gray-200">AI-guided fixes</h2><Bot className="w-5 h-5 text-primary" /></div><div className="space-y-3">{(data.recommendations || []).map((recommendation) => <button key={recommendation} onClick={() => askAssistant(recommendation)} className="w-full text-left p-3 rounded-lg bg-surface hover:bg-primary/10 border border-border hover:border-primary/30 transition"><p className="text-sm text-gray-300">{recommendation}</p><span className="text-xs text-primary mt-2 inline-block">Ask agent to fix this →</span></button>)}</div></div>
          </div>

          <div className="card overflow-hidden"><h2 className="font-semibold text-gray-200 mb-4">Recent report evidence</h2><div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="text-left text-xs uppercase text-gray-600 border-b border-border">{reportType === 'browser' ? <><th className="py-3">Time</th><th>Category</th><th>Severity</th><th>Action</th><th>Domain</th><th>Finding</th></> : <><th className="py-3">Time</th><th>Type</th><th>Category</th><th>Severity</th><th>Action</th><th>Route</th><th>Source</th></>}</tr></thead><tbody>{reportType === 'browser' ? (data.recentThreats || []).map((item) => <tr key={item._id} className="border-b border-border/60"><td className="py-3 text-xs text-gray-500">{new Date(item.createdAt).toLocaleString()}</td><td>{item.category}</td><td className="text-warning">{item.severity}</td><td>{item.action}</td><td>{item.domain || '-'}</td><td className="max-w-xs text-gray-400">{item.detail}</td></tr>) : (data.recentEvents || []).map((event) => <tr key={event._id} className="border-b border-border/60"><td className="py-3 text-xs text-gray-500">{new Date(event.createdAt).toLocaleString()}</td><td>{event.eventType}</td><td>{event.category}</td><td className="text-warning">{event.severity}</td><td>{event.action}</td><td>{event.route}</td><td className="text-primary font-mono text-xs">{event.source}</td></tr>)}</tbody></table></div></div>

          <div className="card border-safe/20 bg-safe/5"><h2 className="font-semibold text-gray-200">Privacy and report scope</h2><p className="text-xs text-gray-500 mt-2">{data.privacyMode}</p>{(data.limitations || []).length > 0 && <ul className="mt-3 space-y-2 text-xs text-gray-500 list-disc pl-5">{data.limitations.map((item) => <li key={item}>{item}</li>)}</ul>}</div>
        </>
      )}
    </div>
  );
}
