import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { CheckCircle, Chrome, Download, ExternalLink, RefreshCw, Shield } from 'lucide-react';

const fallbackRelease = {
  latestVersion: '3.1.0',
  downloadUrl: '/downloads/netguard-pro-extension.zip',
  publishedAt: '2026-07-13',
  changelog: ['Google sign-in and cloud sync', 'Public update notifications', 'Password breach and TLS inspection tools'],
};

export default function Install() {
  const [release, setRelease] = useState(fallbackRelease);

  useEffect(() => {
    fetch('/release.json', { cache: 'no-store' })
      .then((response) => {
        if (!response.ok) throw new Error('Release metadata unavailable');
        return response.json();
      })
      .then(setRelease)
      .catch(() => setRelease(fallbackRelease));
  }, []);

  const downloadUrl = release.downloadUrl || fallbackRelease.downloadUrl;

  return (
    <div className="min-h-screen bg-dark text-gray-100">
      <nav className="border-b border-border bg-dark/90 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto h-16 px-6 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3">
            <span className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center">
              <Shield className="w-5 h-5 text-primary" />
            </span>
            <span className="font-bold">NetGuard Pro</span>
          </Link>
          <Link to="/login" className="btn-ghost text-sm">Dashboard Sign In</Link>
        </div>
      </nav>

      <main className="max-w-5xl mx-auto px-6 py-16">
        <section className="text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-safe/10 border border-safe/20 text-safe text-sm mb-6">
            <CheckCircle className="w-4 h-4" /> Latest release v{release.latestVersion}
          </div>
          <h1 className="text-4xl md:text-5xl font-bold mb-5">Install NetGuard Pro for Chrome</h1>
          <p className="text-gray-400 leading-relaxed mb-8">
            The project build is distributed as an unpacked Manifest V3 extension for testing and assessment.
            Download it once, then load the extracted folder in Chrome Developer Mode.
          </p>

          <a href={downloadUrl} className="btn-primary inline-flex items-center gap-2 text-base px-8 py-3" download>
            <Download className="w-5 h-5" /> Download v{release.latestVersion}
          </a>
          {release.sha256 && (
            <p className="mt-3 text-xs text-gray-600 font-mono break-all">SHA-256: {release.sha256}</p>
          )}
        </section>

        <section className="grid md:grid-cols-3 gap-5 mt-16">
          {[
            { icon: Download, title: '1. Download & extract', text: 'Download the ZIP and extract it to a permanent folder. Do not select the ZIP itself.' },
            { icon: Chrome, title: '2. Open extensions', text: 'Open chrome://extensions, then enable the Developer mode switch in the top-right corner.' },
            { icon: ExternalLink, title: '3. Load unpacked', text: 'Choose Load unpacked and select the extracted folder that contains manifest.json.' },
          ].map(({ icon: Icon, title, text }) => (
            <article key={title} className="card">
              <div className="w-11 h-11 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
                <Icon className="w-5 h-5 text-primary" />
              </div>
              <h2 className="font-semibold mb-2">{title}</h2>
              <p className="text-sm text-gray-500 leading-relaxed">{text}</p>
            </article>
          ))}
        </section>

        <section className="grid md:grid-cols-2 gap-6 mt-10">
          <article className="card">
            <div className="flex items-center gap-2 mb-3">
              <RefreshCw className="w-5 h-5 text-warning" />
              <h2 className="font-semibold">How updates work</h2>
            </div>
            <p className="text-sm text-gray-500 leading-relaxed">
              The extension checks this public release feed even when you are signed out. When a newer version is available,
              an update banner appears inside the extension. Download the new ZIP, replace the old extracted files, and click
              Reload on chrome://extensions.
            </p>
          </article>

          <article className="card">
            <h2 className="font-semibold mb-3">What changed in v{release.latestVersion}</h2>
            <ul className="space-y-2 text-sm text-gray-500">
              {(release.changelog || []).map((item) => (
                <li key={item} className="flex gap-2"><span className="text-safe">✓</span><span>{item}</span></li>
              ))}
            </ul>
          </article>
        </section>

        <p className="text-center text-xs text-gray-600 mt-12">
          For direct one-click installation and automatic updates, publish the final build in the Chrome Web Store.
        </p>
      </main>
    </div>
  );
}
