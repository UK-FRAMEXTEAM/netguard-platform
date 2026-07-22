import { Shield, Globe, Lock, Zap, Eye, Brain, Cloud, Download } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';

const features = [
  { icon: Shield, title: 'Defense-in-Depth', desc: '5-layer security with behavioral analysis, threat intelligence, and Zero Trust enforcement' },
  { icon: Brain, title: 'AI Threat Detection', desc: 'Privacy Badger-style behavioral tracking with automatic threat classification' },
  { icon: Lock, title: 'Zero Trust Architecture', desc: 'Never trust, always verify. All connections validated in real-time' },
  { icon: Eye, title: 'Real-Time Monitoring', desc: 'SIEM-style threat logging with severity levels and instant alerts' },
  { icon: Cloud, title: 'Cloud Dashboard', desc: 'Monitor all threats, attacks, and security events from a centralized dashboard' },
  { icon: Globe, title: 'Site Protection', desc: 'Generate unique protection codes to secure your websites' },
];

const stats = [
  { label: 'Chrome Standard', value: 'MV3' },
  { label: 'Defense Layers', value: '5' },
  { label: 'Password Privacy', value: 'k-Anon' },
  { label: 'Cloud Dashboard', value: 'Live' },
];

export default function Landing() {
  const { login } = useAuth();

  return (
    <div className="min-h-screen bg-dark">
      {/* Navbar */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-dark/80 backdrop-blur-xl border-b border-border">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center">
              <Shield className="w-5 h-5 text-primary" />
            </div>
            <span className="font-bold text-lg text-gray-100">NetGuard</span>
            <span className="text-xs bg-primary/20 text-primary px-2 py-0.5 rounded-full font-mono">v3.5</span>
          </div>
          <div className="flex items-center gap-4">
            <Link to="/login" className="btn-primary text-sm">
              Get Started Free
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-6 relative overflow-hidden">
        {/* Background Effects */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary/5 rounded-full blur-3xl"></div>
          <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-secondary/5 rounded-full blur-3xl"></div>
          <div className="absolute inset-0" style={{
            backgroundImage: 'radial-gradient(circle at 1px 1px, rgba(255,255,255,0.03) 1px, transparent 0)',
            backgroundSize: '40px 40px'
          }}></div>
        </div>

        <div className="max-w-5xl mx-auto text-center relative">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <div className="inline-flex items-center gap-2 bg-primary/10 border border-primary/20 rounded-full px-4 py-1.5 mb-6">
              <Zap className="w-4 h-4 text-primary" />
              <span className="text-sm text-primary font-medium">Final Year Project – Network & Cloud Security</span>
            </div>

            <h1 className="text-5xl md:text-6xl font-bold text-gray-100 leading-tight mb-6">
              Defense-in-Depth
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary to-secondary"> Cloud Security </span>
              Platform
            </h1>

            <p className="text-lg text-gray-400 max-w-2xl mx-auto mb-10 leading-relaxed">
              Network-focused protection for Chrome with cloud threat intelligence,
              Zero Trust enforcement, real-time browser analysis, and centralized security monitoring.
            </p>

            <div className="flex flex-wrap items-center justify-center gap-4">
              <Link to="/install" className="btn-primary text-base px-8 py-3">
                <span className="flex items-center gap-2">
                  <Download className="w-5 h-5" />
                  Install Chrome Extension
                </span>
              </Link>
              <button onClick={login} className="btn-ghost text-base px-8 py-3">Sign in with Google</button>
            </div>
          </motion.div>

          {/* Stats Bar */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mt-16 max-w-3xl mx-auto">
            {stats.map((stat, i) => (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 + i * 0.1 }}
                className="text-center"
              >
                <div className="text-3xl font-bold text-gray-100">{stat.value}</div>
                <div className="text-sm text-gray-500 mt-1">{stat.label}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 px-6 border-t border-border">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold text-gray-100 mb-4">Advanced Security Features</h2>
            <p className="text-gray-500 max-w-xl mx-auto">
              Built with modern security frameworks including NIST CSF, Zero Trust, and Defense-in-Depth architecture.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feature, i) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.1 }}
                viewport={{ once: true }}
                className="card group hover:border-primary/30 transition-all duration-300"
              >
                <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4 group-hover:bg-primary/20 transition-colors">
                  <feature.icon className="w-6 h-6 text-primary" />
                </div>
                <h3 className="text-lg font-semibold text-gray-100 mb-2">{feature.title}</h3>
                <p className="text-sm text-gray-500 leading-relaxed">{feature.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Tech Stack Section */}
      <section className="py-20 px-6 border-t border-border bg-surface/30">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-3xl font-bold text-gray-100 mb-4">Technology Stack</h2>
          <p className="text-gray-500 mb-12">Built with modern, production-ready technologies</p>
          <div className="flex flex-wrap justify-center gap-4">
            {['React', 'Node.js', 'MongoDB', 'Express', 'Chrome MV3', 'OAuth 2.0', 'JWT', 'TLS Inspection', 'Threat Intelligence', 'Real-time Sync'].map((tech) => (
              <span key={tech} className="px-4 py-2 bg-card border border-border rounded-full text-sm text-gray-300">
                {tech}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-6 border-t border-border">
        <div className="max-w-3xl mx-auto text-center">
          <h2 className="text-3xl font-bold text-gray-100 mb-4">Ready to Secure Your Browsing?</h2>
          <p className="text-gray-500 mb-8">Get started with NetGuard Cloud Platform – it's free.</p>
          <Link to="/install" className="btn-primary inline-flex text-lg px-10 py-3.5">Install Chrome Extension</Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 px-6 border-t border-border text-center">
        <p className="text-sm text-gray-600">
          🛡️ NetGuard Pro v3.5 – Final Year Project | Network & Cloud Security | 2026
        </p>
      </footer>
    </div>
  );
}
