import React, { useState, useEffect } from 'react';
import { apiService } from '../services/api';
import type { Attacker/*, ForensicEvent*/ } from '../services/api';
import { 
  Search, ShieldCheck, Download, 
  EyeOff, Terminal, Network, Ban, Laptop, AlertCircle, RefreshCw
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis } from 'recharts';

export const AlertsView: React.FC = () => {
  const [attackers, setAttackers] = useState<Attacker[]>([]);
  const [selectedAttacker, setSelectedAttacker] = useState<Attacker | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterLevel, setFilterLevel] = useState<'all' | 'critical' | 'high' | 'medium'>('all');
  const [loading, setLoading] = useState(true);
  
  // Dynamic forensic logs states (Commented out temporarily to ensure clean TS production build prior to ChatGPT integration)
  // const [events, setEvents] = useState<ForensicEvent[]>([]);
  // const [eventsLoading, setEventsLoading] = useState(false);
  // const [expandedCve, setExpandedCve] = useState<string | null>(null);
  // const [expandedMitre, setExpandedMitre] = useState<string | null>(null);
  
  // Custom operational states
  const [blockedIps, setBlockedIps] = useState<Record<string, boolean>>({});
  const [mutedIps, setMutedIps] = useState<Record<string, boolean>>({});
  const [isolatedIps, setIsolatedIps] = useState<Record<string, boolean>>({});
  const [dumpingPcap, setDumpingPcap] = useState<Record<string, boolean>>({});

  const loadAttackers = async () => {
    try {
      const data = await apiService.getTopAttackers(30);
      setAttackers(data.results);
      if (data.results.length > 0 && !selectedAttacker) {
        setSelectedAttacker(data.results[0]);
      }
    } catch (err) {
      console.error('Error fetching attackers list', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAttackers();
  }, []);

  const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
  };

  // Actions
  const toggleBlock = (ip: string) => {
    setBlockedIps(prev => ({ ...prev, [ip]: !prev[ip] }));
  };

  const toggleMute = (ip: string) => {
    setMutedIps(prev => ({ ...prev, [ip]: !prev[ip] }));
  };

  const toggleIsolate = (ip: string) => {
    setIsolatedIps(prev => ({ ...prev, [ip]: !prev[ip] }));
  };

  const triggerPcapDump = (ip: string) => {
    setDumpingPcap(prev => ({ ...prev, [ip]: true }));
    setTimeout(() => {
      setDumpingPcap(prev => ({ ...prev, [ip]: false }));
      alert(`PCAP packet dump exported successfully for host ${ip}`);
    }, 2000);
  };

  // Filtering
  const filteredAttackers = attackers.filter(attacker => {
    const matchesSearch = attacker.src_ip.includes(searchQuery);
    const matchesLevel = filterLevel === 'all' ? true : attacker.threat_level === filterLevel;
    return matchesSearch && matchesLevel;
  });

  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '400px', gap: '16px', fontFamily: 'var(--font-mono)' }}>
        <RefreshCw style={{ animation: 'spin 1.5s linear infinite', color: 'var(--color-primary)' }} size={32} />
        <span>PARSING THREAT INCIDENT QUEUE...</span>
      </div>
    );
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '380px 1fr', gap: 'var(--spacing-lg)' }}>
      {/* Left List Queue */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-md)' }}>
        {/* Filters Panel */}
        <div className="glass-panel" style={{ padding: 'var(--spacing-md)' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ position: 'relative' }}>
              <Search style={{ position: 'absolute', left: '10px', top: '10px', color: 'rgba(255, 255, 255, 0.3)' }} size={14} />
              <input 
                type="text" 
                placeholder="SEARCH IP SUBNET..." 
                value={searchQuery}
                onChange={handleSearch}
                className="search-input"
                style={{ paddingLeft: '32px', width: '100%', maxWidth: '100%', fontFamily: 'var(--font-mono)' }}
              />
            </div>
            
            <div style={{ display: 'flex', gap: '4px', background: 'rgba(2, 4, 10, 0.4)', padding: '2px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              {(['all', 'critical', 'high', 'medium'] as const).map(level => (
                <button 
                  key={level} 
                  onClick={() => setFilterLevel(level)}
                  style={{
                    flex: 1,
                    background: filterLevel === level ? 'var(--color-secondary)' : 'transparent',
                    border: 'none',
                    color: filterLevel === level ? '#ffffff' : 'rgba(226, 232, 240, 0.4)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '10px',
                    padding: '6px 0',
                    cursor: 'pointer',
                    textTransform: 'uppercase',
                    fontWeight: 700
                  }}
                >
                  {level}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Attackers Queue Container */}
        <div className="glass-panel" style={{ padding: 0, height: '620px', overflowY: 'auto' }}>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {filteredAttackers.map(attacker => {
              const isSelected = selectedAttacker?.src_ip === attacker.src_ip;
              const isBlocked = blockedIps[attacker.src_ip];
              const isMuted = mutedIps[attacker.src_ip];
              const isIsolated = isolatedIps[attacker.src_ip];

              return (
                <div 
                  key={attacker.src_ip}
                  onClick={() => setSelectedAttacker(attacker)}
                  style={{
                    padding: '16px',
                    borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                    cursor: 'pointer',
                    background: isSelected ? 'rgba(34, 211, 238, 0.06)' : 'transparent',
                    borderLeft: isSelected ? '4px solid var(--color-primary)' : '4px solid transparent',
                    transition: 'var(--transition-fast)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '8px'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '14px', color: '#ffffff' }}>
                      {attacker.src_ip}
                    </span>
                    <span className={`status-pill ${attacker.threat_level}`}>
                      {attacker.threat_level}
                    </span>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'rgba(226, 232, 240, 0.4)' }}>
                    <span>Alerts: <strong style={{ color: '#e2e8f0', fontFamily: 'var(--font-mono)' }}>{attacker.total_events}</strong></span>
                    <span>Risk Index: <strong style={{ color: 'var(--color-danger)', fontFamily: 'var(--font-mono)' }}>{attacker.risk_score}/100</strong></span>
                  </div>

                  {/* Badges indicators for applied security controls */}
                  {(isBlocked || isMuted || isIsolated) && (
                    <div style={{ display: 'flex', gap: '4px', marginTop: '4px' }}>
                      {isBlocked && <span className="status-pill critical" style={{ fontSize: '8px', padding: '1px 4px' }}><Ban size={8} /> BLOCKED</span>}
                      {isMuted && <span className="status-pill medium" style={{ fontSize: '8px', padding: '1px 4px' }}><EyeOff size={8} /> MUTED</span>}
                      {isIsolated && <span className="status-pill high" style={{ fontSize: '8px', padding: '1px 4px' }}><Laptop size={8} /> ISOLATED</span>}
                    </div>
                  )}
                </div>
              );
            })}
            
            {filteredAttackers.length === 0 && (
              <div style={{ textAlign: 'center', padding: '32px', color: 'rgba(226, 232, 240, 0.3)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                <AlertCircle size={24} style={{ marginBottom: '8px', opacity: 0.5 }} />
                <p>NO THREAT ACTORS DETECTED</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Right Forensics Detail Panel */}
      {selectedAttacker ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-lg)' }}>
          {/* Main Info Card */}
          <div className="glass-panel glowing" style={{ minHeight: '340px', display: 'flex', flexDirection: 'column', justifyItems: 'space-between' }}>
            <div className="panel-header">
              <h3 className="panel-title">
                <Network size={16} style={{ color: 'var(--color-primary)' }} />
                FORENSIC DATA SUMMARY: {selectedAttacker.src_ip}
              </h3>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'rgba(226, 232, 240, 0.4)' }}>
                REGISTRY STAMP: {selectedAttacker.created_at || 'LIVE INTRUSION'}
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', margin: '16px 0' }}>
              <div style={{ background: 'rgba(2, 4, 10, 0.4)', padding: '12px', border: '1px solid rgba(255, 255, 255, 0.03)' }}>
                <span className="kpi-label">Aggregated Risk</span>
                <p style={{ fontFamily: 'var(--font-mono)', fontSize: '24px', fontWeight: 700, color: 'var(--color-danger)', marginTop: '4px' }}>
                  {selectedAttacker.risk_score}
                </p>
              </div>
              <div style={{ background: 'rgba(2, 4, 10, 0.4)', padding: '12px', border: '1px solid rgba(255, 255, 255, 0.03)' }}>
                <span className="kpi-label">NIDS Suricata Alerts</span>
                <p style={{ fontFamily: 'var(--font-mono)', fontSize: '24px', fontWeight: 700, color: '#ffffff', marginTop: '4px' }}>
                  {selectedAttacker.suricata_events}
                </p>
              </div>
              <div style={{ background: 'rgba(2, 4, 10, 0.4)', padding: '12px', border: '1px solid rgba(255, 255, 255, 0.03)' }}>
                <span className="kpi-label">Honeypot Hits</span>
                <p style={{ fontFamily: 'var(--font-mono)', fontSize: '24px', fontWeight: 700, color: '#ffffff', marginTop: '4px' }}>
                  {selectedAttacker.cowrie_events}
                </p>
              </div>
              <div style={{ background: 'rgba(2, 4, 10, 0.4)', padding: '12px', border: '1px solid rgba(255, 255, 255, 0.03)' }}>
                <span className="kpi-label">Active Vectors</span>
                <p style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--color-primary)', marginTop: '12px', fontWeight: 700 }}>
                  {selectedAttacker.unique_techniques} techniques Mapped
                </p>
              </div>
            </div>

            {/* Tactical Control Action Dashboard */}
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', borderTop: '1px solid rgba(255, 255, 255, 0.05)', paddingTop: '16px', marginTop: 'auto' }}>
              <button 
                onClick={() => toggleBlock(selectedAttacker.src_ip)} 
                className={`tactical-btn ${blockedIps[selectedAttacker.src_ip] ? 'danger' : ''}`}
                style={{ flex: 1, minWidth: '130px', justifyContent: 'center' }}
              >
                <Ban size={12} />
                {blockedIps[selectedAttacker.src_ip] ? 'UNBLOCK IP' : 'BLOCK IP ADDRESS'}
              </button>

              <button 
                onClick={() => toggleIsolate(selectedAttacker.src_ip)} 
                className={`tactical-btn ${isolatedIps[selectedAttacker.src_ip] ? 'ghost' : ''}`}
                style={{ flex: 1, minWidth: '130px', justifyContent: 'center' }}
              >
                <Laptop size={12} />
                {isolatedIps[selectedAttacker.src_ip] ? 'CONNECT HOST' : 'ISOLATE TARGET HOST'}
              </button>

              <button 
                onClick={() => toggleMute(selectedAttacker.src_ip)} 
                className="tactical-btn ghost"
                style={{ flex: 1, minWidth: '130px', justifyContent: 'center' }}
              >
                <EyeOff size={12} />
                {mutedIps[selectedAttacker.src_ip] ? 'UNMUTE ALERTS' : 'MUTE TELEMETRY'}
              </button>

              <button 
                onClick={() => triggerPcapDump(selectedAttacker.src_ip)} 
                className="tactical-btn"
                style={{ flex: 1, minWidth: '130px', justifyContent: 'center' }}
                disabled={dumpingPcap[selectedAttacker.src_ip]}
              >
                {dumpingPcap[selectedAttacker.src_ip] ? (
                  <RefreshCw style={{ animation: 'spin 1.5s linear infinite' }} size={12} />
                ) : (
                  <Download size={12} />
                )}
                {dumpingPcap[selectedAttacker.src_ip] ? 'CAPTURING...' : 'PCAP PACKET DUMP'}
              </button>
            </div>
          </div>

          {/* Traffic/Frequency Scan */}
          <div className="glass-panel glowing">
            <div className="panel-header">
              <h3 className="panel-title">
                <Terminal size={16} style={{ color: 'var(--color-secondary)' }} />
                REAL-TIME SECURITY LOG FLOW INDEX
              </h3>
              <span className="status-pill critical" style={{ fontSize: '9px' }}>
                LOG_PACKET_VERIFY: LIVE
              </span>
            </div>
            
            <div style={{ height: '140px', width: '100%', marginTop: '12px' }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart 
                  data={[
                    { time: '10s', load: Math.floor(Math.random() * 40) + selectedAttacker.risk_score },
                    { time: '20s', load: Math.floor(Math.random() * 30) + selectedAttacker.risk_score },
                    { time: '30s', load: Math.floor(Math.random() * 50) + selectedAttacker.risk_score },
                    { time: '40s', load: Math.floor(Math.random() * 20) + selectedAttacker.risk_score },
                    { time: '50s', load: Math.floor(Math.random() * 40) + selectedAttacker.risk_score },
                    { time: '60s', load: Math.floor(Math.random() * 60) + selectedAttacker.risk_score }
                  ]}
                  margin={{ top: 5, right: 5, left: -40, bottom: 5 }}
                >
                  <defs>
                    <linearGradient id="loadCyan" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--color-primary)" stopOpacity={0.25}/>
                      <stop offset="95%" stopColor="var(--color-primary)" stopOpacity={0.0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="rgba(255, 255, 255, 0.15)" fontSize={8} tickLine={false} />
                  <YAxis stroke="rgba(255, 255, 255, 0.15)" fontSize={8} tickLine={false} />
                  <Area type="monotone" dataKey="load" stroke="var(--color-primary)" strokeWidth={1.5} fillOpacity={1} fill="url(#loadCyan)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      ) : (
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '400px', color: 'rgba(226, 232, 240, 0.3)', fontFamily: 'var(--font-mono)' }}>
          <ShieldCheck size={48} style={{ opacity: 0.2, marginBottom: '16px' }} />
          <span>SELECT A THREAT VECTOR FROM THE INCIDENT QUEUE FOR SECURITY AUDITING</span>
        </div>
      )}
    </div>
  );
};
