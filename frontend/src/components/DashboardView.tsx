import React, { useState, useEffect } from 'react';
import { apiService } from '../services/api';
import type { Attacker, DashboardSummary, AttackTactic } from '../services/api';
import {
  ShieldAlert, Activity,
  TrendingUp, TrendingDown, ShieldX, UserX,
  RefreshCw, Radio
} from 'lucide-react';
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip,
  AreaChart, Area
} from 'recharts';

export const DashboardView: React.FC<{
  onSelectAttacker: (ip: string) => void;
}> = ({ onSelectAttacker }) => {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [tactics, setTactics] = useState<AttackTactic[]>([]);
  const [criticalAttackers, setCriticalAttackers] = useState<Attacker[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [isolatedHosts, setIsolatedHosts] = useState<Record<string, boolean>>({});

  const loadData = async () => {
    try {
      const [sumData, tacticsData, critData] = await Promise.all([
        apiService.getDashboardSummary(),
        apiService.getTopTactics(8),
        apiService.getCriticalAttackers(5)
      ]);
      setSummary(sumData);
      setTactics(tacticsData.results);
      setCriticalAttackers(critData.results);
    } catch (err) {
      console.error('Error fetching dashboard statistics', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
  };

  const toggleIsolation = (ip: string) => {
    setIsolatedHosts(prev => ({
      ...prev,
      [ip]: !prev[ip]
    }));
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '400px', gap: '16px', fontFamily: 'var(--font-mono)' }}>
        <RefreshCw style={{ animation: 'spin 1.5s linear infinite', color: 'var(--color-primary)' }} size={32} />
        <span>INITIALIZING THREAT INTELLIGENCE FEED...</span>
      </div>
    );
  }

  // Combined events count
  const totalEvents = summary ? summary.total_suricata_events + summary.total_cowrie_events : 0;

  // Chart Gradient definitions
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div style={{ background: 'var(--surface-black)', border: 'var(--border-glow)', padding: '12px', fontFamily: 'var(--font-mono)', fontSize: '11px', boxShadow: 'var(--shadow-neon)' }}>
          <p style={{ margin: 0, color: '#ffffff', fontWeight: 700 }}>{label}</p>
          <p style={{ margin: '4px 0 0', color: 'var(--color-primary)' }}>
            Exploits: <span style={{ color: '#ffffff' }}>{payload[0].value.toLocaleString()}</span>
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-lg)' }}>
      {/* Top Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'rgba(255, 255, 255, 0.6)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
          <Radio style={{ color: 'var(--color-primary)', animation: 'pulse 1.8s infinite' }} size={14} />
          <span>LIVE SOC CENTRAL ORCHESTRATION LAYER ACTIVE</span>
        </div>
        <button onClick={handleRefresh} className="tactical-btn" style={{ gap: '6px' }} disabled={refreshing}>
          <RefreshCw style={{ animation: refreshing ? 'spin 1.5s linear infinite' : 'none' }} size={12} />
          {refreshing ? 'REFRESHING...' : 'REFRESH INTEL'}
        </button>
      </div>

      {/* KPI Panel Grid */}
      <div className="kpi-grid">
        <div className="glass-panel kpi-card cyan glowing">
          <div className="kpi-label">Active Threat Actors</div>
          <div className="kpi-value-container">
            <span className="kpi-value">{summary?.total_attackers ?? 0}</span>
            <span className="kpi-trend up"><TrendingUp size={12} /> +12.4%</span>
          </div>
          <div style={{ fontSize: '11px', color: 'rgba(226, 232, 240, 0.4)', display: 'flex', justifyContent: 'space-between', marginTop: '8px', fontFamily: 'var(--font-mono)' }}>
            <span>MUTED: 2</span>
            <span>BLOCKED: 18</span>
          </div>
        </div>

        <div className="glass-panel kpi-card red glowing">
          <div className="kpi-label">Critical Intrusion Hosts</div>
          <div className="kpi-value-container">
            <span className="kpi-value">{summary?.critical_attackers || 0}</span>
            <span className="kpi-trend up"><TrendingUp size={12} /> +8.3%</span>
          </div>
          <div style={{ fontSize: '11px', color: 'rgba(226, 232, 240, 0.4)', display: 'flex', justifyContent: 'space-between', marginTop: '8px', fontFamily: 'var(--font-mono)' }}>
            <span>ISOLATED: {Object.values(isolatedHosts).filter(Boolean).length}</span>
            <span>BREACH LIMIT: 10</span>
          </div>
        </div>

        <div className="glass-panel kpi-card purple glowing">
          <div className="kpi-label">Aggregated NIDS Telemetry</div>
          <div className="kpi-value-container">
            <span className="kpi-value">{totalEvents.toLocaleString()}</span>
            <span className="kpi-trend down"><TrendingDown size={12} /> -2.1%</span>
          </div>
          <div style={{ fontSize: '11px', color: 'rgba(226, 232, 240, 0.4)', display: 'flex', justifyContent: 'space-between', marginTop: '8px', fontFamily: 'var(--font-mono)' }}>
            <span>SURICATA: {summary?.total_suricata_events.toLocaleString()}</span>
            <span>COWRIE: {summary?.total_cowrie_events.toLocaleString()}</span>
          </div>
        </div>

        <div className="glass-panel kpi-card green glowing">
          <div className="kpi-label">Top Threat Vector</div>
          <div className="kpi-value-container" style={{ margin: '6px 0' }}>
            <span style={{ fontSize: '15px', fontWeight: 800, color: '#ffffff', fontFamily: 'var(--font-display)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '160px' }}>
              {summary?.top_tactic || 'N/A'}
            </span>
            <span className="status-pill critical" style={{ fontSize: '9px', padding: '1px 4px' }}>MITRE</span>
          </div>
          <div style={{ fontSize: '11px', color: 'rgba(226, 232, 240, 0.4)', display: 'flex', justifyContent: 'space-between', marginTop: '8px', fontFamily: 'var(--font-mono)' }}>
            <span>TACTICAL RANGE: L1-L4</span>
            <span>DENSITY: HIGH</span>
          </div>
        </div>
      </div>

      {/* Double Column Graph Panel */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))', gap: 'var(--spacing-lg)' }}>
        {/* Tactics Distribution BarChart */}
        <div className="glass-panel glowing">
          <div className="panel-header">
            <h3 className="panel-title">
              <ShieldAlert size={16} style={{ color: 'var(--color-primary)' }} />
              MITRE ATT&CK TACTICS DISTRIBUTION
            </h3>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--color-primary)' }}>NIDS EVENTS</span>
          </div>
          <div style={{ width: '100%', height: '240px', marginTop: '12px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={tactics} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="barCyan" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--color-primary)" stopOpacity={0.8} />
                    <stop offset="95%" stopColor="var(--color-secondary)" stopOpacity={0.1} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="tactic" stroke="rgba(255, 255, 255, 0.2)" fontSize={9} fontFamily="var(--font-mono)" tickLine={false} />
                <YAxis stroke="rgba(255, 255, 255, 0.2)" fontSize={9} fontFamily="var(--font-mono)" tickLine={false} />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255, 255, 255, 0.02)' }} />
                <Bar dataKey="occurrences" fill="url(#barCyan)" stroke="var(--color-primary)" strokeWidth={1} radius={[0, 0, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Level Over Time AreaChart */}
        <div className="glass-panel glowing">
          <div className="panel-header">
            <h3 className="panel-title">
              <Activity size={16} style={{ color: 'var(--color-tertiary)' }} />
              THREAT SEVERITY FREQUENCY
            </h3>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--color-tertiary)' }}>REAL-TIME SCAN</span>
          </div>
          <div style={{ width: '100%', height: '240px', marginTop: '12px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={[
                  { time: '10:00', critical: 12, high: 45, medium: 72 },
                  { time: '11:00', critical: 18, high: 52, medium: 94 },
                  { time: '12:00', critical: 14, high: 61, medium: 110 },
                  { time: '13:00', critical: 24, high: 58, medium: 98 },
                  { time: '14:00', critical: 16, high: 75, medium: 122 },
                  { time: '15:00', critical: summary?.critical_attackers || 14, high: 82, medium: 140 }
                ]}
                margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="areaRed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--color-danger)" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="var(--color-danger)" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="areaAmber" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--color-warning)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="var(--color-warning)" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="rgba(255, 255, 255, 0.2)" fontSize={9} fontFamily="var(--font-mono)" tickLine={false} />
                <YAxis stroke="rgba(255, 255, 255, 0.2)" fontSize={9} fontFamily="var(--font-mono)" tickLine={false} />
                <Tooltip
                  contentStyle={{ background: 'var(--surface-black)', border: 'var(--border-glass)', fontFamily: 'var(--font-mono)', fontSize: '10px' }}
                  itemStyle={{ margin: 0 }}
                />
                <Area type="monotone" dataKey="critical" stroke="var(--color-danger)" strokeWidth={2} fillOpacity={1} fill="url(#areaRed)" name="Critical" />
                <Area type="monotone" dataKey="high" stroke="var(--color-warning)" strokeWidth={2} fillOpacity={1} fill="url(#areaAmber)" name="High" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Critical Host Threat Matrix Table */}
      <div className="glass-panel glowing">
        <div className="panel-header">
          <h3 className="panel-title">
            <ShieldX size={16} style={{ color: 'var(--color-danger)' }} />
            CRITICAL HOST ATTACK MATRIX
          </h3>
          <span className="status-pill critical" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span className="pulse-dot danger"></span>
            SECURITY BREACH THREAT LEVEL: SEC-LEVEL 5
          </span>
        </div>

        <div className="table-container">
          <table className="tactical-table">
            <thead>
              <tr>
                <th>TARGET HOST/IP</th>
                <th>THREAT LEVEL</th>
                <th>INTELLIGENCE RISK SCORE</th>
                <th>NIDS ALERTS</th>
                <th>HONEYPOT SENSORS</th>
                <th>UNIQUE ATT&CK PATHS</th>
                <th style={{ textAlign: 'right' }}>TACTICAL ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {criticalAttackers.map((attacker) => {
                const isIsolated = isolatedHosts[attacker.src_ip];
                return (
                  <tr key={attacker.src_ip} className={isIsolated ? 'active' : ''}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#ffffff' }}>
                      {attacker.src_ip}
                    </td>
                    <td>
                      <span className={`status-pill ${attacker.threat_level}`}>
                        {attacker.threat_level}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <div style={{ width: '80px', height: '4px', background: 'rgba(255, 255, 255, 0.05)', position: 'relative' }}>
                          <div style={{ height: '100%', width: `${attacker.risk_score}%`, background: 'linear-gradient(90deg, var(--color-warning), var(--color-danger))' }} />
                        </div>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--color-danger)', fontWeight: 700 }}>
                          {attacker.risk_score}/100
                        </span>
                      </div>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{attacker.suricata_events.toLocaleString()}</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{attacker.cowrie_events.toLocaleString()}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-primary)' }}>
                      {attacker.unique_techniques} tech / {attacker.unique_tactics} tact
                    </td>
                    <td style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                      <button
                        onClick={() => toggleIsolation(attacker.src_ip)}
                        className={`tactical-btn ${isIsolated ? 'ghost' : 'danger'}`}
                        style={{ padding: '4px 8px', fontSize: '10px' }}
                      >
                        <UserX size={10} />
                        {isIsolated ? 'RESTORE HOST' : 'ISOLATE HOST'}
                      </button>
                      <button
                        onClick={() => onSelectAttacker(attacker.src_ip)}
                        className="tactical-btn"
                        style={{ padding: '4px 8px', fontSize: '10px' }}
                      >
                        VIEW DETAILS
                      </button>

                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
