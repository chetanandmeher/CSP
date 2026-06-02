import { Shield, Radio, Globe, AlertTriangle, Cpu, Activity, LogOut } from 'lucide-react';
import type { View } from '../types';

interface SidebarNavProps {
  activeView: View;
  onNavigate: (view: View) => void;
  /** Whether a heuristic scan is currently in progress */
  isScanRunning: boolean;
  /** Status message displayed while a scan is running */
  scanStatus: string;
  onInitiateScan: () => void;
  onDisconnect: () => void;
}

// Sidebar navigation items — each maps a view key to an icon and label
const SIDEBAR_ITEMS: { view: View; icon: React.ReactNode; label: string }[] = [
  { view: 'dashboard', icon: <Radio size={14} />,        label: 'Overview'     },
  { view: 'threatmap', icon: <Globe size={14} />,        label: 'Threat Map'   },
  { view: 'alerts',    icon: <AlertTriangle size={14} />, label: 'Active Alerts' },
  { view: 'mitre',     icon: <Cpu size={14} />,           label: 'MITRE Matrix' },
];

/**
 * SidebarNav — Left-hand administrative navigation panel.
 * Renders the operator identity badge, view navigation buttons,
 * the heuristic scan trigger, and the disconnect button.
 */
export function SidebarNav({
  activeView,
  onNavigate,
  isScanRunning,
  scanStatus,
  onInitiateScan,
  onDisconnect,
}: SidebarNavProps) {
  return (
    <aside className="app-sidebar-nav">
      {/* Operator identity badge */}
      <div style={{ marginBottom: '24px' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '12px',
            background: 'rgba(46,52,71,0.2)',
            border: '1px solid rgba(255,255,255,0.05)',
            borderRadius: '4px',
          }}
        >
          <div
            style={{
              width: '40px',
              height: '40px',
              background: 'rgba(34,211,238,0.1)',
              color: 'var(--color-primary)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Shield size={20} style={{ animation: 'pulse 2s infinite' }} />
          </div>
          <div>
            <p style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', fontWeight: 700, color: 'var(--color-primary)', margin: 0 }}>
              OPERATIONS
            </p>
            <p style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'rgba(226,232,240,0.4)', margin: 0 }}>
              Sector-7 Alpha
            </p>
          </div>
        </div>
      </div>

      {/* View navigation links */}
      <nav style={{ flex: 1 }}>
        {SIDEBAR_ITEMS.map(({ view, icon, label }) => (
          <button
            key={view}
            className={`sidebar-btn ${activeView === view ? 'active' : ''}`}
            onClick={() => onNavigate(view)}
          >
            {icon}
            <span>{label}</span>
          </button>
        ))}
      </nav>

      {/* Bottom action buttons */}
      <div style={{ marginTop: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {/* Heuristic scan trigger */}
        <button
          onClick={onInitiateScan}
          className="tactical-btn"
          disabled={isScanRunning}
          style={{
            width: '100%',
            padding: '12px',
            justifyContent: 'center',
            background: isScanRunning ? 'transparent' : 'var(--color-primary)',
            color:  isScanRunning ? 'var(--color-primary)' : 'var(--surface-black)',
            boxShadow: isScanRunning ? 'none' : '0 0 15px rgba(34,211,238,0.3)',
          }}
        >
          <Activity size={12} style={{ animation: isScanRunning ? 'spin 1.5s linear infinite' : 'none' }} />
          {isScanRunning ? scanStatus : 'INITIATE HEURISTIC SCAN'}
        </button>

        {/* Disconnect */}
        <button
          className="sidebar-btn"
          style={{ color: 'rgba(244,63,94,0.65)' }}
          onClick={onDisconnect}
        >
          <LogOut size={14} />
          <span>Disconnect</span>
        </button>
      </div>
    </aside>
  );
}
