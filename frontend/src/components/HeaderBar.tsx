import { Search, Bell, Lock, User } from 'lucide-react';
import { useClock } from '../hooks/useClock';
import type { View } from '../types';

interface HeaderBarProps {
  activeView: View;
  onNavigate: (view: View) => void;
  searchQuery: string;
  onSearchChange: (query: string) => void;
}

// Navigation items shown in the top bar (matches sidebar for redundancy on wider screens)
const NAV_ITEMS: { label: string; view: View }[] = [
  { label: 'Dashboard',  view: 'dashboard' },
  { label: 'Attackers',  view: 'alerts'    },
  { label: 'Analytics',  view: 'mitre'     },
  { label: 'Monitoring', view: 'threatmap' },
];

/**
 * HeaderBar — Top command bar with branding, navigation links, UTC clock,
 * global threat search input and quick-action icon buttons.
 */
export function HeaderBar({ activeView, onNavigate, searchQuery, onSearchChange }: HeaderBarProps) {
  const utcTime = useClock();

  return (
    <header className="app-header-bar">
      {/* Branding + top-bar nav links */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '24px' }}>
        <span className="cti-title-glow glitch-text">CYBER THREAT INTELLIGENCE</span>

        <div style={{ display: 'flex', gap: '8px' }} className="hidden md:flex">
          {NAV_ITEMS.map(({ label, view }) => (
            <button
              key={view}
              className={`nav-link text-body-md font-bold px-3 py-2 ${
                activeView === view ? 'active text-primary' : 'text-on-surface-variant'
              }`}
              onClick={() => onNavigate(view)}
              style={{
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                fontFamily: 'var(--font-display)',
              }}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* UTC clock, search box and icon actions */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        {/* Live UTC clock */}
        <div
          className="hidden lg:block"
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            color: 'var(--color-primary)',
            borderRight: '1px solid rgba(255,255,255,0.1)',
            paddingRight: '16px',
          }}
        >
          {utcTime || 'SYNCHRONIZING CLOCK...'}
        </div>

        {/* Global threat search */}
        <div style={{ position: 'relative' }} className="hidden lg:block">
          <Search
            size={14}
            style={{ position: 'absolute', left: '12px', top: '10px', color: 'rgba(34,211,238,0.4)' }}
          />
          <input
            type="text"
            placeholder="GLOBAL THREAT SEARCH..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className="search-input"
            style={{ paddingLeft: '34px', width: '220px', borderRadius: '4px' }}
          />
        </div>

        {/* Quick-action icon buttons */}
        <div style={{ display: 'flex', gap: '8px', color: 'var(--color-primary)' }}>
          <button className="tactical-btn ghost" style={{ padding: '6px', border: 'none' }}>
            <Bell size={16} />
          </button>
          <button className="tactical-btn ghost" style={{ padding: '6px', border: 'none' }}>
            <Lock size={16} />
          </button>
          <button className="tactical-btn ghost" style={{ padding: '6px', border: 'none' }}>
            <User size={16} />
          </button>
        </div>
      </div>
    </header>
  );
}
