import { useState, useEffect } from 'react';
import {
  Shield, Radio, Globe, AlertTriangle,
  LogOut, Search, Bell, Lock, User,
  Cpu, Activity
} from 'lucide-react';
import { DashboardView } from './components/DashboardView';
import { AlertsView } from './components/AlertsView';
import { MITREMatrixView } from './components/MITREMatrixView';
import { ThreatMapView } from './components/ThreatMapView';
import './App.css';
import { apiService } from "./services/api";
import type { Attacker } from "./services/api";

function App() {
  const [activeView, setActiveView] = useState<'dashboard' | 'alerts' | 'mitre' | 'threatmap'>('dashboard');
  const [utcTime, setUtcTime] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [initiatedScan, setInitiatedScan] = useState(false);
  const [scanningStatus, setScanningStatus] = useState('');
  const [selectedAttackerIp, setSelectedAttackerIp] = useState<string | null>(null);
  const [attackerDetails, setAttackerDetails] = useState<Attacker | null>(null);
  const [attackerEvents, setAttackerEvents] = useState<any[]>([]);
  const [expandedEvent, setExpandedEvent] = useState<number | null>(null);
  const [eventsLoading, setEventsLoading] = useState(false);



  useEffect(() => {

    if (!selectedAttackerIp) return;

    const fetchAttackerDetails = async () => {
      setEventsLoading(true);
      try {
        const response = await apiService.getAttackerDetails(selectedAttackerIp);

        setAttackerDetails(response as Attacker);

        const eventsResponse =
          await apiService.getAttackerEvents(
            selectedAttackerIp,
            20
          );

        setAttackerEvents(eventsResponse.results);

      } catch (error) {

        console.error(
          "Failed to fetch attacker details",
          error
        );
      } finally {
        setEventsLoading(false);
      }
    };

    fetchAttackerDetails();

  }, [selectedAttackerIp]);

  // Dynamic UTC operational clock
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const format = now.toUTCString().replace('GMT', 'UTC');
      setUtcTime(format);
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Global mouse glow tracking for all active glass-panel items
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      const panels = document.querySelectorAll('.glass-panel');
      panels.forEach(panel => {
        const rect = panel.getBoundingClientRect();
        const glow = panel.querySelector('.mouse-glow') as HTMLElement;
        if (glow) {
          const x = e.clientX - rect.left;
          const y = e.clientY - rect.top;
          glow.style.left = `${x}px`;
          glow.style.top = `${y}px`;
        }
      });
    };

    window.addEventListener('mousemove', handleMouseMove);
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
    };
  }, [activeView]);

  // Initiate dynamic threat scanning trigger
  const handleInitiateScan = () => {
    if (initiatedScan) return;
    setInitiatedScan(true);
    setScanningStatus('CONNECTING DECOY NODES...');

    setTimeout(() => {
      setScanningStatus('INJECTING HEURISTICS...');
      setTimeout(() => {
        setScanningStatus('ANALYST REPORT COMPLETED');
        setTimeout(() => {
          setInitiatedScan(false);
          setScanningStatus('');
          alert('Global dynamic NIDS active heuristic trace completed. Zero active exploits discovered.');
        }, 1500);
      }, 1500);
    }, 1500);
  };

  // Render sub-view component canvas
  const renderCanvas = () => {
    switch (activeView) {

      case 'dashboard':
        return (
          <DashboardView
            onSelectAttacker={(ip) => {
              setSelectedAttackerIp(ip);
            }}
          />
        );

      case 'alerts':
        return <AlertsView />;

      case 'mitre':
        return <MITREMatrixView />;

      case 'threatmap':
        return <ThreatMapView />;

      default:
        return (
          <DashboardView
            onSelectAttacker={(ip) => {
              setSelectedAttackerIp(ip);
            }}
          />
        );
    }
  };

  return (
    <div className="app-shell">
      {/* Top Main Command Bar */}
      <header className="app-header-bar">
        <div style={{ display: 'flex', alignItems: 'center', gap: '24px' }}>
          <span className="cti-title-glow glitch-text">
            CYBER THREAT INTELLIGENCE
          </span>
          <div style={{ display: 'flex', gap: '8px' }} className="hidden md:flex">
            <button
              className={`nav-link text-body-md font-bold px-3 py-2 ${activeView === 'dashboard' ? 'active text-primary' : 'text-on-surface-variant'}`}
              onClick={() => setActiveView('dashboard')}
              style={{ background: 'transparent', border: 'none', cursor: 'pointer', fontFamily: 'var(--font-display)' }}
            >
              Dashboard
            </button>
            <button
              className={`nav-link text-body-md font-bold px-3 py-2 ${activeView === 'alerts' ? 'active text-primary' : 'text-on-surface-variant'}`}
              onClick={() => setActiveView('alerts')}
              style={{ background: 'transparent', border: 'none', cursor: 'pointer', fontFamily: 'var(--font-display)' }}
            >
              Attackers
            </button>
            <button
              className={`nav-link text-body-md font-bold px-3 py-2 ${activeView === 'mitre' ? 'active text-primary' : 'text-on-surface-variant'}`}
              onClick={() => setActiveView('mitre')}
              style={{ background: 'transparent', border: 'none', cursor: 'pointer', fontFamily: 'var(--font-display)' }}
            >
              Analytics
            </button>
            <button
              className={`nav-link text-body-md font-bold px-3 py-2 ${activeView === 'threatmap' ? 'active text-primary' : 'text-on-surface-variant'}`}
              onClick={() => setActiveView('threatmap')}
              style={{ background: 'transparent', border: 'none', cursor: 'pointer', fontFamily: 'var(--font-display)' }}
            >
              Monitoring
            </button>
          </div>
        </div>

        {/* Dynamic clocks and search tools */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--color-primary)', borderRight: '1px solid rgba(255, 255, 255, 0.1)', paddingRight: '16px' }} className="hidden lg:block">
            {utcTime || 'SYNCHRONIZING CLOCK...'}
          </div>

          <div style={{ position: 'relative' }} className="hidden lg:block">
            <Search style={{ position: 'absolute', left: '12px', top: '10px', color: 'rgba(34, 211, 238, 0.4)' }} size={14} />
            <input
              type="text"
              placeholder="GLOBAL THREAT SEARCH..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="search-input"
              style={{ paddingLeft: '34px', width: '220px', borderRadius: '4px' }}
            />
          </div>

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

      {/* Main Container Dashboard split */}
      <div className="app-body-layout">

        {/* Sidebar administrative Navigation */}
        <aside className="app-sidebar-nav">
          <div style={{ marginBottom: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '12px', background: 'rgba(46, 52, 71, 0.2)', border: '1px solid rgba(255, 255, 255, 0.05)', borderRadius: '4px' }}>
              <div style={{ width: '40px', height: '40px', background: 'rgba(34, 211, 238, 0.1)', color: 'var(--color-primary)', display: 'flex', alignItems: 'center', justifyItems: 'center', justifyContent: 'center' }}>
                <Shield size={20} style={{ animation: 'pulse 2s infinite' }} />
              </div>
              <div>
                <p style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', fontWeight: 700, color: 'var(--color-primary)', margin: 0 }}>OPERATIONS</p>
                <p style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'rgba(226, 232, 240, 0.4)', margin: 0 }}>Sector-7 Alpha</p>
              </div>
            </div>
          </div>

          <nav style={{ flex: 1 }}>
            <button
              className={`sidebar-btn ${activeView === 'dashboard' ? 'active' : ''}`}
              onClick={() => setActiveView('dashboard')}
            >
              <Radio size={14} />
              <span>Overview</span>
            </button>
            <button
              className={`sidebar-btn ${activeView === 'threatmap' ? 'active' : ''}`}
              onClick={() => setActiveView('threatmap')}
            >
              <Globe size={14} />
              <span>Threat Map</span>
            </button>
            <button
              className={`sidebar-btn ${activeView === 'alerts' ? 'active' : ''}`}
              onClick={() => setActiveView('alerts')}
            >
              <AlertTriangle size={14} />
              <span>Active Alerts</span>
            </button>
            <button
              className={`sidebar-btn ${activeView === 'mitre' ? 'active' : ''}`}
              onClick={() => setActiveView('mitre')}
            >
              <Cpu size={14} />
              <span>MITRE Matrix</span>
            </button>
          </nav>

          {/* System dynamic triggers */}
          <div style={{ marginTop: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <button
              onClick={handleInitiateScan}
              className="tactical-btn"
              disabled={initiatedScan}
              style={{
                width: '100%',
                padding: '12px',
                justifyContent: 'center',
                background: initiatedScan ? 'transparent' : 'var(--color-primary)',
                color: initiatedScan ? 'var(--color-primary)' : 'var(--surface-black)',
                boxShadow: initiatedScan ? 'none' : '0 0 15px rgba(34, 211, 238, 0.3)'
              }}
            >
              <Activity size={12} style={{ animation: initiatedScan ? 'spin 1.5s linear infinite' : 'none' }} />
              {initiatedScan ? scanningStatus : 'INITIATE HEURISTIC SCAN'}
            </button>
            <button
              className="sidebar-btn"
              style={{ color: 'rgba(244, 63, 94, 0.65)' }}
              onClick={() => alert('Terminating secure CTI operator session...')}
            >
              <LogOut size={14} />
              <span>Disconnect</span>
            </button>
          </div>
        </aside>

        {/* Main Canvas Workspace Pane */}
        <main className="app-main-canvas custom-scrollbar">
          {renderCanvas()}
          {selectedAttackerIp && (
            <div
              style={{
                position: 'fixed',
                inset: 0,
                background: 'rgba(0,0,0,0.72)',
                backdropFilter: 'blur(8px)',
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                zIndex: 9999,
                padding: '40px'
              }}
            >
              <div
                onClick={(e) => e.stopPropagation()}
                style={{
                  width: '90%',
                  maxWidth: '1500px',
                  height: '90vh',
                  background: 'linear-gradient(180deg, #07111f 0%, #0b1728 100%)',
                  border: '1px solid rgba(0,255,255,0.12)',
                  borderRadius: '24px',
                  overflow: 'auto',
                  display: 'flex',
                  flexDirection: 'column',
                  boxShadow: '0 0 40px rgba(0,255,255,0.08)',
                  overflowY: 'scroll',
                  scrollbarWidth: 'thin',
                }}
              >

                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: '24px'
                  }}
                >
                  <div>
                    <h2
                      style={{
                        margin: 0,
                        fontSize: '32px',
                        fontWeight: 700,
                        color: '#ffffff'
                      }}
                    >
                      Attacker Details
                    </h2>

                    <div
                      style={{
                        marginTop: '14px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '12px'
                      }}
                    >

                      <div
                        style={{
                          width: '12px',
                          height: '12px',
                          borderRadius: '50%',
                          background: '#ff355e',
                          boxShadow: '0 0 14px #ff355e'
                        }}
                      />

                      <div
                        style={{
                          padding: '8px 16px',
                          borderRadius: '10px',
                          background:
                            'linear-gradient(90deg, rgba(255,53,94,0.2), rgba(255,53,94,0.08))',
                          border: '1px solid rgba(255,53,94,0.4)',
                          color: '#ff4d6d',
                          fontWeight: 700,
                          fontSize: '13px',
                          letterSpacing: '1px',
                          textTransform: 'uppercase'
                        }}
                      >
                        Critical Threat Actor
                      </div>

                    </div>
                  </div>

                  <button
                    onClick={() => setSelectedAttackerIp(null)}
                    style={{
                      background: 'transparent',
                      border: 'none',
                      color: '#9fb3c8',
                      fontSize: '24px',
                      cursor: 'pointer'
                    }}
                  >
                    ✕
                  </button>
                </div>
                <div>
                  <div
                    style={{
                      marginBottom: '24px',
                      padding: '16px',
                      borderRadius: '14px',
                      background: 'rgba(255,255,255,0.03)',
                      border: '1px solid rgba(255,255,255,0.05)'
                    }}
                  >
                    <div
                      style={{
                        fontSize: '12px',
                        color: '#7f8ea3',
                        marginBottom: '6px',
                        textTransform: 'uppercase'
                      }}
                    >
                      IP Address
                    </div>

                    <div
                      style={{
                        fontSize: '28px',
                        fontWeight: 700,
                        color: '#ffffff'
                      }}
                    >
                      {selectedAttackerIp}
                    </div>
                  </div>

                  {attackerDetails && (
                    <>
                      <div
                        style={{
                          display: 'grid',
                          gridTemplateColumns: '380px 1fr',
                          gap: '24px',
                          alignItems: 'start',
                          marginTop: '24px'
                        }}
                      >
                        <div
                          style={{
                            display: 'grid',
                            gridTemplateColumns: '1fr 1fr',
                            gap: '16px',
                            marginBottom: '24px'
                          }}
                        >
                          <div
                            style={{
                              padding: '18px',
                              borderRadius: '14px',
                              background: 'rgba(255,255,255,0.03)',
                              border: '1px solid rgba(255,255,255,0.05)'
                            }}
                          >
                            <div
                              style={{
                                fontSize: '12px',
                                color: '#7f8ea3',
                                marginBottom: '10px'
                              }}
                            >
                              RISK SCORE
                            </div>

                            <div
                              style={{
                                fontSize: '38px',
                                fontWeight: 700,
                                color: '#ff4d6d'
                              }}
                            >
                              {attackerDetails.risk_score}
                            </div>
                          </div>

                          <div
                            style={{
                              padding: '18px',
                              borderRadius: '14px',
                              background: 'rgba(255,255,255,0.03)',
                              border: '1px solid rgba(255,255,255,0.05)'
                            }}
                          >
                            <div
                              style={{
                                fontSize: '12px',
                                color: '#7f8ea3',
                                marginBottom: '10px'
                              }}
                            >
                              THREAT LEVEL
                            </div>

                            <div
                              style={{
                                fontSize: '28px',
                                fontWeight: 700,
                                color: '#ff4d6d',
                                textTransform: 'uppercase'
                              }}
                            >
                              {attackerDetails.threat_level}
                            </div>
                          </div>

                          <div
                            style={{
                              padding: '18px',
                              borderRadius: '14px',
                              background: 'rgba(255,255,255,0.03)',
                              border: '1px solid rgba(255,255,255,0.05)'
                            }}
                          >
                            <div
                              style={{
                                fontSize: '12px',
                                color: '#7f8ea3',
                                marginBottom: '10px'
                              }}
                            >
                              TOTAL EVENTS
                            </div>

                            <div
                              style={{
                                fontSize: '34px',
                                fontWeight: 700,
                                color: '#00e5ff'
                              }}
                            >
                              {attackerDetails.total_events}
                            </div>
                          </div>

                          <div
                            style={{
                              padding: '18px',
                              borderRadius: '14px',
                              background: 'rgba(255,255,255,0.03)',
                              border: '1px solid rgba(255,255,255,0.05)'
                            }}
                          >
                            <div
                              style={{
                                fontSize: '12px',
                                color: '#7f8ea3',
                                marginBottom: '10px'
                              }}
                            >
                              UNIQUE TECHNIQUES
                            </div>

                            <div
                              style={{
                                fontSize: '34px',
                                fontWeight: 700,
                                color: '#00e5ff'
                              }}
                            >
                              {attackerDetails.unique_techniques}
                            </div>
                          </div>
                        </div>

                        <div
                          style={{
                            padding: '18px',
                            borderRadius: '14px',
                            background: 'rgba(255,255,255,0.03)',
                            border: '1px solid rgba(255,255,255,0.05)',
                            marginBottom: '24px'
                          }}
                        >
                          <div
                            style={{
                              fontSize: '14px',
                              color: '#7f8ea3',
                              marginBottom: '16px',
                              textTransform: 'uppercase'
                            }}
                          >
                            Threat Intelligence Summary
                          </div>

                          <div style={{ lineHeight: 1.8 }}>
                            <div>
                              • Risk Score:
                              {' '}
                              <span style={{ color: '#ff4d6d' }}>
                                {attackerDetails.risk_score}
                              </span>
                            </div>

                            <div>
                              • Threat Level:
                              {' '}
                              <span style={{ color: '#ff4d6d' }}>
                                {attackerDetails.threat_level}
                              </span>
                            </div>

                            <div>
                              • Total Events:
                              {' '}
                              <span style={{ color: '#00e5ff' }}>
                                {attackerDetails.total_events}
                              </span>
                            </div>

                            <div>
                              • Unique Techniques:
                              {' '}
                              <span style={{ color: '#00e5ff' }}>
                                {attackerDetails.unique_techniques}
                              </span>
                              {attackerDetails.geo && (
                                <div
                                  style={{
                                    marginTop: '20px',
                                    paddingTop: '16px',
                                    borderTop: '1px solid rgba(255,255,255,0.08)'
                                  }}
                                >

                                  <div
                                    style={{
                                      fontSize: '13px',
                                      color: '#7f8ea3',
                                      marginBottom: '14px',
                                      textTransform: 'uppercase',
                                      letterSpacing: '1px'
                                    }}
                                  >
                                    Geo Intelligence
                                  </div>

                                  <div
                                    style={{
                                      display: 'grid',
                                      gap: '10px'
                                    }}
                                  >

                                    <div>
                                      🌍
                                      {' '}
                                      <span style={{ color: '#00e5ff' }}>
                                        {attackerDetails.geo.country}
                                      </span>
                                    </div>

                                    <div>
                                      🏙️
                                      {' '}
                                      {attackerDetails.geo.city},
                                      {' '}
                                      {attackerDetails.geo.region}
                                    </div>

                                    <div>
                                      🛰️
                                      {' '}
                                      {attackerDetails.geo.isp}
                                    </div>

                                    <div>
                                      🧠
                                      {' '}
                                      {attackerDetails.geo.asn}
                                    </div>

                                  </div>

                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                      <div
                        style={{
                          marginTop: '24px',
                          padding: '18px',
                          borderRadius: '14px',
                          background: 'rgba(255,255,255,0.03)',
                          border: '1px solid rgba(255,255,255,0.05)'
                        }}
                      >

                        <div
                          style={{
                            fontSize: '14px',
                            color: '#7f8ea3',
                            marginBottom: '16px',
                            textTransform: 'uppercase'
                          }}
                        >
                          Live Forensic Timeline
                        </div>

                        {eventsLoading ? (

                          <div style={{ color: '#00e5ff' }}>
                            Loading forensic telemetry...
                          </div>

                        ) : (

                          <div
                            style={{
                              maxHeight: '280px',
                              overflowY: 'auto',
                              display: 'flex',
                              flexDirection: 'column',
                              gap: '12px'
                            }}
                          >

                            {attackerEvents.map((event, index) => (

                              <div
                                key={index}
                                onClick={() =>
                                  setExpandedEvent(
                                    expandedEvent === index
                                      ? null
                                      : index
                                  )
                                }
                                style={{
                                  padding: '12px',
                                  borderRadius: '10px',
                                  background: 'rgba(255,255,255,0.02)',
                                  border:
                                    '1px solid rgba(255,255,255,0.05)',
                                  cursor: 'pointer'
                                }}
                              >

                                <div
                                  style={{
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    marginBottom: '8px',
                                    fontSize: '11px'
                                  }}
                                >

                                  <div
                                    style={{
                                      color:
                                        event.source_type === 'suricata'
                                          ? '#ff4d6d'
                                          : '#00e5ff',
                                      fontWeight: 700,
                                      textTransform: 'uppercase'
                                    }}
                                  >
                                    {event.source_type}
                                  </div>

                                  <div
                                    style={{
                                      color: '#7f8ea3'
                                    }}
                                  >
                                    {new Date(
                                      event.timestamp
                                    ).toLocaleTimeString()}
                                  </div>

                                </div>

                                <div
                                  style={{
                                    color: '#d6e2f0',
                                    fontSize: '12px',
                                    lineHeight: 1.6
                                  }}
                                >
                                  {event.alert_signature}
                                </div>

                                {event.cve_id && (

                                  <div
                                    style={{
                                      marginTop: '10px',
                                      color: '#ff4d6d',
                                      fontSize: '11px',
                                      fontWeight: 700
                                    }}
                                  >
                                    🔥 {event.cve_id}
                                  </div>

                                )}

                                {event.technique_id && (

                                  <div
                                    style={{
                                      marginTop: '6px',
                                      color: '#00e5ff',
                                      fontSize: '11px',
                                      fontWeight: 700
                                    }}
                                  >
                                    🛡️ MITRE {event.technique_id}
                                  </div>

                                )}

                                {expandedEvent === index && (

                                  <div
                                    style={{
                                      marginTop: '14px',
                                      paddingTop: '14px',
                                      borderTop:
                                        '1px solid rgba(255,255,255,0.08)',
                                      display: 'flex',
                                      flexDirection: 'column',
                                      gap: '10px'
                                    }}
                                  >

                                    <div>
                                      <span style={{ color: '#7f8ea3' }}>
                                        Source IP:
                                      </span>
                                      {' '}
                                      {event.src_ip}
                                    </div>

                                    <div>
                                      <span style={{ color: '#7f8ea3' }}>
                                        Destination IP:
                                      </span>
                                      {' '}
                                      {event.dest_ip || 'N/A'}
                                    </div>

                                    <div>
                                      <span style={{ color: '#7f8ea3' }}>
                                        Protocol:
                                      </span>
                                      {' '}
                                      {event.proto || 'N/A'}
                                    </div>

                                    <div>
                                      <span style={{ color: '#7f8ea3' }}>
                                        Technique:
                                      </span>
                                      {' '}
                                      {event.technique_name || 'Unknown'}
                                    </div>
                                    
                                    {event.technique_description && (

                                      <div
                                        style={{
                                          marginTop: '12px',
                                          padding: '12px',
                                          borderRadius: '10px',
                                          background:
                                            'rgba(0,229,255,0.05)',
                                          border:
                                            '1px solid rgba(0,229,255,0.12)'
                                        }}
                                      >

                                        <div
                                          style={{
                                            color: '#00e5ff',
                                            fontWeight: 700,
                                            marginBottom: '8px'
                                          }}
                                        >
                                          MITRE ATT&CK Intelligence
                                        </div>

                                        <div
                                          style={{
                                            color: '#c7d5e0',
                                            lineHeight: 1.7,
                                            fontSize: '13px'
                                          }}
                                        >
                                          {event.technique_description}
                                        </div>

                                        {event.technique_url && (

                                          <a
                                            href={event.technique_url}
                                            target="_blank"
                                            rel="noreferrer"
                                            style={{
                                              display: 'inline-block',
                                              marginTop: '12px',
                                              color: '#00e5ff',
                                              textDecoration: 'none',
                                              fontWeight: 700
                                            }}
                                          >
                                            View MITRE ATT&CK →
                                          </a>

                                        )}

                                      </div>

                                    )}

                                    {event.cve_details && (

                                      <div
                                        style={{
                                          marginTop: '10px',
                                          padding: '12px',
                                          borderRadius: '10px',
                                          background:
                                            'rgba(255,77,109,0.08)',
                                          border:
                                            '1px solid rgba(255,77,109,0.15)'
                                        }}
                                      >

                                        <div
                                          style={{
                                            color: '#ff4d6d',
                                            fontWeight: 700,
                                            marginBottom: '8px'
                                          }}
                                        >
                                          CVE Intelligence
                                        </div>

                                        <div>
                                          CVSS:
                                          {' '}
                                          {event.cve_details.base_score}
                                        </div>

                                        <div>
                                          Severity:
                                          {' '}
                                          {event.cve_details.base_severity}
                                        </div>

                                        <div>
                                          Attack Vector:
                                          {' '}
                                          {event.cve_details.attack_vector}
                                        </div>

                                      </div>

                                    )}

                                  </div>

                                )}
                                {event.tactic && (

                                  <div
                                    style={{
                                      marginTop: '10px',
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      padding: '6px 12px',
                                      borderRadius: '999px',
                                      background:
                                        'linear-gradient(90deg, rgba(0,229,255,0.18), rgba(0,229,255,0.06))',
                                      border: '1px solid rgba(0,229,255,0.25)',
                                      color: '#00e5ff',
                                      fontSize: '10px',
                                      fontWeight: 700,
                                      textTransform: 'uppercase',
                                      letterSpacing: '1px'
                                    }}
                                  >
                                    {event.tactic}
                                  </div>

                                )}

                              </div>

                            ))}

                          </div>

                        )}

                      </div>
                      <div
                        style={{
                          marginTop: '24px',
                          display: 'grid',
                          gridTemplateColumns: '1fr 1fr',
                          gap: '12px'
                        }}
                      >
                        <div>
                          <button
                            style={{
                              padding: '14px',
                              borderRadius: '12px',
                              border: '1px solid rgba(255,53,94,0.35)',
                              background:
                                'linear-gradient(180deg, rgba(255,53,94,0.16), rgba(255,53,94,0.05))',
                              color: '#ff4d6d',
                              fontWeight: 700,
                              cursor: 'pointer',
                              letterSpacing: '0.5px'
                            }}
                          >
                            ISOLATE HOST
                          </button>
                        </div>

                        <div
                          style={{
                            display: 'flex',
                            gap: '12px'
                          }}
                        >
                          <button
                            style={{
                              padding: '14px',
                              borderRadius: '12px',
                              border: '1px solid rgba(0,229,255,0.25)',
                              background:
                                'linear-gradient(180deg, rgba(0,229,255,0.14), rgba(0,229,255,0.04))',
                              color: '#00e5ff',
                              fontWeight: 700,
                              cursor: 'pointer',
                              letterSpacing: '0.5px'
                            }}
                          >
                            EXPORT IOC
                          </button>

                          <button
                            style={{
                              padding: '14px',
                              borderRadius: '12px',
                              border: '1px solid rgba(255,255,255,0.08)',
                              background:
                                'rgba(255,255,255,0.03)',
                              color: '#d6e2f0',
                              fontWeight: 600,
                              cursor: 'pointer'
                            }}
                          >
                            OPEN TIMELINE
                          </button>

                          <button
                            style={{
                              padding: '14px',
                              borderRadius: '12px',
                              border: '1px solid rgba(255,255,255,0.08)',
                              background:
                                'rgba(255,255,255,0.03)',
                              color: '#d6e2f0',
                              fontWeight: 600,
                              cursor: 'pointer'
                            }}
                          >
                            GENERATE REPORT
                          </button>

                        </div>
                      </div>
                    </>
                  )}
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Scrolling dynamic Telemetry Log Stream */}
      <footer className="app-footer-ticker">
        <div className="ticker-scroll" style={{ whiteSpace: 'nowrap' }}>
          <div style={{ display: 'flex', gap: '32px', paddingRight: '32px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'rgba(226, 232, 240, 0.65)' }}>
            <span style={{ color: 'var(--color-primary)' }}>[SYSTEM MONITOR ONLINE]</span>
            <span>NODE_ALPHA_01: CPU 12% | LATENCY 14ms | DATABASE SPEEDUP 120X</span>
            <span style={{ color: 'var(--color-danger)' }}>[WARN] SSH BRUTE FORCE DETECTED FROM IP 85.203.47.112</span>
            <span>CTI_THREAT_FEED: NEW RANSOMWARE VARIANT &apos;CYPHER&apos; IDENTIFIED BY ENTRUST</span>
            <span>TELEMETRY RATE: 1,840 PKTS/SEC | STREAM CIPHER: AES-256-GCM</span>
            <span style={{ color: 'var(--color-success)' }}>[INFO] MITRE HEATMAP METRICS DYNAMICALLY COMPILED</span>
            <span>OPERATING MODE: FULL SECURE BACKEND INTEGRATION CHANNELS ACTIVE</span>
          </div>
          <div style={{ display: 'flex', gap: '32px', paddingRight: '32px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'rgba(226, 232, 240, 0.65)' }}>
            <span style={{ color: 'var(--color-primary)' }}>[SYSTEM MONITOR ONLINE]</span>
            <span>NODE_ALPHA_01: CPU 12% | LATENCY 14ms | DATABASE SPEEDUP 120X</span>
            <span style={{ color: 'var(--color-danger)' }}>[WARN] SSH BRUTE FORCE DETECTED FROM IP 85.203.47.112</span>
            <span>CTI_THREAT_FEED: NEW RANSOMWARE VARIANT &apos;CYPHER&apos; IDENTIFIED BY ENTRUST</span>
            <span>TELEMETRY RATE: 1,840 PKTS/SEC | STREAM CIPHER: AES-256-GCM</span>
            <span style={{ color: 'var(--color-success)' }}>[INFO] MITRE HEATMAP METRICS DYNAMICALLY COMPILED</span>
            <span>OPERATING MODE: FULL SECURE BACKEND INTEGRATION CHANNELS ACTIVE</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
