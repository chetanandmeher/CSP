import { useState, useEffect } from 'react';
import { HeaderBar } from './components/HeaderBar';
import { SidebarNav } from './components/SidebarNav';
import { FooterTicker } from './components/FooterTicker';
import { AttackerDetailsModal } from './components/AttackerDetailsModal';
import { DashboardView } from './components/DashboardView';
import { AlertsView } from './components/AlertsView';
import { MITREMatrixView } from './components/MITREMatrixView';
import { ThreatMapView } from './components/ThreatMapView';
import { useMouseGlow } from './hooks/useMouseGlow';
import './App.css';
import { apiService } from './services/api';
import type { Attacker, ForensicEvent } from './services/api';
import type { View } from './types';

// ─── Types ────────────────────────────────────────────────────────────────────


// ─── View registry ────────────────────────────────────────────────────────────

/** Maps each view key to its rendered component */
function renderView(view: View, onSelectAttacker: (ip: string) => void) {
  switch (view) {
    case 'dashboard': return <DashboardView onSelectAttacker={onSelectAttacker} />;
    case 'alerts':    return <AlertsView />;
    case 'mitre':     return <MITREMatrixView />;
    case 'threatmap': return <ThreatMapView />;
    default:          return <DashboardView onSelectAttacker={onSelectAttacker} />;
  }
}

// ─── App ──────────────────────────────────────────────────────────────────────

function App() {
  // ── Navigation state ──────────────────────────────────────────────────────
  const [activeView, setActiveView] = useState<View>('dashboard');
  const [searchQuery, setSearchQuery] = useState('');

  // ── Heuristic scan state ──────────────────────────────────────────────────
  const [isScanRunning, setIsScanRunning] = useState(false);
  const [scanStatus,    setScanStatus]    = useState('');

  // ── Selected attacker / modal state ──────────────────────────────────────
  const [selectedAttackerIp, setSelectedAttackerIp] = useState<string | null>(null);
  const [attackerDetails,    setAttackerDetails]    = useState<Attacker | null>(null);
  const [attackerEvents,     setAttackerEvents]     = useState<ForensicEvent[]>([]);
  const [eventsLoading,      setEventsLoading]      = useState(false);

  // ── Side effects ──────────────────────────────────────────────────────────

  // Attach the glass-panel mouse-glow effect; re-registers when view changes
  useMouseGlow(activeView);

  // Fetch attacker details + events whenever a new IP is selected
  useEffect(() => {
    if (!selectedAttackerIp) return;

    const fetchDetails = async () => {
      setEventsLoading(true);
      try {
        const [details, eventsResponse] = await Promise.all([
          apiService.getAttackerDetails(selectedAttackerIp),
          apiService.getAttackerEvents(selectedAttackerIp, 20),
        ]);
        setAttackerDetails(details as Attacker);
        setAttackerEvents(eventsResponse.results);
      } catch (err) {
        console.error('Failed to fetch attacker details', err);
      } finally {
        setEventsLoading(false);
      }
    };

    fetchDetails();
  }, [selectedAttackerIp]);

  // ── Handlers ──────────────────────────────────────────────────────────────

  /** Clears attacker selection, hiding the modal */
  const handleCloseModal = () => {
    setSelectedAttackerIp(null);
    setAttackerDetails(null);
    setAttackerEvents([]);
  };

  /** Simulates a heuristic scan with status message transitions */
  const handleInitiateScan = () => {
    if (isScanRunning) return;
    setIsScanRunning(true);
    setScanStatus('CONNECTING DECOY NODES...');

    setTimeout(() => {
      setScanStatus('INJECTING HEURISTICS...');
      setTimeout(() => {
        setScanStatus('ANALYST REPORT COMPLETED');
        setTimeout(() => {
          setIsScanRunning(false);
          setScanStatus('');
          alert('Global dynamic NIDS active heuristic trace completed. Zero active exploits discovered.');
        }, 1500);
      }, 1500);
    }, 1500);
  };

  /** Alert shown when the operator clicks "Disconnect" */
  const handleDisconnect = () => {
    alert('Terminating secure CTI operator session...');
  };

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="app-shell">
      {/* Top command bar */}
      <HeaderBar
        activeView={activeView}
        onNavigate={setActiveView}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
      />

      <div className="app-body-layout">
        {/* Left sidebar */}
        <SidebarNav
          activeView={activeView}
          onNavigate={setActiveView}
          isScanRunning={isScanRunning}
          scanStatus={scanStatus}
          onInitiateScan={handleInitiateScan}
          onDisconnect={handleDisconnect}
        />

        {/* Main content area */}
        <main className="app-main-canvas custom-scrollbar">
          {renderView(activeView, setSelectedAttackerIp)}

          {/* Attacker details modal — mounted only when an IP is selected */}
          {selectedAttackerIp && (
            <AttackerDetailsModal
              selectedIp={selectedAttackerIp}
              attackerDetails={attackerDetails}
              attackerEvents={attackerEvents}
              eventsLoading={eventsLoading}
              onClose={handleCloseModal}
            />
          )}
        </main>
      </div>

      {/* Scrolling telemetry footer */}
      <FooterTicker />
    </div>
  );
}

export default App;
