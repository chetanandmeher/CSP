import React from 'react';
import type { Attacker, ForensicEvent } from '../services/api';

interface AttackerDetailsModalProps {
  /** The IP of the currently selected attacker, used as the modal title */
  selectedIp: string;
  /** Full attacker record fetched from the API (null while loading) */
  attackerDetails: Attacker | null;
  /** Forensic events belonging to this attacker */
  attackerEvents: ForensicEvent[];
  /** Whether the events list is still being fetched */
  eventsLoading: boolean;
  /** Called when the user closes the modal */
  onClose: () => void;
}

// ─── Small sub-components ────────────────────────────────────────────────────

/** A single stat card shown in the 2×2 metrics grid */
function StatCard({
  label,
  value,
  valueColor,
  valueFontSize = '34px',
}: {
  label: string;
  value: React.ReactNode;
  valueColor: string;
  valueFontSize?: string;
}) {
  return (
    <div
      style={{
        padding: '18px',
        borderRadius: '14px',
        background: 'rgba(255,255,255,0.03)',
        border: '1px solid rgba(255,255,255,0.05)',
      }}
    >
      <div style={{ fontSize: '12px', color: '#7f8ea3', marginBottom: '10px' }}>{label}</div>
      <div style={{ fontSize: valueFontSize, fontWeight: 700, color: valueColor, textTransform: 'uppercase' }}>
        {value}
      </div>
    </div>
  );
}

/** Geo intelligence block rendered inside the summary card */
function GeoBlock({ geo }: { geo: NonNullable<Attacker['geo']> }) {
  return (
    <div style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px solid rgba(255,255,255,0.08)' }}>
      <div
        style={{
          fontSize: '13px',
          color: '#7f8ea3',
          marginBottom: '14px',
          textTransform: 'uppercase',
          letterSpacing: '1px',
        }}
      >
        Geo Intelligence
      </div>
      <div style={{ display: 'grid', gap: '10px' }}>
        <div>🌍 <span style={{ color: '#00e5ff' }}>{geo.country}</span></div>
        <div>🏙️ {geo.city}, {geo.region}</div>
        <div>🛰️ {geo.isp}</div>
        <div>🧠 {geo.asn}</div>
      </div>
    </div>
  );
}

/** Expandable MITRE ATT&CK intelligence block shown when an event is expanded */
function MitreBlock({ event }: { event: ForensicEvent }) {
  if (!event.technique_description) return null;
  return (
    <div
      style={{
        marginTop: '12px',
        padding: '12px',
        borderRadius: '10px',
        background: 'rgba(0,229,255,0.05)',
        border: '1px solid rgba(0,229,255,0.12)',
      }}
    >
      <div style={{ color: '#00e5ff', fontWeight: 700, marginBottom: '8px' }}>MITRE ATT&amp;CK Intelligence</div>
      <div style={{ color: '#c7d5e0', lineHeight: 1.7, fontSize: '13px' }}>{event.technique_description}</div>
      {event.technique_url && (
        <a
          href={event.technique_url}
          target="_blank"
          rel="noreferrer"
          style={{ display: 'inline-block', marginTop: '12px', color: '#00e5ff', textDecoration: 'none', fontWeight: 700 }}
        >
          View MITRE ATT&amp;CK →
        </a>
      )}
    </div>
  );
}

/** Expandable CVE intelligence block shown when an event is expanded */
function CveBlock({ event }: { event: ForensicEvent }) {
  if (!event.cve_details) return null;
  return (
    <div
      style={{
        marginTop: '10px',
        padding: '12px',
        borderRadius: '10px',
        background: 'rgba(255,77,109,0.08)',
        border: '1px solid rgba(255,77,109,0.15)',
      }}
    >
      <div style={{ color: '#ff4d6d', fontWeight: 700, marginBottom: '8px' }}>CVE Intelligence</div>
      <div>CVSS: {event.cve_details.base_score}</div>
      <div>Severity: {event.cve_details.base_severity}</div>
      <div>Attack Vector: {event.cve_details.attack_vector}</div>
    </div>
  );
}

/** A single row in the Live Forensic Timeline list */
function ForensicEventRow({
  event,
  isExpanded,
  onToggle,
}: {
  event: ForensicEvent;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div
      onClick={onToggle}
      style={{
        padding: '12px',
        borderRadius: '10px',
        background: 'rgba(255,255,255,0.02)',
        border: '1px solid rgba(255,255,255,0.05)',
        cursor: 'pointer',
      }}
    >
      {/* Header row: source type + timestamp */}
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', fontSize: '11px' }}>
        <div
          style={{
            color: event.source_type === 'suricata' ? '#ff4d6d' : '#00e5ff',
            fontWeight: 700,
            textTransform: 'uppercase',
          }}
        >
          {event.source_type}
        </div>
        <div style={{ color: '#7f8ea3' }}>{new Date(event.timestamp).toLocaleTimeString()}</div>
      </div>

      {/* Alert signature */}
      <div style={{ color: '#d6e2f0', fontSize: '12px', lineHeight: 1.6 }}>{event.alert_signature}</div>

      {/* CVE badge */}
      {event.cve_id && (
        <div style={{ marginTop: '10px', color: '#ff4d6d', fontSize: '11px', fontWeight: 700 }}>
          🔥 {event.cve_id}
        </div>
      )}

      {/* MITRE technique badge */}
      {event.technique_id && (
        <div style={{ marginTop: '6px', color: '#00e5ff', fontSize: '11px', fontWeight: 700 }}>
          🛡️ MITRE {event.technique_id}
        </div>
      )}

      {/* Expanded detail section */}
      {isExpanded && (
        <div
          style={{
            marginTop: '14px',
            paddingTop: '14px',
            borderTop: '1px solid rgba(255,255,255,0.08)',
            display: 'flex',
            flexDirection: 'column',
            gap: '10px',
          }}
        >
          <div><span style={{ color: '#7f8ea3' }}>Source IP:</span> {event.src_ip}</div>
          <div><span style={{ color: '#7f8ea3' }}>Destination IP:</span> {event.dest_ip || 'N/A'}</div>
          <div><span style={{ color: '#7f8ea3' }}>Protocol:</span> {event.proto || 'N/A'}</div>
          <div><span style={{ color: '#7f8ea3' }}>Technique:</span> {event.technique_name || 'Unknown'}</div>
          <MitreBlock event={event} />
          <CveBlock event={event} />
        </div>
      )}

      {/* Tactic pill */}
      {event.tactic && (
        <div
          style={{
            marginTop: '10px',
            display: 'inline-flex',
            alignItems: 'center',
            padding: '6px 12px',
            borderRadius: '999px',
            background: 'linear-gradient(90deg, rgba(0,229,255,0.18), rgba(0,229,255,0.06))',
            border: '1px solid rgba(0,229,255,0.25)',
            color: '#00e5ff',
            fontSize: '10px',
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '1px',
          }}
        >
          {event.tactic}
        </div>
      )}
    </div>
  );
}

// ─── Main modal component ─────────────────────────────────────────────────────

/**
 * AttackerDetailsModal — Full-screen overlay displaying deep intelligence on a
 * selected threat actor: stat cards, geo info, a threat summary, and a live
 * forensic timeline with expandable per-event details.
 */
export function AttackerDetailsModal({
  selectedIp,
  attackerDetails,
  attackerEvents,
  eventsLoading,
  onClose,
}: AttackerDetailsModalProps) {
  // Track which forensic event row is currently expanded
  const [expandedEvent, setExpandedEvent] = React.useState<number | null>(null);

  const toggleEvent = (index: number) =>
    setExpandedEvent((prev) => (prev === index ? null : index));

  return (
    /* Backdrop */
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
        padding: '40px',
      }}
    >
      {/* Modal panel */}
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '90%',
          maxWidth: '1500px',
          height: '90vh',
          background: 'linear-gradient(180deg, #07111f 0%, #0b1728 100%)',
          border: '1px solid rgba(0,255,255,0.12)',
          borderRadius: '24px',
          display: 'flex',
          flexDirection: 'column',
          boxShadow: '0 0 40px rgba(0,255,255,0.08)',
          overflowY: 'scroll',
          scrollbarWidth: 'thin',
          padding: '32px',
        }}
      >
        {/* ── Modal header ── */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
          <div>
            <h2 style={{ margin: 0, fontSize: '32px', fontWeight: 700, color: '#ffffff' }}>
              Attacker Details
            </h2>
            {/* Threat level badge */}
            <div style={{ marginTop: '14px', display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div
                style={{
                  width: '12px', height: '12px', borderRadius: '50%',
                  background: '#ff355e', boxShadow: '0 0 14px #ff355e',
                }}
              />
              <div
                style={{
                  padding: '8px 16px',
                  borderRadius: '10px',
                  background: 'linear-gradient(90deg, rgba(255,53,94,0.2), rgba(255,53,94,0.08))',
                  border: '1px solid rgba(255,53,94,0.4)',
                  color: '#ff4d6d',
                  fontWeight: 700,
                  fontSize: '13px',
                  letterSpacing: '1px',
                  textTransform: 'uppercase',
                }}
              >
                Critical Threat Actor
              </div>
            </div>
          </div>

          {/* Close button */}
          <button
            onClick={onClose}
            style={{ background: 'transparent', border: 'none', color: '#9fb3c8', fontSize: '24px', cursor: 'pointer' }}
          >
            ✕
          </button>
        </div>

        {/* ── IP address block ── */}
        <div
          style={{
            marginBottom: '24px',
            padding: '16px',
            borderRadius: '14px',
            background: 'rgba(255,255,255,0.03)',
            border: '1px solid rgba(255,255,255,0.05)',
          }}
        >
          <div style={{ fontSize: '12px', color: '#7f8ea3', marginBottom: '6px', textTransform: 'uppercase' }}>
            IP Address
          </div>
          <div style={{ fontSize: '28px', fontWeight: 700, color: '#ffffff' }}>{selectedIp}</div>
        </div>

        {/* ── Data section (only shown once attackerDetails has loaded) ── */}
        {attackerDetails && (
          <>
            {/* 2-column grid: stat cards | threat summary */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '380px 1fr',
                gap: '24px',
                alignItems: 'start',
                marginTop: '24px',
              }}
            >
              {/* Left column: 2×2 stat cards */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '24px' }}>
                <StatCard label="RISK SCORE"         value={attackerDetails.risk_score}       valueColor="#ff4d6d" valueFontSize="38px" />
                <StatCard label="THREAT LEVEL"       value={attackerDetails.threat_level}      valueColor="#ff4d6d" valueFontSize="28px" />
                <StatCard label="TOTAL EVENTS"       value={attackerDetails.total_events}      valueColor="#00e5ff" />
                <StatCard label="UNIQUE TECHNIQUES"  value={attackerDetails.unique_techniques} valueColor="#00e5ff" />
              </div>

              {/* Right column: threat intelligence summary */}
              <div
                style={{
                  padding: '18px',
                  borderRadius: '14px',
                  background: 'rgba(255,255,255,0.03)',
                  border: '1px solid rgba(255,255,255,0.05)',
                  marginBottom: '24px',
                }}
              >
                <div style={{ fontSize: '14px', color: '#7f8ea3', marginBottom: '16px', textTransform: 'uppercase' }}>
                  Threat Intelligence Summary
                </div>
                <div style={{ lineHeight: 1.8 }}>
                  <div>• Risk Score: <span style={{ color: '#ff4d6d' }}>{attackerDetails.risk_score}</span></div>
                  <div>• Threat Level: <span style={{ color: '#ff4d6d' }}>{attackerDetails.threat_level}</span></div>
                  <div>• Total Events: <span style={{ color: '#00e5ff' }}>{attackerDetails.total_events}</span></div>
                  <div>• Unique Techniques: <span style={{ color: '#00e5ff' }}>{attackerDetails.unique_techniques}</span></div>

                  {/* Geo intelligence sub-section */}
                  {attackerDetails.geo && <GeoBlock geo={attackerDetails.geo} />}
                </div>
              </div>
            </div>

            {/* ── Live Forensic Timeline ── */}
            <div
              style={{
                marginTop: '24px',
                padding: '18px',
                borderRadius: '14px',
                background: 'rgba(255,255,255,0.03)',
                border: '1px solid rgba(255,255,255,0.05)',
              }}
            >
              <div style={{ fontSize: '14px', color: '#7f8ea3', marginBottom: '16px', textTransform: 'uppercase' }}>
                Live Forensic Timeline
              </div>

              {eventsLoading ? (
                <div style={{ color: '#00e5ff' }}>Loading forensic telemetry...</div>
              ) : (
                <div style={{ maxHeight: '280px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {attackerEvents.map((event, idx) => (
                    <ForensicEventRow
                      key={event.id ?? idx}
                      event={event}
                      isExpanded={expandedEvent === idx}
                      onToggle={() => toggleEvent(idx)}
                    />
                  ))}
                </div>
              )}
            </div>

            {/* ── Action buttons ── */}
            <div style={{ marginTop: '24px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div>
                <button
                  style={{
                    padding: '14px',
                    borderRadius: '12px',
                    border: '1px solid rgba(255,53,94,0.35)',
                    background: 'linear-gradient(180deg, rgba(255,53,94,0.16), rgba(255,53,94,0.05))',
                    color: '#ff4d6d',
                    fontWeight: 700,
                    cursor: 'pointer',
                    letterSpacing: '0.5px',
                  }}
                >
                  ISOLATE HOST
                </button>
              </div>
              <div style={{ display: 'flex', gap: '12px' }}>
                {[
                  { label: 'EXPORT IOC',       color: '#00e5ff', border: 'rgba(0,229,255,0.25)',  bg: 'linear-gradient(180deg, rgba(0,229,255,0.14), rgba(0,229,255,0.04))' },
                  { label: 'OPEN TIMELINE',    color: '#d6e2f0', border: 'rgba(255,255,255,0.08)', bg: 'rgba(255,255,255,0.03)' },
                  { label: 'GENERATE REPORT',  color: '#d6e2f0', border: 'rgba(255,255,255,0.08)', bg: 'rgba(255,255,255,0.03)' },
                ].map(({ label, color, border, bg }) => (
                  <button
                    key={label}
                    style={{
                      padding: '14px',
                      borderRadius: '12px',
                      border: `1px solid ${border}`,
                      background: bg,
                      color,
                      fontWeight: 700,
                      cursor: 'pointer',
                      letterSpacing: '0.5px',
                    }}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

