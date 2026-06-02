// Telemetry messages that scroll across the footer ticker
const TICKER_MESSAGES = [
  { text: '[SYSTEM MONITOR ONLINE]',                                                              style: { color: 'var(--color-primary)' } },
  { text: 'NODE_ALPHA_01: CPU 12% | LATENCY 14ms | DATABASE SPEEDUP 120X',                       style: {} },
  { text: '[WARN] SSH BRUTE FORCE DETECTED FROM IP 85.203.47.112',                               style: { color: 'var(--color-danger)' } },
  { text: "CTI_THREAT_FEED: NEW RANSOMWARE VARIANT 'CYPHER' IDENTIFIED BY ENTRUST",              style: {} },
  { text: 'TELEMETRY RATE: 1,840 PKTS/SEC | STREAM CIPHER: AES-256-GCM',                        style: {} },
  { text: '[INFO] MITRE HEATMAP METRICS DYNAMICALLY COMPILED',                                   style: { color: 'var(--color-success)' } },
  { text: 'OPERATING MODE: FULL SECURE BACKEND INTEGRATION CHANNELS ACTIVE',                     style: {} },
];

const tickerTextStyle: React.CSSProperties = {
  fontFamily: 'var(--font-mono)',
  fontSize: '11px',
  color: 'rgba(226,232,240,0.65)',
};

/**
 * FooterTicker — Horizontally-scrolling telemetry log stream rendered as a
 * sticky footer. Messages are duplicated so the scroll animation loops
 * seamlessly without a visible gap.
 */
export function FooterTicker() {
  return (
    <footer className="app-footer-ticker">
      <div className="ticker-scroll" style={{ whiteSpace: 'nowrap' }}>
        {/* Render messages twice so the CSS marquee animation loops seamlessly */}
        {[0, 1].map((pass) => (
          <div key={pass} style={{ display: 'flex', gap: '32px', paddingRight: '32px', ...tickerTextStyle }}>
            {TICKER_MESSAGES.map(({ text, style }, i) => (
              <span key={i} style={style}>{text}</span>
            ))}
          </div>
        ))}
      </div>
    </footer>
  );
}
