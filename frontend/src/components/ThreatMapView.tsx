import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Play, Square } from 'lucide-react';

import { sensorLocations, attackIps, tactics, alerts } from '../data/threat-map';
import type { LogEntry } from '../data/threat-map';

export const ThreatMapView: React.FC = () => {
  const [logs, setLogs] = useState<LogEntry[]>(() => {
    return Array.from({ length: 8 }).map((_, i) => {
      const isSuricata = i % 2 === 0;
      return {
        timestamp: new Date(Date.now() - (8 - i) * 60000).toLocaleTimeString(),
        type: isSuricata ? 'SURICATA' : 'COWRIE',
        ip: attackIps[i % attackIps.length],
        tactic: tactics[i % tactics.length],
        message: alerts[i % alerts.length]
      };
    });
  });
  const [isStreaming, setIsStreaming] = useState(true);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Map active laser threat line coordinates
  const [activeLaser, setActiveLaser] = useState<{ x1: number; y1: number; x2: number; y2: number } | null>(null);
  const [laserTarget, setLaserTarget] = useState<string | null>(null);

  const addLog = () => {
    const randomIp = attackIps[Math.floor(Math.random() * attackIps.length)];
    const randomTactic = tactics[Math.floor(Math.random() * tactics.length)];
    const randomMsg = alerts[Math.floor(Math.random() * alerts.length)];
    const isSuricata = Math.random() > 0.5;

    const newLog: LogEntry = {
      timestamp: new Date().toLocaleTimeString(),
      type: isSuricata ? 'SURICATA' : 'COWRIE',
      ip: randomIp,
      tactic: randomTactic,
      message: randomMsg
    };

    setLogs(prev => [...prev.slice(-30), newLog]);

    // Animate map laser vector strike
    const targetSensor = sensorLocations[Math.floor(Math.random() * sensorLocations.length)];
    const randomSourceX = Math.floor(Math.random() * 960);
    const randomSourceY = Math.floor(Math.random() * 450);
    
    setLaserTarget(targetSensor.name);
    setActiveLaser({
      x1: randomSourceX,
      y1: randomSourceY,
      x2: targetSensor.x,
      y2: targetSensor.y
    });

    setTimeout(() => {
      setActiveLaser(null);
      setLaserTarget(null);
    }, 1200);
  };

  // Baseline logs populated via state initializer to avoid synchronous mount-effect updates

  useEffect(() => {
    if (!isStreaming) return;
    const interval = setInterval(addLog, 2400);
    return () => clearInterval(interval);
  }, [isStreaming]);

  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-lg)' }}>
      {/* SVG Map Section */}
      <div className="glass-panel glowing" style={{ padding: 0, overflow: 'hidden', height: '420px', position: 'relative' }}>
        <div style={{ position: 'absolute', top: '16px', left: '16px', zIndex: 10, display: 'flex', gap: '8px' }}>
          <span className="status-pill critical" style={{ display: 'flex', alignItems: 'center', gap: '4px', background: 'rgba(5, 8, 17, 0.8)' }}>
            <span className="pulse-dot"></span>
            ACTIVE DECOY NETWORK INTRUSION SENSORS: 5/5
          </span>
        </div>

        {/* Global Geographic SVG Board */}
        <svg 
          viewBox="0 0 960 480" 
          style={{ width: '100%', height: '100%', background: 'rgba(2, 4, 10, 0.4)' }}
        >
          {/* Grid Gridlines Background */}
          <pattern id="mapGrid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(34, 211, 238, 0.03)" strokeWidth="1"/>
          </pattern>
          <rect width="100%" height="100%" fill="url(#mapGrid)" />

          {/* Simple Vectorized World Map Outline representation (Circles / Nodes) */}
          {/* North America */}
          <circle cx="220" cy="180" r="45" fill="rgba(255,255,255,0.015)" />
          <circle cx="280" cy="190" r="30" fill="rgba(255,255,255,0.015)" />
          {/* South America */}
          <circle cx="340" cy="340" r="35" fill="rgba(255,255,255,0.015)" />
          {/* Europe */}
          <circle cx="500" cy="150" r="40" fill="rgba(255,255,255,0.015)" />
          {/* Africa */}
          <circle cx="520" cy="280" r="45" fill="rgba(255,255,255,0.015)" />
          {/* Asia */}
          <circle cx="720" cy="180" r="60" fill="rgba(255,255,255,0.015)" />
          <circle cx="820" cy="220" r="40" fill="rgba(255,255,255,0.015)" />
          {/* Australia */}
          <circle cx="840" cy="360" r="30" fill="rgba(255,255,255,0.015)" />

          {/* Map Laser Vector Threat Line */}
          {activeLaser && (
            <>
              <line 
                x1={activeLaser.x1} 
                y1={activeLaser.y1} 
                x2={activeLaser.x2} 
                y2={activeLaser.y2} 
                stroke="var(--color-danger)" 
                strokeWidth="1.5" 
                strokeDasharray="4 2"
                style={{ animation: 'dash 10s linear infinite' }}
              />
              <circle cx={activeLaser.x1} cy={activeLaser.y1} r="4" fill="var(--color-danger)" />
              <circle cx={activeLaser.x1} cy={activeLaser.y1} r="10" fill="none" stroke="var(--color-danger)" strokeWidth="1">
                <animate attributeName="r" values="4;15" dur="1s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="1;0" dur="1s" repeatCount="indefinite" />
              </circle>
            </>
          )}

          {/* Render Sensors */}
          {sensorLocations.map(sensor => {
            const isTarget = laserTarget === sensor.name;
            return (
              <g key={sensor.name}>
                {/* Glowing Aura */}
                <circle 
                  cx={sensor.x} 
                  cy={sensor.y} 
                  r={isTarget ? 15 : 6} 
                  fill={isTarget ? 'var(--color-danger)' : 'var(--color-primary)'} 
                  opacity={isTarget ? 0.35 : 0.2}
                  style={{ transition: 'r var(--transition-fast), fill var(--transition-fast)' }}
                />
                {/* Core Dot */}
                <circle 
                  cx={sensor.x} 
                  cy={sensor.y} 
                  r="3.5" 
                  fill={isTarget ? 'var(--color-danger)' : 'var(--color-primary)'} 
                />
                {/* Labels */}
                <text 
                  x={sensor.x + 8} 
                  y={sensor.y + 4} 
                  fill="#ffffff" 
                  fontSize="8" 
                  fontFamily="var(--font-mono)"
                  fontWeight="bold"
                  opacity={isTarget ? 1 : 0.6}
                >
                  {sensor.name} ({sensor.ip})
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Live Logs Terminal */}
      <div className="glass-panel glowing">
        <div className="panel-header">
          <h3 className="panel-title">
            <Terminal size={16} style={{ color: 'var(--color-success)' }} />
            LIVE SECURITY THREAT CONSOLE INDEX
          </h3>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button 
              onClick={() => setIsStreaming(!isStreaming)} 
              className="tactical-btn" 
              style={{ padding: '3px 8px', fontSize: '9px', display: 'flex', gap: '4px' }}
            >
              {isStreaming ? (
                <>
                  <Square size={8} fill="currentColor" /> MUTE STREAM
                </>
              ) : (
                <>
                  <Play size={8} fill="currentColor" /> RESUME STREAM
                </>
              )}
            </button>
          </div>
        </div>

        {/* Console logs view */}
        <div style={{ background: 'var(--surface-black)', height: '240px', padding: '16px', overflowY: 'auto', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
            {logs.map((log, index) => (
              <div key={index} style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', borderBottom: '1px solid rgba(255, 255, 255, 0.02)', paddingBottom: '4px' }}>
                <span style={{ color: 'rgba(226, 232, 240, 0.3)' }}>[{log.timestamp}]</span>
                <span style={{ 
                  color: log.type === 'SURICATA' ? 'var(--color-danger)' : 'var(--color-secondary)',
                  fontWeight: 'bold',
                  flexShrink: 0
                }}>
                  [{log.type}]
                </span>
                <span style={{ color: 'var(--color-primary)', fontWeight: 'bold' }}>{log.ip}</span>
                <span style={{ color: 'var(--color-tertiary)', fontWeight: 'bold', flexShrink: 0 }}>[{log.tactic}]</span>
                <span style={{ color: '#ffffff' }}>- {log.message}</span>
              </div>
            ))}
            <div ref={terminalEndRef} />
          </div>
        </div>
      </div>
    </div>
  );
};
