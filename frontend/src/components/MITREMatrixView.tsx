import React, { useState } from 'react';
import { Shield, ShieldAlert, X, Terminal, Cpu } from 'lucide-react';

import { matrixData } from '../data/mitre-matrix';
import type { Technique } from '../data/mitre-matrix';

export const MITREMatrixView: React.FC = () => {
  const [selectedTech, setSelectedTech] = useState<Technique | null>(null);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-lg)' }}>
      {/* Header Info */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'rgba(255, 255, 255, 0.6)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
          <Shield style={{ color: 'var(--color-primary)' }} size={14} />
          <span>MITRE ATT&CK HEATMAP ORCHESTRATOR - SEVERITY WEIGHTED</span>
        </div>
        <div style={{ display: 'flex', gap: '16px', fontSize: '10px', fontFamily: 'var(--font-mono)' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span style={{ width: '8px', height: '8px', background: 'rgba(244, 63, 94, 0.25)', border: '1px solid var(--color-danger)' }} />
            CRITICAL ({'>'}5,000 EXPLOITS)
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span style={{ width: '8px', height: '8px', background: 'rgba(245, 158, 11, 0.2)', border: '1px solid var(--color-warning)' }} />
            HIGH ({'>'}1,000 EXPLOITS)
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span style={{ width: '8px', height: '8px', background: 'rgba(59, 130, 246, 0.15)', border: '1px solid var(--color-secondary)' }} />
            MEDIUM
          </span>
        </div>
      </div>

      {/* Main Grid & Drawer split */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedTech ? '1fr 340px' : '1fr', gap: 'var(--spacing-lg)', transition: 'grid-template-columns var(--transition-normal)' }}>
        
        {/* 12 Column Tactics Grid */}
        <div className="glass-panel" style={{ overflowX: 'auto', padding: 'var(--spacing-md)' }}>
          <div className="mitre-grid">
            {matrixData.map(col => (
              <div key={col.id} className="mitre-column">
                <div className="mitre-header">
                  {col.name}
                </div>
                {col.techniques.map(tech => {
                  const isSelected = selectedTech?.id === tech.id;
                  const heatClass = tech.severity === 'critical' ? 'heat-critical' : 
                                    tech.severity === 'high' ? 'heat-high' : 
                                    tech.severity === 'medium' ? 'heat-medium' : '';
                                    
                  return (
                    <div 
                      key={tech.id} 
                      className={`mitre-cell ${heatClass}`}
                      style={{
                        border: isSelected ? '1px solid var(--color-primary)' : '',
                        boxShadow: isSelected ? 'var(--shadow-neon)' : ''
                      }}
                      onClick={() => setSelectedTech(tech)}
                    >
                      <div className="mitre-cell-title">{tech.name}</div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '8px', alignItems: 'center' }}>
                        <span className="mitre-cell-id">{tech.id}</span>
                        {tech.count > 0 && <span className="mitre-cell-count">{tech.count.toLocaleString()}</span>}
                      </div>
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        </div>

        {/* Selected Technique Inspector Drawer */}
        {selectedTech && (
          <div className="glass-panel glowing" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-md)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255, 255, 255, 0.05)', paddingBottom: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldAlert size={16} style={{ color: 'var(--color-primary)' }} />
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700, color: 'var(--color-primary)' }}>
                  MITRE TACTICAL INSPECT
                </span>
              </div>
              <button 
                onClick={() => setSelectedTech(null)}
                style={{ background: 'transparent', border: 'none', color: 'rgba(255, 255, 255, 0.4)', cursor: 'pointer' }}
              >
                <X size={16} />
              </button>
            </div>

            <div>
              <h4 style={{ fontFamily: 'var(--font-display)', fontSize: '18px', fontWeight: 800, color: '#ffffff' }}>
                {selectedTech.name}
              </h4>
              <span className="status-pill critical" style={{ fontSize: '9px', marginTop: '6px' }}>
                ID: {selectedTech.id} | SEVERITY: {selectedTech.severity}
              </span>
            </div>

            <div style={{ fontSize: '13px', color: 'rgba(226, 232, 240, 0.7)', lineHeight: 1.5 }}>
              <h5 style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', textTransform: 'uppercase', color: 'rgba(226, 232, 240, 0.4)', marginBottom: '4px' }}>
                Description
              </h5>
              <p>{selectedTech.description}</p>
            </div>

            {/* Mapped Honeypot/NIDS Detections */}
            {selectedTech.detections.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <h5 style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', textTransform: 'uppercase', color: 'rgba(226, 232, 240, 0.4)' }}>
                  Active Sensor Logs
                </h5>
                <div style={{ background: '#000000', padding: '12px', border: '1px solid rgba(255, 255, 255, 0.05)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {selectedTech.detections.map((det, index) => (
                    <div key={index} style={{ fontFamily: 'var(--font-mono)', fontSize: '9px', color: '#10b981', display: 'flex', gap: '6px', alignItems: 'flex-start' }}>
                      <Terminal size={10} style={{ flexShrink: 0, marginTop: '2px' }} />
                      <span>{det}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Security Remediation Steps */}
            {selectedTech.remediations.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <h5 style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', textTransform: 'uppercase', color: 'rgba(226, 232, 240, 0.4)' }}>
                  SOC Security Remediation
                </h5>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {selectedTech.remediations.map((rem, index) => (
                    <div key={index} style={{ fontSize: '12px', color: '#ffffff', display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
                      <Cpu size={12} style={{ color: 'var(--color-primary)', marginTop: '2px', flexShrink: 0 }} />
                      <span>{rem}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
