export interface LogEntry {
  timestamp: string;
  type: 'SURICATA' | 'COWRIE';
  ip: string;
  tactic: string;
  message: string;
}

export const sensorLocations = [
  { name: 'London', x: 480, y: 140, ip: '82.165.97.12' },
  { name: 'Frankfurt', x: 505, y: 145, ip: '185.190.140.8' },
  { name: 'Tokyo', x: 860, y: 220, ip: '210.140.10.45' },
  { name: 'Singapore', x: 770, y: 320, ip: '111.95.84.18' },
  { name: 'New York', x: 280, y: 180, ip: '198.51.100.22' }
];

export const attackIps = [
  '194.26.135.84', '85.203.47.112', '45.142.195.6', '103.214.144.18',
  '185.220.101.42', '91.240.118.15', '198.51.100.77', '203.0.113.159'
];

export const tactics = [
  'Credential Access', 'Execution', 'Initial Access', 'Discovery',
  'Lateral Movement', 'Command and Control', 'Persistence'
];

export const alerts = [
  'Web Application Exploit Attempt - Log4j payload found',
  'CVE-2023-49103 scan vector on port 8000',
  'Failed SSH root login attempt with password rotation',
  'Attempted write to /root/.ssh/authorized_keys',
  'Outbound TCP connection to port 9999 from isolated host',
  'uname -a and CPU metrics query executed in sandbox shell',
  'Successful root authentication with generic passwords'
];
