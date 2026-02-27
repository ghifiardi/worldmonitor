/**
 * Compact MITRE ATT&CK technique database for TAA enrichment.
 *
 * Contains the top 60 enterprise techniques with tactic, severity,
 * description, and detection guidance. Used by the Triage & Analysis
 * Agent to map keywords to real ATT&CK techniques.
 */

// Severity: 1 = low, 2 = medium, 3 = high, 4 = critical
// tactic codes: RA=Reconnaissance, RD=Resource Development, IA=Initial Access,
//   EX=Execution, PE=Persistence, PV=Privilege Escalation, DE=Defense Evasion,
//   CR=Credential Access, DI=Discovery, LM=Lateral Movement, CO=Collection,
//   C2=Command and Control, EF=Exfiltration, IM=Impact

const TECHNIQUES = [
  // Initial Access
  { id: 'T1566', name: 'Phishing', tactic: 'IA', sev: 3, keywords: ['phish', 'spearphish', 'email', 'lure', 'attachment', 'credential harvest'],
    desc: 'Adversaries send phishing messages to gain access to victim systems.',
    detect: 'Monitor email gateway for suspicious attachments/links. Analyze sender reputation.' },
  { id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'IA', sev: 3, keywords: ['spearphish', 'attachment', 'macro', 'document', 'docx', 'xlsx'],
    desc: 'Phishing with a malicious attachment (macro-enabled document, PDF, etc.).',
    detect: 'Sandbox email attachments. Monitor for macro execution from Office processes.' },
  { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'IA', sev: 4, keywords: ['exploit', 'rce', 'public', 'web shell', 'cve', 'vulnerability', 'apache', 'exchange'],
    desc: 'Exploit software vulnerabilities in internet-facing services.',
    detect: 'WAF rules, vulnerability scanning, monitor web server logs for exploit patterns.' },
  { id: 'T1133', name: 'External Remote Services', tactic: 'IA', sev: 3, keywords: ['vpn', 'rdp', 'remote', 'citrix', 'ssh', 'brute force'],
    desc: 'Leverage external remote services (VPN, RDP, Citrix) for initial access.',
    detect: 'Monitor for unusual VPN/RDP connections, especially from new geolocations.' },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'IA', sev: 4, keywords: ['valid account', 'compromised credential', 'stolen password', 'credential stuff'],
    desc: 'Use stolen or leaked credentials to gain access.',
    detect: 'Impossible travel analysis, credential leak monitoring, MFA enforcement.' },
  { id: 'T1195', name: 'Supply Chain Compromise', tactic: 'IA', sev: 4, keywords: ['supply chain', 'solarwinds', 'dependency', 'package', 'npm', 'pypi', 'trojan'],
    desc: 'Compromise the supply chain to distribute malware via trusted software.',
    detect: 'Software composition analysis, hash verification, vendor risk assessment.' },

  // Execution
  { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'EX', sev: 3, keywords: ['powershell', 'cmd', 'bash', 'python', 'script', 'wscript', 'cscript'],
    desc: 'Abuse command-line interpreters or scripting engines to execute commands.',
    detect: 'Script block logging, command-line auditing, behavioral analysis.' },
  { id: 'T1059.001', name: 'PowerShell', tactic: 'EX', sev: 3, keywords: ['powershell', 'invoke-expression', 'iex', 'downloadstring', 'encoded command'],
    desc: 'Use PowerShell for execution, often with obfuscation or encoded commands.',
    detect: 'Enable PowerShell script block logging (Event ID 4104), constrained language mode.' },
  { id: 'T1059.003', name: 'Windows Command Shell', tactic: 'EX', sev: 2, keywords: ['cmd.exe', 'command prompt', 'batch', 'bat file'],
    desc: 'Use cmd.exe for command execution.',
    detect: 'Monitor process creation for cmd.exe with suspicious arguments.' },
  { id: 'T1203', name: 'Exploitation for Client Execution', tactic: 'EX', sev: 3, keywords: ['exploit', 'client', 'browser', 'office', 'pdf', 'flash', 'java'],
    desc: 'Exploit software vulnerabilities in client applications.',
    detect: 'Endpoint detection, application whitelisting, patch management.' },
  { id: 'T1204', name: 'User Execution', tactic: 'EX', sev: 2, keywords: ['user execution', 'click', 'open', 'run', 'social engineer'],
    desc: 'Rely on user interaction to execute malicious content.',
    detect: 'User awareness training, application control, endpoint monitoring.' },

  // Persistence
  { id: 'T1547', name: 'Boot or Logon Autostart Execution', tactic: 'PE', sev: 3, keywords: ['autostart', 'registry run', 'startup', 'boot', 'logon', 'scheduled task'],
    desc: 'Configure system to execute malware on boot or logon.',
    detect: 'Monitor Run/RunOnce registry keys, startup folders, scheduled tasks.' },
  { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'PE', sev: 2, keywords: ['scheduled task', 'cron', 'at job', 'schtasks', 'crontab'],
    desc: 'Abuse task scheduling to maintain persistence.',
    detect: 'Monitor scheduled task creation (Event ID 4698), crontab changes.' },
  { id: 'T1136', name: 'Create Account', tactic: 'PE', sev: 3, keywords: ['create account', 'new user', 'admin account', 'backdoor account'],
    desc: 'Create new accounts for persistence.',
    detect: 'Monitor account creation events (Event ID 4720), especially privileged accounts.' },
  { id: 'T1505.003', name: 'Web Shell', tactic: 'PE', sev: 4, keywords: ['webshell', 'web shell', 'china chopper', 'jsp', 'aspx', 'php shell'],
    desc: 'Install web shells on internet-facing servers for persistent access.',
    detect: 'File integrity monitoring on web roots, anomalous web server child processes.' },

  // Privilege Escalation
  { id: 'T1055', name: 'Process Injection', tactic: 'PV', sev: 4, keywords: ['process injection', 'dll injection', 'reflective', 'hollow', 'inject'],
    desc: 'Inject code into running processes to escalate privileges or evade detection.',
    detect: 'Monitor for suspicious process access patterns, API calls like WriteProcessMemory.' },
  { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'PV', sev: 4, keywords: ['privilege escalation', 'local exploit', 'kernel', 'root', 'admin', 'lpe'],
    desc: 'Exploit software vulnerabilities to gain elevated privileges.',
    detect: 'Patch management, endpoint detection, monitoring for unusual privilege changes.' },

  // Defense Evasion
  { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'DE', sev: 2, keywords: ['obfuscate', 'encode', 'base64', 'pack', 'encrypt', 'compress'],
    desc: 'Obfuscate files or information to evade detection.',
    detect: 'Entropy analysis, deobfuscation tools, behavioral detection.' },
  { id: 'T1070', name: 'Indicator Removal', tactic: 'DE', sev: 3, keywords: ['clear log', 'delete log', 'timestomp', 'indicator removal', 'anti-forensic'],
    desc: 'Delete or modify indicators to hinder forensic analysis.',
    detect: 'Central log forwarding, file integrity monitoring, Event ID 1102 (audit log cleared).' },
  { id: 'T1562', name: 'Impair Defenses', tactic: 'DE', sev: 3, keywords: ['disable', 'antivirus', 'firewall', 'edr', 'tamper', 'defender'],
    desc: 'Disable or modify security tools.',
    detect: 'Monitor security tool status, tamper protection, health checks.' },
  { id: 'T1036', name: 'Masquerading', tactic: 'DE', sev: 2, keywords: ['masquerade', 'rename', 'disguise', 'lolbin', 'living off the land'],
    desc: 'Manipulate names or locations to appear legitimate.',
    detect: 'Compare process names vs expected paths, signature verification.' },

  // Credential Access
  { id: 'T1003', name: 'OS Credential Dumping', tactic: 'CR', sev: 4, keywords: ['credential dump', 'mimikatz', 'lsass', 'sam', 'ntds', 'dcsync', 'hashdump'],
    desc: 'Dump credentials from the OS (LSASS, SAM, NTDS.dit).',
    detect: 'Monitor LSASS access, enable Credential Guard, detect Mimikatz signatures.' },
  { id: 'T1110', name: 'Brute Force', tactic: 'CR', sev: 2, keywords: ['brute force', 'password spray', 'credential stuff', 'dictionary attack', 'login attempt'],
    desc: 'Systematically guess credentials via brute force or spraying.',
    detect: 'Account lockout policies, login failure monitoring, rate limiting.' },
  { id: 'T1558', name: 'Steal or Forge Kerberos Tickets', tactic: 'CR', sev: 4, keywords: ['kerberoast', 'golden ticket', 'silver ticket', 'kerberos', 'pass the ticket'],
    desc: 'Steal or forge Kerberos tickets for authentication.',
    detect: 'Monitor Kerberos ticket requests, detect TGS requests for service accounts.' },
  { id: 'T1555', name: 'Credentials from Password Stores', tactic: 'CR', sev: 3, keywords: ['password store', 'keychain', 'browser password', 'vault', 'credential manager'],
    desc: 'Extract credentials from password stores or browsers.',
    detect: 'Monitor access to password store files, browser credential databases.' },

  // Discovery
  { id: 'T1046', name: 'Network Service Discovery', tactic: 'DI', sev: 1, keywords: ['port scan', 'nmap', 'network scan', 'service discovery', 'enumerat'],
    desc: 'Scan for running services to identify targets for lateral movement.',
    detect: 'Network IDS, monitor for unusual scanning patterns from internal hosts.' },
  { id: 'T1087', name: 'Account Discovery', tactic: 'DI', sev: 1, keywords: ['account discovery', 'net user', 'whoami', 'enumerate user', 'ldap query'],
    desc: 'Enumerate accounts on the system or domain.',
    detect: 'Monitor for bulk LDAP queries, unusual use of net user/whoami.' },
  { id: 'T1082', name: 'System Information Discovery', tactic: 'DI', sev: 1, keywords: ['systeminfo', 'hostname', 'os version', 'system information'],
    desc: 'Gather system information for further operations.',
    detect: 'Monitor for recon commands executed shortly after initial access.' },

  // Lateral Movement
  { id: 'T1021', name: 'Remote Services', tactic: 'LM', sev: 3, keywords: ['lateral', 'psexec', 'wmi', 'winrm', 'smb', 'remote desktop', 'ssh lateral'],
    desc: 'Use remote services to move laterally between systems.',
    detect: 'Monitor for unusual remote service connections between internal hosts.' },
  { id: 'T1021.001', name: 'Remote Desktop Protocol', tactic: 'LM', sev: 3, keywords: ['rdp', 'remote desktop', 'mstsc', '3389'],
    desc: 'Use RDP for lateral movement.',
    detect: 'Monitor Event ID 4624/4625 for type 10 (RemoteInteractive) logons.' },
  { id: 'T1570', name: 'Lateral Tool Transfer', tactic: 'LM', sev: 2, keywords: ['tool transfer', 'copy', 'scp', 'upload tool', 'stage'],
    desc: 'Transfer tools between systems within the network.',
    detect: 'Monitor for unusual file transfers between internal systems.' },

  // Collection
  { id: 'T1005', name: 'Data from Local System', tactic: 'CO', sev: 2, keywords: ['data collection', 'local data', 'sensitive file', 'document', 'database'],
    desc: 'Collect sensitive data from local system storage.',
    detect: 'DLP solutions, monitor for bulk file access patterns.' },
  { id: 'T1114', name: 'Email Collection', tactic: 'CO', sev: 3, keywords: ['email', 'mailbox', 'outlook', 'exchange', 'email forward', 'mail rule'],
    desc: 'Collect emails for intelligence or credential harvesting.',
    detect: 'Monitor for unusual mailbox access, email forwarding rules.' },

  // Command and Control
  { id: 'T1071', name: 'Application Layer Protocol', tactic: 'C2', sev: 3, keywords: ['c2', 'c&c', 'command and control', 'beacon', 'callback', 'http c2', 'dns tunnel'],
    desc: 'Use application protocols (HTTP, DNS, SMTP) for C2 communication.',
    detect: 'Network traffic analysis, DNS anomaly detection, JA3/JA4 fingerprinting.' },
  { id: 'T1071.001', name: 'Web Protocols', tactic: 'C2', sev: 3, keywords: ['http beacon', 'https c2', 'cobalt strike', 'meterpreter', 'web c2'],
    desc: 'Use HTTP/HTTPS for C2 to blend with normal web traffic.',
    detect: 'Analyze HTTP headers, beacon interval patterns, JA3 hashes.' },
  { id: 'T1071.004', name: 'DNS', tactic: 'C2', sev: 3, keywords: ['dns tunnel', 'dns c2', 'dns exfil', 'dnscat', 'iodine'],
    desc: 'Use DNS protocol for C2 communication or data exfiltration.',
    detect: 'Monitor DNS query length, entropy, volume anomalies.' },
  { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'C2', sev: 2, keywords: ['download', 'wget', 'curl', 'certutil', 'bitsadmin', 'tool transfer'],
    desc: 'Download additional tools from external servers.',
    detect: 'Monitor for LOLBins downloading files (certutil, bitsadmin, PowerShell).' },
  { id: 'T1573', name: 'Encrypted Channel', tactic: 'C2', sev: 2, keywords: ['encrypted', 'ssl', 'tls', 'encrypted channel', 'custom encryption'],
    desc: 'Use encryption to conceal C2 communications.',
    detect: 'TLS inspection, JA3/JA4 fingerprinting, certificate analysis.' },
  { id: 'T1572', name: 'Protocol Tunneling', tactic: 'C2', sev: 3, keywords: ['tunnel', 'proxy', 'ngrok', 'cloudflare tunnel', 'ssh tunnel', 'icmp tunnel'],
    desc: 'Tunnel C2 traffic through legitimate protocols.',
    detect: 'Monitor for tunneling tool processes, unusual protocol usage.' },

  // Exfiltration
  { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'EF', sev: 3, keywords: ['exfiltrat', 'data theft', 'steal data', 'upload data', 'c2 exfil'],
    desc: 'Exfiltrate data over the existing C2 channel.',
    detect: 'DLP, monitor for large outbound transfers, unusual upload patterns.' },
  { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactic: 'EF', sev: 3, keywords: ['dns exfil', 'icmp exfil', 'ftp exfil', 'alternative protocol'],
    desc: 'Exfiltrate data using protocols different from C2.',
    detect: 'Monitor for unusual protocol usage, DNS query payload analysis.' },
  { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'EF', sev: 3, keywords: ['cloud storage', 'dropbox', 'google drive', 'pastebin', 'mega', 'web exfil'],
    desc: 'Use legitimate web services to exfiltrate data.',
    detect: 'CASB solutions, monitor uploads to cloud storage services.' },

  // Impact
  { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'IM', sev: 4, keywords: ['ransomware', 'encrypt', 'ransom', 'lockbit', 'conti', 'blackcat', 'alphv'],
    desc: 'Encrypt data to disrupt availability (ransomware).',
    detect: 'Monitor for mass file encryption, canary files, behavioral detection.' },
  { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'IM', sev: 4, keywords: ['delete backup', 'vssadmin', 'shadow copy', 'bcdedit', 'wbadmin', 'recovery'],
    desc: 'Delete backups and shadow copies to prevent recovery.',
    detect: 'Monitor for vssadmin/bcdedit/wbadmin commands, protect backup systems.' },
  { id: 'T1498', name: 'Network Denial of Service', tactic: 'IM', sev: 3, keywords: ['ddos', 'denial of service', 'dos', 'flood', 'amplification'],
    desc: 'Perform network DoS to disrupt availability.',
    detect: 'DDoS mitigation services, traffic baseline analysis.' },
  { id: 'T1531', name: 'Account Access Removal', tactic: 'IM', sev: 3, keywords: ['account lockout', 'delete account', 'disable account', 'password change'],
    desc: 'Remove account access to disrupt operations.',
    detect: 'Monitor bulk account modifications, password resets.' },
  { id: 'T1485', name: 'Data Destruction', tactic: 'IM', sev: 4, keywords: ['wiper', 'destroy', 'delete data', 'shamoon', 'notpetya', 'hermeticwiper'],
    desc: 'Destroy data to disrupt operations (wiper malware).',
    detect: 'File integrity monitoring, behavioral detection for mass file deletion.' },

  // Reconnaissance
  { id: 'T1595', name: 'Active Scanning', tactic: 'RA', sev: 1, keywords: ['scan', 'recon', 'probe', 'fingerprint', 'banner grab'],
    desc: 'Actively scan victim infrastructure for vulnerabilities.',
    detect: 'Perimeter IDS, honeypots, monitor for scanning patterns.' },
  { id: 'T1589', name: 'Gather Victim Identity Information', tactic: 'RA', sev: 2, keywords: ['osint', 'employee', 'email harvest', 'linkedin', 'identity'],
    desc: 'Gather information about victim identities (names, emails, roles).',
    detect: 'Monitor for bulk profile scraping, dark web credential monitoring.' },

  // Additional high-impact techniques
  { id: 'T1557', name: 'Adversary-in-the-Middle', tactic: 'CR', sev: 3, keywords: ['mitm', 'man in the middle', 'arp spoof', 'llmnr', 'nbns', 'responder'],
    desc: 'Position between two endpoints to intercept traffic.',
    detect: 'Monitor for ARP anomalies, LLMNR/NBT-NS poisoning, rogue DHCP.' },
  { id: 'T1218', name: 'System Binary Proxy Execution', tactic: 'DE', sev: 2, keywords: ['lolbin', 'rundll32', 'regsvr32', 'mshta', 'msiexec', 'proxy exec'],
    desc: 'Use signed system binaries to proxy-execute malicious content.',
    detect: 'Monitor LOLBin execution with unusual arguments or child processes.' },
  { id: 'T1543', name: 'Create or Modify System Process', tactic: 'PE', sev: 3, keywords: ['service', 'systemd', 'launchd', 'daemon', 'windows service'],
    desc: 'Create or modify system-level processes for persistence.',
    detect: 'Monitor service creation (Event ID 7045), systemd unit files.' },
  { id: 'T1548', name: 'Abuse Elevation Control Mechanism', tactic: 'PV', sev: 3, keywords: ['uac bypass', 'sudo', 'setuid', 'elevation', 'runas'],
    desc: 'Bypass elevation controls (UAC, sudo) to gain higher privileges.',
    detect: 'Monitor for UAC bypass techniques, unusual sudo usage.' },
];

// ── Tactic full names ───────────────────────────────────────────

const TACTIC_NAMES = {
  RA: 'Reconnaissance', RD: 'Resource Development', IA: 'Initial Access',
  EX: 'Execution', PE: 'Persistence', PV: 'Privilege Escalation',
  DE: 'Defense Evasion', CR: 'Credential Access', DI: 'Discovery',
  LM: 'Lateral Movement', CO: 'Collection', C2: 'Command and Control',
  EF: 'Exfiltration', IM: 'Impact',
};

const SEVERITY_LABELS = { 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' };

// ── Lookup by ID ────────────────────────────────────────────────

const idIndex = new Map(TECHNIQUES.map(t => [t.id, t]));

export function lookupById(techniqueId) {
  const t = idIndex.get(techniqueId);
  if (!t) return null;
  return { ...t, tacticName: TACTIC_NAMES[t.tactic], severityLabel: SEVERITY_LABELS[t.sev] };
}

// ── Keyword matching ────────────────────────────────────────────

export function matchTechniques(text, maxResults = 5) {
  const lower = text.toLowerCase();
  const scored = [];

  for (const t of TECHNIQUES) {
    let score = 0;
    for (const kw of t.keywords) {
      if (lower.includes(kw.toLowerCase())) {
        score += kw.length; // Longer keyword matches = higher relevance
      }
    }
    // Also match technique ID directly
    if (lower.includes(t.id.toLowerCase())) score += 20;
    if (lower.includes(t.name.toLowerCase())) score += 15;

    if (score > 0) {
      scored.push({
        ...t,
        tacticName: TACTIC_NAMES[t.tactic],
        severityLabel: SEVERITY_LABELS[t.sev],
        matchScore: score,
      });
    }
  }

  return scored
    .sort((a, b) => b.matchScore - a.matchScore || b.sev - a.sev)
    .slice(0, maxResults);
}

// ── Kill chain stage derivation ─────────────────────────────────

const KILL_CHAIN_ORDER = ['RA', 'RD', 'IA', 'EX', 'PE', 'PV', 'DE', 'CR', 'DI', 'LM', 'CO', 'C2', 'EF', 'IM'];

export function deriveKillChainStage(techniques) {
  if (!techniques || techniques.length === 0) return 'Unknown';
  const tactics = [...new Set(techniques.map(t => t.tactic))];
  // Find the furthest stage in the kill chain
  let maxIdx = -1;
  let minIdx = KILL_CHAIN_ORDER.length;
  for (const tac of tactics) {
    const idx = KILL_CHAIN_ORDER.indexOf(tac);
    if (idx > maxIdx) maxIdx = idx;
    if (idx < minIdx) minIdx = idx;
  }
  const from = TACTIC_NAMES[KILL_CHAIN_ORDER[minIdx]] || 'Unknown';
  const to = TACTIC_NAMES[KILL_CHAIN_ORDER[maxIdx]] || 'Unknown';
  return from === to ? from : `${from} → ${to}`;
}

// ── Overall severity ────────────────────────────────────────────

export function maxSeverity(techniques) {
  if (!techniques || techniques.length === 0) return { level: 1, label: 'Low' };
  const max = Math.max(...techniques.map(t => t.sev));
  return { level: max, label: SEVERITY_LABELS[max] };
}

export function getTacticName(code) {
  return TACTIC_NAMES[code] || code;
}
