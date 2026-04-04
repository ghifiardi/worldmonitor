# GATRA World Monitor — User Guide

**Platform:** https://worldmonitor-gatra.vercel.app
**Version:** Cyber Variant (GATRA SOC Edition)
**Last Updated:** March 2026

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Dashboard Overview](#2-dashboard-overview)
3. [Interactive Map](#3-interactive-map)
4. [GATRA SOC Panel](#4-gatra-soc-panel)
5. [SOC COMMS — AI Agent Chat](#5-soc-comms--ai-agent-chat)
6. [A2A Security Monitor](#6-a2a-security-monitor)
7. [Social Threat Intel](#7-social-threat-intel)
8. [CVE Feed](#8-cve-feed)
9. [IoC Lookup](#9-ioc-lookup)
10. [Ransomware Tracker](#10-ransomware-tracker)
11. [CII Monitor](#11-cii-monitor)
12. [Prediction Signals](#12-prediction-signals)
13. [Security Posture](#13-security-posture)
14. [Customization & Settings](#14-customization--settings)
15. [URL Deep Linking](#15-url-deep-linking)
16. [Data Sources & Refresh Rates](#16-data-sources--refresh-rates)
17. [Troubleshooting](#17-troubleshooting)

---

## 1. Getting Started

### Opening the Dashboard

Navigate to **https://worldmonitor-gatra.vercel.app** in a modern browser (Chrome, Firefox, or Edge recommended). The dashboard loads in **Cyber/GATRA mode** by default, showing cybersecurity-focused panels and map layers.

### First-Time Setup

1. **Wait for data to load** — Panels fetch live data on first load (5–15 seconds)
2. **Check the sidebar** — Click the hamburger menu (top-left) to see available panels
3. **Adjust time range** — Most panels support time filtering (1h / 6h / 24h / 7d / all)
4. **Toggle map layers** — Use the layer control on the map to show/hide data layers
5. **Try the SOC Chat** — Type a cybersecurity question to interact with the AI agents

### System Requirements

- **Recommended:** Desktop browser, 1280px+ screen width
- **Supported:** Tablet (768px+) with simplified layout
- **Mobile:** Basic support with warning; best experienced on desktop
- **Dark mode** is the default theme; switch via settings

---

## 2. Dashboard Overview

The dashboard is divided into three main areas:

```
+--------------------------------------------------+
|  HEADER BAR (title, settings, theme toggle)      |
+--------+-----------------------------------------+
|        |                                         |
| PANELS |          INTERACTIVE MAP                |
| (left  |     (global view with layers)           |
|  side) |                                         |
|        |                                         |
+--------+-----------------------------------------+
```

### Panel Layout

Panels appear on the left side in a scrollable column. Each panel has:

- **Title bar** — Panel name + live item count badge
- **Data source badge** — Green "LIVE" (pulsing) means real-time data is active
- **Info tooltip** — Hover the (i) icon for a description of the panel and its refresh rate
- **Collapse/Expand** — Click the panel header to collapse or expand
- **Close** — Hide the panel via the sidebar toggle

### Data Freshness Indicators

| Badge | Meaning |
|-------|---------|
| LIVE (green, pulsing) | Real-time data from API |
| MOCK (yellow) | Simulated data (API unavailable) |
| No badge | Static or cached content |

---

## 3. Interactive Map

The global map is the central view of the dashboard. It visualizes geolocated cybersecurity events, infrastructure, and threat intelligence.

### Map Controls

| Control | Action |
|---------|--------|
| Scroll wheel | Zoom in/out |
| Click + drag | Pan the map |
| `+` / `-` buttons | Zoom in/out |
| Layer icon (top-right) | Toggle map layers on/off |

### Map Layers (Cyber Variant)

The following layers are available. Enabled layers show their data as markers, lines, or regions on the map:

| Layer | Description | Default |
|-------|-------------|---------|
| **GATRA Alerts** | SOC alert geolocations (colored by severity) | ON |
| **Cyber Threats** | Malware hosts, C2 servers, phishing URLs | ON |
| **Conflicts** | Armed conflict zones (UCDP data) | ON |
| **Cables** | Undersea communication cables | ON |
| **Outages** | Internet service disruptions | ON |
| **Datacenters** | AI/GPU compute facilities worldwide | ON |
| **Military** | Aircraft and vessel tracking | ON |
| **Natural** | Earthquakes, volcanoes, storms | ON |
| **Fires** | Satellite-detected wildfires | ON |
| **Flights** | Gulf region commercial air traffic | OFF |
| **Pipelines** | Oil & gas infrastructure | OFF |
| **Nuclear** | Nuclear facilities | OFF |

### Clicking Map Markers

Click any marker on the map for a popup with:
- Type of event/asset
- Name and description
- Timestamp or last update
- Related alerts (if applicable)

---

## 4. GATRA SOC Panel

The **GATRA SOC** panel is the primary security operations dashboard. It displays alerts from the CISA Known Exploited Vulnerabilities (KEV) catalog, scored against your infrastructure profile.

### 4.1 Agent Status Bar

At the top of the panel, five colored dots show the status of the GATRA AI agents:

| Agent | Role | Dot Color |
|-------|------|-----------|
| **ADA** | Anomaly Detection Agent — Detects unusual patterns using Isolation Forest + LSTM | Green = online |
| **TAA** | Threat Analysis Agent — Triages and prioritizes alerts using Actor-Critic RL | Green = online |
| **CRA** | Containment & Response Agent — Executes automated containment playbooks | Green = online |
| **CLA** | Compliance & Logging Agent — Maintains audit trails and regulatory compliance | Green = online |
| **RVA** | Risk & Vulnerability Agent — Assesses vulnerability exposure and patch priority | Yellow = processing |

Hover over any dot to see the agent's full name, status, and last heartbeat time.

### 4.2 Stats Row

| Metric | Description |
|--------|-------------|
| **Active** | Number of critical + high severity incidents |
| **MTTR** | Mean Time to Respond (minutes) — green (<15m), yellow (<30m), red (>30m) |
| **24h Alerts** | Total alerts in the current time range |
| **24h Resp** | CRA automated response actions taken |

### 4.3 Asset Relevance Scoring

This is the intelligence layer that transforms generic alerts into **actionable prioritized intelligence**.

**How it works:**
- Each alert is matched against your organization's **Asset Profile** (tech stack, vendors, products, industry)
- A relevance score (0–100) is computed based on:
  - **Vendor match** (40 pts) — Does the alert affect a vendor you use?
  - **Product match** (30 pts) — Does it target a specific product in your stack?
  - **Industry relevance** (15 pts) — Is it related to your sector (telecom, critical infrastructure)?
  - **Ransomware campaign** (10 pts) — Known ransomware usage is always relevant
  - **Urgency** (5 pts) — CISA remediation deadline within 7 days

**Relevance badges on each alert:**

| Badge | Score | Meaning |
|-------|-------|---------|
| **MATCH** (green) | 80–100 | Direct match — affects your vendor AND product |
| **RELATED** (yellow) | 50–79 | Partial match — affects a vendor you use |
| **LOW** (gray) | 20–49 | Tangential relevance |
| **INFO** (dark) | 0–19 | General advisory — not in your stack |

**Summary bar features:**
- **"X of Y alerts affect your infrastructure"** — Shows how many alerts are relevant to you
- **Progress bar** — Visual percentage of relevant alerts
- **Vendor tags** — Green badges showing which vendors in your stack were matched (e.g., Microsoft, Cisco, Fortinet)
- **"Show Relevant Only" button** — Click to filter the alert feed to only MATCH + RELATED alerts

### 4.4 Alert Feed

Alerts are displayed in a scrollable list, sorted by **relevance first, then severity**. Each alert shows:

- **Severity badge** (CRITICAL / HIGH / MEDIUM / LOW)
- **Relevance badge** (MATCH / RELATED / LOW / INFO)
- **MITRE ATT&CK ID + Technique name** (e.g., T1190 — Exploit Public-Facing Application)
- **Description** — Vulnerability name and summary
- **Metadata** — Location, infrastructure, confidence %, agent responsible
- **Matched assets** (if relevant) — e.g., "Cisco -> SD-WAN" or "Microsoft -> Windows"

Up to 20 alerts are shown; scroll down for more.

### 4.5 TAA Threat Analysis Section

Below the alert feed, the Threat Analysis Agent provides:
- **Actor attribution** — Who is likely behind the threat
- **Campaign name** — Associated threat campaign
- **Kill chain phase** — Where in the attack lifecycle (Recon -> Exploit -> C2 -> Actions)
- **Confidence** — How certain the attribution is
- **IOCs** — Indicators of Compromise linked to the analysis

### 4.6 CRA Response Actions

Shows automated containment actions taken:
- Action type (IP Blocked, Endpoint Isolated, Credential Rotated, etc.)
- Status badge (green = success, red = failed)
- Timestamp

### 4.7 Time Range Filter

Use the time range buttons to filter alerts:
- **1h** — Last hour only
- **6h** — Last 6 hours
- **24h** — Last 24 hours
- **48h** — Last 2 days
- **7d** — Last week
- **all** — Show all available alerts

---

## 5. SOC COMMS — AI Agent Chat

The **SOC COMMS** panel is an interactive chat interface where you can ask questions and the GATRA AI agents respond in real time.

### How to Use

1. Type your question in the input box at the bottom
2. Press **Send** or hit **Enter**
3. The appropriate agent(s) automatically respond based on your question

### Agent Routing

The system matches your message against keyword patterns to route it to the right agent:

| What to Ask | Agent That Responds |
|------------|-------------------|
| "any new anomaly?" / "what did ADA detect?" | **ADA** — Anomaly detection results |
| "any coming real threat?" / "triage alerts" / "escalate" | **TAA** — Threat assessment and prioritization |
| "block this IP" / "isolate endpoint" / "run playbook" | **CRA** — Containment and response actions |
| "generate report" / "audit trail" / "compliance status" | **CLA** — Compliance and logging |
| "vulnerability scan" / "CVE status" / "patch priority" | **RVA** — Risk and vulnerability assessment |

### Quick Commands

Type these directly in the chat:

| Command | Action |
|---------|--------|
| `/help` | Show available commands |
| `/status` | Get overall SOC status summary |
| `@ADA` | Direct a question to the Anomaly Detection Agent |
| `@TAA` | Direct a question to the Threat Analysis Agent |
| `@CRA` | Direct a question to the Containment Response Agent |
| `@CLA` | Direct a question to the Compliance & Logging Agent |
| `@RVA` | Direct a question to the Risk & Vulnerability Agent |

### IOC Lookups in Chat

Paste an IP address, domain, hash, or URL directly into the chat:
- The system auto-detects the indicator type
- Queries ThreatFox, URLhaus, and MalwareBazaar in real time
- Returns threat intelligence results inline

**Example:** Type `8.8.8.8` or `evil-domain.com` and the agent will look it up.

### Quick Action Buttons

At the bottom of the chat, shortcut buttons are available:
- **Alert** — Create a new alert reference
- **Location** — Tag a geographic location
- **Incident** — Open an incident report
- **/help** — Show help

---

## 6. A2A Security Monitor

The **A2A (Agent-to-Agent) Security Monitor** shows how GATRA agents communicate and validates the trust level of inter-agent traffic.

### 6.1 Agent Registry

Lists all registered agents with:
- Online/offline status (green/red dot)
- Trust score bar (0–100)
- Agent role and description

**Trust Score Levels:**
| Score | Level | Meaning |
|-------|-------|---------|
| 85–100 | Trusted | Internal GATRA agents, verified partners |
| 60–84 | Verified | External agents with validated certificates |
| 40–59 | Pending | Agents awaiting verification |
| 0–39 | Blocked | Untrusted or malicious agents |

### 6.2 Endpoint Health

Shows connectivity status for each agent endpoint:
- Green = healthy, Red = unreachable
- Latency in milliseconds
- Version information

### 6.3 A2A Console

Interactive command interface:
- Select a target agent from the dropdown
- Type a command or query
- View the formatted response

### 6.4 Security Tests

A grid of security test cards you can run:
- Click **Run** to execute a test
- Results show pass (green), fail (red), or running (yellow)
- Tests verify certificate validity, encryption, injection resistance

### 6.5 Traffic Feed

Live stream of agent-to-agent communication:
- **Clean** (green) — Verified, normal traffic
- **Suspicious** (yellow) — Potential injection or drift detected
- **Blocked** (red) — Malicious traffic rejected

Shows: timestamp, route (sender -> receiver), skill/method, and verdict.

### 6.6 CII-Aware Trust Policy

Trust policies automatically adjust based on the Country Instability Index:
- **Standard** (CII normal): Relaxed trust thresholds
- **Elevated** (CII rising): Tighter validation, manual approval required
- **Critical** (CII spike): Maximum security, block low-trust agents

---

## 7. Social Threat Intel

The **Social Threat Intel** panel monitors cybersecurity discussions across three open social platforms in real time.

### Data Sources

| Platform | What It Monitors | Badge Color |
|----------|-----------------|-------------|
| **Hacker News** | Top cybersecurity stories (Algolia API) | Orange |
| **Mastodon** | #cybersecurity and #infosec hashtag feeds (mastodon.social + hachyderm.io) | Purple |
| **Bluesky** | Cybersecurity keyword search (AT Protocol) | Blue |

### Platform Filter Tabs

Click the tabs at the top to filter by platform:
- **All** — Combined feed from all sources
- **Bluesky** — Bluesky posts only
- **HN** — Hacker News stories only
- **Mastodon** — Mastodon toots only

Each tab shows the count of posts from that platform.

### Stats Row

| Metric | Description |
|--------|-------------|
| **Posts** | Total posts in the current view |
| **Threats** | Posts containing threat-related keywords |
| **Engage** | Total engagement (likes + reposts + replies) |
| **Trending** | Most mentioned threat keyword |

### Post Cards

Each post displays:
- **Platform badge** (color-coded by source)
- **Author** — Display name + handle
- **Content** — First 200 characters with threat keywords highlighted in red
- **Threat keyword badges** (e.g., "CVE-2026-XXXX", "ransomware", "zero-day")
- **Engagement** — Likes, reposts, replies counts
- **Timestamp** — Relative time (e.g., "2h ago")

Click any post to open the original on its platform.

### Threat Keyword Detection

The system automatically highlights mentions of:
CVE IDs, ransomware, malware, phishing, exploit, zero-day, breach, DDoS, APT, vulnerability, botnet, C2, backdoor, supply chain attack

### Refresh Rate

Data refreshes every **10 minutes**. The footer shows when the data was last updated.

---

## 8. CVE Feed

The **CVE Feed** panel shows the latest vulnerabilities from the National Vulnerability Database (NVD) and CISA Known Exploited Vulnerabilities catalog.

### Stats Row

| Metric | Description |
|--------|-------------|
| **Total** | All CVEs in the current feed |
| **Critical** | CVSS score 9.0–10.0 |
| **High** | CVSS score 7.0–8.9 |
| **Exploited** | In CISA KEV catalog (actively exploited in the wild) |

### CVE List

Each entry shows:
- **CVSS score badge** — Color-coded (red = critical, orange = high, yellow = medium, blue = low)
- **CVE ID** — e.g., CVE-2026-12345
- **KEV badge** — Red pulsing "KEV" tag if actively exploited
- **CWE ID** — Weakness classification (if available)
- **Published date** — Relative time
- **Description** — Vulnerability summary (2 lines)
- **Affected products** — Vendor and product names

**Refresh:** Every 10 minutes from NVD v2 API.

---

## 9. IoC Lookup

The **IoC Lookup** panel lets you search any Indicator of Compromise against multiple threat intelligence feeds.

### How to Search

1. Type or paste an indicator into the search box:
   - **IP address** — e.g., `192.168.1.1`
   - **Domain** — e.g., `malicious-site.com`
   - **Hash** — MD5, SHA1, or SHA256
   - **URL** — e.g., `https://phishing-page.com/login`
2. The system auto-detects the type and shows a colored badge (IP = blue, Domain = purple, Hash = pink, URL = amber)
3. Click **Search** or press Enter

### Results View

After searching:
- **Threat Level** — Malicious (red) / Suspicious (orange) / Clean (green) / Unknown (gray)
- **Source Verdicts** — Results from ThreatFox, URLhaus, MalwareBazaar, and others
- **Tags** — Malware family, infection vectors
- **Timeline** — First seen, last seen
- **Related IOCs** — Linked indicators (click to pivot search)

### Default View (No Search)

When no search is active, the panel shows the **Recent Threats** feed from ThreatFox — the latest 24 hours of reported indicators.

---

## 10. Ransomware Tracker

The **Ransomware Tracker** panel monitors active ransomware groups and their latest victims.

### Stats Row

| Metric | Description |
|--------|-------------|
| **Victims (30d)** | Total victims claimed in the last 30 days |
| **Top Group** | Most active ransomware group + victim count |
| **Top Country** | Most targeted country |

### Top Groups Chart

Horizontal bar chart showing the top 5 most active ransomware groups by victim count. Each group has a deterministic color for consistency.

### Recent Victims Feed

Scrollable list of the latest ransomware victims:
- **Group badge** — Color-coded by ransomware group
- **Victim name** — Organization or company
- **Country** — Flag + country code
- **Sector** — Industry (if known)
- **Discovered date** — When the claim was posted

**Data Source:** ransomware.live API. **Refresh:** Every 5 minutes.

---

## 11. CII Monitor

The **CII (Country Instability Index) Monitor** tracks geopolitical instability scores for Indonesia and ASEAN countries.

### Indonesia Focus Card

- **Large score display** (0–100)
  - Green (<30): Stable
  - Yellow (30–59): Moderate instability
  - Orange (60–79): Elevated instability
  - Red (80+): Critical instability
- **Trend arrow** — Shows direction of change
- **Sparkline chart** — 24-hour historical trend
- **Regime type** — Current governance classification

### R_geo Impact Signal

Shows how the instability score feeds into the GATRA reinforcement learning reward function:
- **Status:** "Active" (yellow) or "Nominal" (green)
- **Value:** Computed impact on SOC defensive posture
- Higher R_geo = SOC agents adopt more aggressive detection/containment

### Regional Grid

Compact grid showing CII scores for neighboring countries:
- Singapore, Malaysia, Philippines, Thailand, Vietnam, Australia, PNG, Myanmar, China
- Each shows: flag, score, trend, and mini progress bar

---

## 12. Prediction Signals

The **Prediction Signals** panel monitors prediction market data for geopolitical events that could impact cybersecurity posture.

### Early Warning Multiplier

A composite score (1.0–3.0) at the top:
- **1.0** = Nominal geopolitical baseline
- **1.5+** = Elevated risk signals detected
- **2.0+** = Multiple high-confidence risk indicators

### Market Cards

Each tracked market shows:
- **Question** — What the market is predicting
- **Probability bar** — Visual 0–100%
- **Threat level** — CRITICAL / HIGH / ELEVATED / MODERATE / LOW
- **Relevance tier:**
  - Tier 1: Direct impact on Indonesia
  - Tier 2: Regional (ASEAN) impact
  - Tier 3: Global conflict/security
  - Tier 4: Economic/commodity impact
- **Volume** — Market size
- **Velocity** — How fast the probability is changing (higher = more urgent)

---

## 13. Security Posture

The **Personal Security Posture** panel helps individual analysts assess their own cybersecurity hygiene.

### Categories Scored

- **Authentication** — Password strength, 2FA usage, password manager
- **Device Security** — OS updates, antivirus, disk encryption, screen lock
- **Online Behavior** — VPN usage, link checking, software updates, data backup

### Auto-Scan Features

The panel can automatically detect:
- Browser type and version (outdated = risk)
- Whether the connection uses HTTPS
- Email domain security (SPF/DKIM/DMARC)

### Score Display

Overall score (0–100) with color-coded grade:
- 80–100: Strong (green)
- 60–79: Moderate (yellow)
- Below 60: Weak (red)

---

## 14. Customization & Settings

### Theme

Toggle between **Dark** and **Light** mode:
- Click the moon/sun icon in the header
- Preference is saved to browser storage

### Language

Select your preferred language from the dropdown:
- English, Bahasa Indonesia, Spanish, French, German, Japanese, Arabic, and more

### Panel Visibility

Open the sidebar to toggle panels on/off. Your selection persists across sessions.

### Map Layer Toggles

Click the layer icon on the map to show/hide individual data layers. Preferences are saved.

### Panel Reordering

Panels can be reordered by dragging. Your custom order is saved locally.

---

## 15. URL Deep Linking

You can share specific dashboard views using URL parameters:

```
https://worldmonitor-gatra.vercel.app/?view=global&zoom=4&layers=gatraAlerts,cyberThreats&timeRange=24h
```

### Available Parameters

| Parameter | Values | Example |
|-----------|--------|---------|
| `view` | `global`, `us` | `?view=global` |
| `zoom` | 1–20 | `&zoom=4` |
| `center` | lat,lon | `&center=10.5,106.8` |
| `layers` | comma-separated | `&layers=gatraAlerts,cables,outages` |
| `timeRange` | `1h`, `6h`, `24h`, `7d`, `all` | `&timeRange=24h` |
| `panels` | comma-separated panel IDs | `&panels=gatra-soc,cve-feed` |
| `theme` | `dark`, `light` | `&theme=dark` |
| `country` | ISO code | `&country=ID` |

### Useful Bookmarks

| View | URL |
|------|-----|
| **Full Cyber Dashboard** | `?view=global&zoom=2.5&layers=gatraAlerts,cyberThreats,cables,outages` |
| **Indonesia Focus** | `?view=global&zoom=5&center=-2.5,118&layers=gatraAlerts,cyberThreats&country=ID` |
| **Gulf Region** | `?view=global&zoom=5&center=25,52&layers=flights,cables,conflicts` |
| **SOC Analyst View** | `?panels=gatra-soc,ioc-lookup,ransomware-tracker&timeRange=24h` |

---

## 16. Data Sources & Refresh Rates

| Panel | Data Source | Refresh Interval |
|-------|------------|-----------------|
| GATRA SOC | CISA KEV catalog (via edge proxy) | 60 seconds |
| CVE Feed | NVD v2 API | 10 minutes |
| Social Threat Intel | HackerNews Algolia + Mastodon + Bluesky | 10 minutes |
| IoC Lookup | ThreatFox / URLhaus / MalwareBazaar | On-demand (5-min cache) |
| Ransomware Tracker | ransomware.live API | 5 minutes |
| CII Monitor | Prediction markets + geopolitical feeds | 5 minutes |
| Prediction Signals | Polymarket / prediction APIs | 5 minutes |
| A2A Security | Internal agent traffic (simulated) | Real-time |
| Map Layers | Multiple (AIS, flight, UCDP, USGS, etc.) | 2–10 minutes |

All API responses are cached to minimize bandwidth and avoid rate limits. Background tabs automatically reduce polling frequency by 4x.

---

## 17. Troubleshooting

### Dashboard shows "MOCK" data

The live API may be temporarily unavailable. The dashboard automatically falls back to realistic mock data. Wait a few minutes and refresh — live data will restore automatically.

### Panels show "No alerts" or are empty

- Check your **time range filter** — you may have it set to "1h" with no recent data
- Check your **Relevant Only filter** in GATRA SOC — toggle it off to see all alerts
- Ensure your browser is not blocking API calls (check console for CORS errors)

### Map is blank or slow

- Reduce the number of active map layers (disable layers you don't need)
- Zoom into a specific region rather than viewing the full globe
- Close unused browser tabs to free memory

### SOC COMMS agents not responding

- Make sure your message contains relevant keywords (see Section 5)
- Use `@ADA`, `@TAA`, `@CRA`, `@CLA`, or `@RVA` to explicitly target an agent
- Try `/help` for available commands

### Browser recommendations

- **Best:** Chrome 120+ or Firefox 120+ on desktop
- **Good:** Edge, Safari (macOS)
- **Limited:** Mobile browsers (reduced features, simplified layout)

### Reporting issues

If you encounter bugs or have feature requests, contact the GATRA development team or file an issue on the project repository.

---

*GATRA World Monitor is an AI-Driven Security Operations Center platform designed for Tier-1 telecom and critical infrastructure operators. It combines real-time threat intelligence, reinforcement learning-based alert triage, and multi-agent coordination to deliver actionable cybersecurity intelligence.*
