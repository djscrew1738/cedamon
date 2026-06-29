'use client'

import { useState } from 'react'
import {
  ChevronDown, Globe, Wifi, Link2, Search, Bug, Shield,
  Database, Code2, Terminal, FolderTree, Brain, GitBranch,
  Container, KeyRound, Mail, Zap, FileSearch, Network, Server,
  Box, Activity,
} from 'lucide-react'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface ToolCatalogSectionProps {
  formData: FormData
}

interface ToolEntry {
  id: string
  name: string
  description: string
  icon: React.ReactNode
  isEnabled: boolean
}

function getToolCatalog(data: FormData): { category: string; icon: React.ReactNode; tools: ToolEntry[] }[] {
  const scanModules = data.scanModules as string[]
  const attackConfig = data.attackSkillConfig as { builtIn?: Record<string, boolean> } | undefined
  const builtIn = attackConfig?.builtIn ?? {}

  return [
    {
      category: 'Discovery & OSINT',
      icon: <Globe size={14} />,
      tools: [
        {
          id: 'subdomain_discovery',
          name: 'Subdomain Discovery',
          description: 'Enumerate subdomains via DNS brute-force, certificate transparency, and search engines',
          icon: <Globe size={14} />,
          isEnabled: (data.subdomainDiscoveryEnabled as boolean) !== false,
        },
        {
          id: 'shodan',
          name: 'Shodan',
          description: 'Enrich targets with Shodan internet-wide scan data',
          icon: <Server size={14} />,
          isEnabled: (data.shodanEnabled as boolean) !== false,
        },
        {
          id: 'urlscan',
          name: 'URLScan.io',
          description: 'Fetch historical snapshots and page metadata from URLScan.io',
          icon: <Activity size={14} />,
          isEnabled: (data.urlscanEnabled as boolean) !== false,
        },
        {
          id: 'osint_enrichment',
          name: 'OSINT Enrichment',
          description: 'Enrich targets with WHOIS, SSL certs, DNS history, and social profiles',
          icon: <Search size={14} />,
          isEnabled: (data.osintEnrichmentEnabled as boolean) !== false,
        },
      ],
    },
    {
      category: 'Port Scanning',
      icon: <Network size={14} />,
      tools: [
        {
          id: 'naabu',
          name: 'Naabu',
          description: 'Fast, concurrent TCP port scanner (default)',
          icon: <Wifi size={14} />,
          isEnabled: scanModules.includes('port_scan') && (data.naabuEnabled as boolean) !== false,
        },
        {
          id: 'masscan',
          name: 'Masscan',
          description: 'Ultra-fast Internet-scale port scanner (optional, for large ranges)',
          icon: <Zap size={14} />,
          isEnabled: scanModules.includes('port_scan') && (data.masscanEnabled as boolean) === true,
        },
        {
          id: 'nmap',
          name: 'Nmap',
          description: 'Service version detection, OS fingerprinting, and NSE scripts',
          icon: <Server size={14} />,
          isEnabled: scanModules.includes('port_scan') && (data.nmapEnabled as boolean) !== false,
        },
      ],
    },
    {
      category: 'HTTP Probing',
      icon: <Link2 size={14} />,
      tools: [
        {
          id: 'httpx',
          name: 'httpx',
          description: 'HTTP/HTTPS service probe, tech stack fingerprinting, screenshot capture',
          icon: <Link2 size={14} />,
          isEnabled: scanModules.includes('http_probe'),
        },
      ],
    },
    {
      category: 'Resource Enumeration',
      icon: <FileSearch size={14} />,
      tools: [
        {
          id: 'katana',
          name: 'Katana',
          description: 'Headless browser crawler — JavaScript-rendered page discovery',
          icon: <Search size={14} />,
          isEnabled: scanModules.includes('resource_enum') && (data.katanaEnabled as boolean) !== false,
        },
        {
          id: 'gau',
          name: 'GAU (Get All URLs)',
          description: 'Fetch known URLs from AlienVault, Wayback Machine, CommonCrawl',
          icon: <Globe size={14} />,
          isEnabled: scanModules.includes('resource_enum') && (data.gauEnabled as boolean) !== false,
        },
        {
          id: 'hakrawler',
          name: 'Hakrawler',
          description: 'Fast Golang web crawler for endpoint discovery',
          icon: <Activity size={14} />,
          isEnabled: scanModules.includes('resource_enum') && (data.hakrawlerEnabled as boolean) !== false,
        },
        {
          id: 'ffuf',
          name: 'FFuf',
          description: 'Fast web fuzzer — directory, file, vhost, and parameter brute-force',
          icon: <Zap size={14} />,
          isEnabled: scanModules.includes('resource_enum') && (data.ffufEnabled as boolean) !== false,
        },
        {
          id: 'jsluice',
          name: 'Jsluice',
          description: 'Extract URLs, secrets, and endpoints from JavaScript files',
          icon: <Code2 size={14} />,
          isEnabled: scanModules.includes('resource_enum') && (data.jsluiceEnabled as boolean) !== false,
        },
        {
          id: 'paramspider',
          name: 'ParamSpider',
          description: 'Mine web archives for parameter names used in target endpoints',
          icon: <Box size={14} />,
          isEnabled: scanModules.includes('resource_enum') && (data.paramspiderEnabled as boolean) !== false,
        },
        {
          id: 'kiterunner',
          name: 'Kiterunner',
          description: 'API endpoint brute-force with route-aware wordlists',
          icon: <Terminal size={14} />,
          isEnabled: scanModules.includes('resource_enum') && (data.kiterunnerEnabled as boolean) !== false,
        },
        {
          id: 'arjun',
          name: 'Arjun',
          description: 'HTTP parameter discovery — finds hidden GET/POST parameters',
          icon: <Search size={14} />,
          isEnabled: scanModules.includes('resource_enum') && (data.arjunEnabled as boolean) !== false,
        },
      ],
    },
    {
      category: 'Vulnerability Scanning',
      icon: <Bug size={14} />,
      tools: [
        {
          id: 'nuclei',
          name: 'Nuclei',
          description: 'Template-based vulnerability scanner — 1000+ CVE, misconfig, and exposure checks',
          icon: <Bug size={14} />,
          isEnabled: scanModules.includes('vuln_scan') && (data.nucleiEnabled as boolean) !== false,
        },
        {
          id: 'takeover',
          name: 'Subdomain Takeover',
          description: 'Check for dangling DNS records pointing to cloud services (S3, Azure, GitHub Pages, etc.)',
          icon: <Globe size={14} />,
          isEnabled: scanModules.includes('vuln_scan') && (data.subdomainTakeoverEnabled as boolean) !== false,
        },
        {
          id: 'graphql_scan',
          name: 'GraphQL Scan',
          description: 'Introspection query, field fuzzing, and batching attack detection',
          icon: <Activity size={14} />,
          isEnabled: scanModules.includes('vuln_scan') && (data.graphqlSecurityEnabled as boolean) !== false,
        },
        {
          id: 'vhost_sni',
          name: 'Virtual Host / SNI',
          description: 'Discover virtual hosts and SNI-based services via Host header fuzzing',
          icon: <Server size={14} />,
          isEnabled: scanModules.includes('vuln_scan') && (data.vhostSniEnabled as boolean) !== false,
        },
        {
          id: 'security_checks',
          name: 'Security Checks',
          description: 'SSL/TLS analysis, CORS misconfig, CSP analysis, cookie security audit',
          icon: <Shield size={14} />,
          isEnabled: (data.securityCheckEnabled as boolean) !== false,
        },
      ],
    },
    {
      category: 'Attack & Exploitation',
      icon: <Terminal size={14} />,
      tools: [
        {
          id: 'cve_exploit',
          name: 'CVE Exploit (MSF)',
          description: 'Exploit known CVEs using Metasploit Framework against discovered services',
          icon: <Bug size={14} />,
          isEnabled: builtIn.cve_exploit !== false,
        },
        {
          id: 'sql_injection',
          name: 'SQL Injection (SQLMap)',
          description: 'Automated SQLi detection, WAF bypass, blind injection, OOB DNS exfiltration',
          icon: <Database size={14} />,
          isEnabled: builtIn.sql_injection !== false,
        },
        {
          id: 'xss',
          name: 'XSS (dalfox)',
          description: 'Reflected, stored, DOM-based, and blind XSS with dalfox, kxss, Playwright',
          icon: <Code2 size={14} />,
          isEnabled: builtIn.xss !== false,
        },
        {
          id: 'ssrf',
          name: 'SSRF',
          description: 'SSRF detection, cloud-metadata pivots, protocol smuggling, DNS rebinding',
          icon: <Globe size={14} />,
          isEnabled: builtIn.ssrf !== false,
        },
        {
          id: 'rce',
          name: 'RCE / Command Injection',
          description: 'Shell metachar injection (commix), SSTI (sstimap), deserialization (ysoserial)',
          icon: <Terminal size={14} />,
          isEnabled: builtIn.rce !== false,
        },
        {
          id: 'path_traversal',
          name: 'Path Traversal / LFI / RFI',
          description: 'Arbitrary file read, PHP wrapper chains, log poisoning, Zip Slip',
          icon: <FolderTree size={14} />,
          isEnabled: builtIn.path_traversal !== false,
        },
        {
          id: 'container_k8s',
          name: 'Container & K8s Security',
          description: 'Image-layer analysis, RBAC enumeration, pod breakout, etcd exposure',
          icon: <Container size={14} />,
          isEnabled: builtIn.container_k8s !== false,
        },
        {
          id: 'brute_force',
          name: 'Credential Testing (Hydra)',
          description: 'Password policy validation against SSH, FTP, HTTP, RDP, SMB services',
          icon: <KeyRound size={14} />,
          isEnabled: builtIn.brute_force_credential_guess === true,
        },
        {
          id: 'cicd_pipeline',
          name: 'CI/CD Pipeline Attacks',
          description: 'GitHub Actions, GitLab CI, Jenkins pipeline abuse, dependency confusion',
          icon: <GitBranch size={14} />,
          isEnabled: builtIn.cicd_pipeline !== false,
        },
        {
          id: 'llm_security',
          name: 'GenAI / LLM Security',
          description: 'Prompt injection, jailbreaking, model extraction, RAG pipeline poisoning',
          icon: <Brain size={14} />,
          isEnabled: builtIn.llm_security !== false,
        },
      ],
    },
    {
      category: 'Secret & Credential Hunting',
      icon: <KeyRound size={14} />,
      tools: [
        {
          id: 'github_hunt',
          name: 'GitHub Secret Hunt',
          description: 'Scan organization repos for exposed credentials, tokens, and API keys',
          icon: <GitBranch size={14} />,
          isEnabled: (data.githubTargetOrg as string || '').length > 0,
        },
        {
          id: 'trufflehog',
          name: 'TruffleHog',
          description: 'Deep git history scanning for high-entropy secrets and verified credentials',
          icon: <Search size={14} />,
          isEnabled: (data.trufflehogEnabled as boolean) !== false,
        },
      ],
    },
  ]
}

export function ToolCatalogSection({ formData }: ToolCatalogSectionProps) {
  const [isOpen, setIsOpen] = useState(false)
  const catalog = getToolCatalog(formData)
  const totalTools = catalog.reduce((sum, cat) => sum + cat.tools.length, 0)
  const enabledTools = catalog.reduce(
    (sum, cat) => sum + cat.tools.filter(t => t.isEnabled).length,
    0,
  )

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Box size={16} />
          Available Pentesting Tools
        </h2>
        <div className={styles.sectionHeaderRight}>
          <span className={styles.toolCountBadge}>
            {enabledTools}/{totalTools} enabled
          </span>
          <ChevronDown
            size={16}
            className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
          />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Overview of all available reconnaissance and pentesting tools. Enabled tools will execute during the pipeline scan. Toggle individual tools in their respective configuration tabs.
          </p>

          <div className={styles.toolCatalog}>
            {catalog.map(cat => (
              <div key={cat.category} className={styles.toolCategory}>
                <div className={styles.toolCategoryHeader}>
                  {cat.icon}
                  <span className={styles.toolCategoryLabel}>{cat.category}</span>
                  <span className={styles.toolCategoryCount}>
                    {cat.tools.filter(t => t.isEnabled).length}/{cat.tools.length}
                  </span>
                </div>
                <div className={styles.toolList}>
                  {cat.tools.map(tool => (
                    <div
                      key={tool.id}
                      className={`${styles.toolItem} ${!tool.isEnabled ? styles.toolItemDisabled : ''}`}
                    >
                      <span className={`${styles.toolItemIcon} ${tool.isEnabled ? styles.toolItemIconActive : ''}`}>
                        {tool.icon}
                      </span>
                      <div className={styles.toolItemInfo}>
                        <span className={`${styles.toolItemName} ${!tool.isEnabled ? styles.toolItemNameDisabled : ''}`}>
                          {tool.name}
                        </span>
                        <span className={styles.toolItemDesc}>{tool.description}</span>
                      </div>
                      <span className={`${styles.toolItemStatus} ${tool.isEnabled ? styles.toolItemStatusOn : styles.toolItemStatusOff}`}>
                        {tool.isEnabled ? 'ON' : 'OFF'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
