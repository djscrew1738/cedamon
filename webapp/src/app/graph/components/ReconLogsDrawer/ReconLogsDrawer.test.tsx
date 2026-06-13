import { describe, test, expect } from 'vitest'
import { isVulnerabilityLine } from './ReconLogsDrawer'

describe('isVulnerabilityLine', () => {
  test('matches RedAmon vulnerability summaries', () => {
    expect(isVulnerabilityLine('[+][Nuclei] Vuln findings: 10')).toBe(true)
    expect(isVulnerabilityLine('[+][GraphQL] Vulnerabilities found: 5')).toBe(true)
    expect(isVulnerabilityLine('[+][Nmap] NSE vulnerabilities found: 3')).toBe(true)
  })

  test('matches severity count lines', () => {
    expect(isVulnerabilityLine('[+][Nuclei]   CRITICAL: 2')).toBe(true)
    expect(isVulnerabilityLine('[+][Nuclei]   HIGH: 5')).toBe(true)
    expect(isVulnerabilityLine('[+][Nuclei]   MEDIUM: 8')).toBe(true)
    expect(isVulnerabilityLine('[+][Nuclei]   LOW: 12')).toBe(true)
  })

  test('matches Nmap NSE VULN lines', () => {
    expect(isVulnerabilityLine('[+][Nmap] VULN: ftp-vsftpd-backdoor on 10.0.0.1:21')).toBe(true)
    expect(isVulnerabilityLine('[+][Nmap] VULNERABLE: vsFTPd backdoor')).toBe(true)
  })

  test('matches raw Nuclei severity tags', () => {
    expect(isVulnerabilityLine('[critical] http://target.com/admin')).toBe(true)
    expect(isVulnerabilityLine('[high] http://target.com/api')).toBe(true)
    expect(isVulnerabilityLine('[medium] http://target.com/login')).toBe(true)
    expect(isVulnerabilityLine('[low] http://target.com/icon')).toBe(true)
  })

  test('matches literal CVE identifiers', () => {
    expect(isVulnerabilityLine('[+][CVE] Found CVE-2021-44228 on target')).toBe(true)
  })

  test('does not match plain action/info lines', () => {
    expect(isVulnerabilityLine('[*][Nuclei] Running vulnerability scan...')).toBe(false)
    expect(isVulnerabilityLine('[*][Pipeline] Starting phase 4')).toBe(false)
    expect(isVulnerabilityLine('[info] http://target.com/robots.txt')).toBe(false)
  })
})
