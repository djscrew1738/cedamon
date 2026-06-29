import { NextRequest, NextResponse } from 'next/server'
import { createWriteStream, existsSync, mkdirSync, statSync } from 'fs'
import { join, dirname } from 'path'
import { pipeline } from 'stream/promises'
import { Readable } from 'stream'

/**
 * GET /api/wordlists/seclists — List or download SecLists wordlists.
 *
 * ?action=list     — Return a catalog of available wordlists grouped by category
 * ?action=download — Download a specific wordlist by path
 *   &path=/Discovery/Web-Content/common.txt
 *
 * Wordlists are cached locally in /data/wordlists/seclists/
 */

const SECLISTS_REPO = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master'
const WORDLISTS_DIR = process.env.WORDLISTS_DIR || '/data/wordlists/seclists'

// Curated catalog of useful wordlists grouped by category.
const CATALOG = {
  'Web Content': [
    { name: 'common.txt', path: '/Discovery/Web-Content/common.txt', size: '25KB', desc: 'Most common web paths' },
    { name: 'directory-list-2.3-small.txt', path: '/Discovery/Web-Content/directory-list-2.3-small.txt', size: '400KB', desc: 'Small directory list' },
    { name: 'directory-list-2.3-medium.txt', path: '/Discovery/Web-Content/directory-list-2.3-medium.txt', size: '1.2MB', desc: 'Medium directory list' },
    { name: 'directory-list-2.3-big.txt', path: '/Discovery/Web-Content/directory-list-2.3-big.txt', size: '10MB', desc: 'Large directory list' },
    { name: 'raft-large-directories.txt', path: '/Discovery/Web-Content/raft-large-directories.txt', size: '5.6MB', desc: 'Raft large directories' },
    { name: 'raft-medium-directories.txt', path: '/Discovery/Web-Content/raft-medium-directories.txt', size: '890KB', desc: 'Raft medium directories' },
    { name: 'raft-small-directories.txt', path: '/Discovery/Web-Content/raft-small-directories.txt', size: '140KB', desc: 'Raft small directories' },
    { name: 'big.txt', path: '/Discovery/Web-Content/big.txt', size: '4.5MB', desc: 'Large combined wordlist' },
    { name: 'quickhits.txt', path: '/Discovery/Web-Content/quickhits.txt', size: '10KB', desc: 'Quick-win paths' },
  ],
  'API Endpoints': [
    { name: 'api-endpoints-res.txt', path: '/Discovery/Web-Content/api/api-endpoints-res.txt', size: '113KB', desc: 'REST API endpoints' },
    { name: 'api-seen-in-wild.txt', path: '/Discovery/Web-Content/api/api-seen-in-wild.txt', size: '36KB', desc: 'APIs seen in the wild' },
  ],
  'Passwords': [
    { name: 'darkweb2017-top10000.txt', path: '/Passwords/Common-Credentials/darkweb2017-top10000.txt', size: '83KB', desc: 'Top 10K passwords from darkweb leaks' },
    { name: '10-million-password-list-top-100000.txt', path: '/Passwords/Common-Credentials/10-million-password-list-top-100000.txt', size: '800KB', desc: 'Top 100K passwords' },
    { name: 'xato-net-10-million-passwords-100000.txt', path: '/Passwords/xato-net-10-million-passwords-100000.txt', size: '800KB', desc: 'Xato top 100K' },
    { name: '500-worst-passwords.txt', path: '/Passwords/Common-Credentials/500-worst-passwords.txt', size: '4KB', desc: '500 most common passwords' },
  ],
  'Usernames': [
    { name: 'names.txt', path: '/Usernames/Names/names.txt', size: '1MB', desc: 'Common names/usernames' },
    { name: 'top-usernames-shortlist.txt', path: '/Usernames/top-usernames-shortlist.txt', size: '2KB', desc: 'Top usernames shortlist' },
  ],
  'Subdomains': [
    { name: 'subdomains-top1million-5000.txt', path: '/Discovery/DNS/subdomains-top1million-5000.txt', size: '40KB', desc: 'Top 5K subdomains' },
    { name: 'subdomains-top1million-20000.txt', path: '/Discovery/DNS/subdomains-top1million-20000.txt', size: '165KB', desc: 'Top 20K subdomains' },
    { name: 'subdomains-top1million-110000.txt', path: '/Discovery/DNS/subdomains-top1million-110000.txt', size: '890KB', desc: 'Top 110K subdomains' },
    { name: 'bitquark-subdomains-top100000.txt', path: '/Discovery/DNS/bitquark-subdomains-top100000.txt', size: '760KB', desc: 'Bitquark top 100K' },
  ],
  'Fuzzing': [
    { name: 'php.txt', path: '/Fuzzing/extensions-skipfish.fuzz.txt', size: '1KB', desc: 'Common extensions' },
    { name: 'LFI-JHADDIX.txt', path: '/Fuzzing/LFI/LFI-Jhaddix.txt', size: '12KB', desc: 'LFI payloads' },
    { name: 'UnixAttacks.fuzzdb.txt', path: '/Fuzzing/UnixAttacks.fuzzdb.txt', size: '4KB', desc: 'Unix attack strings' },
  ],
}

function localPath(seclistPath: string): string {
  return join(WORDLISTS_DIR, seclistPath)
}

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url)
  const action = searchParams.get('action') || 'list'

  try {
    if (action === 'list') {
      // Return the catalog with download status for each entry.
      const enriched = Object.entries(CATALOG).map(([category, lists]) => ({
        category,
        lists: lists.map(item => ({
          ...item,
          downloaded: existsSync(localPath(item.path)),
        })),
      }))

      return NextResponse.json({ catalog: enriched })
    }

    if (action === 'download') {
      const seclistPath = searchParams.get('path')
      if (!seclistPath) {
        return NextResponse.json({ error: 'path parameter required' }, { status: 400 })
      }

      // Security: prevent path traversal.
      if (seclistPath.includes('..') || seclistPath.startsWith('/')) {
        return NextResponse.json({ error: 'Invalid path' }, { status: 400 })
      }

      const targetPath = localPath(seclistPath)
      const url = `${SECLISTS_REPO}/${seclistPath}`

      // Return existing file if already downloaded.
      if (existsSync(targetPath)) {
        const stats = statSync(targetPath)
        return NextResponse.json({
          status: 'cached',
          path: targetPath,
          size: stats.size,
        })
      }

      // Download from GitHub.
      mkdirSync(dirname(targetPath), { recursive: true })

      const response = await fetch(url)
      if (!response.ok) {
        return NextResponse.json(
          { error: `Failed to download: HTTP ${response.status}` },
          { status: response.status }
        )
      }

      if (!response.body) {
        return NextResponse.json({ error: 'Empty response body' }, { status: 500 })
      }

      // Stream to disk.
      const nodeStream = Readable.fromWeb(response.body as any)
      const fileStream = createWriteStream(targetPath)
      await pipeline(nodeStream, fileStream)

      const stats = statSync(targetPath)

      return NextResponse.json({
        status: 'downloaded',
        path: targetPath,
        size: stats.size,
      })
    }

    return NextResponse.json({ error: 'Invalid action' }, { status: 400 })
  } catch (error) {
    console.error('Wordlist API error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}
