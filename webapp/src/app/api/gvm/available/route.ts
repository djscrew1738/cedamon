import { NextResponse } from 'next/server'
import { orchestratorFetch } from '@/lib/orchestratorFetch'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

export async function GET() {
  try {
    const response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/health`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })

    if (!response.ok) {
      return NextResponse.json({ available: false })
    }

    const data = await response.json()
    const available = data.gvm_available ?? false
    const ready = data.gvm_ready ?? false
    return NextResponse.json({
      available,
      ready,
      message: available && !ready
        ? 'GVM is installed but still syncing vulnerability feeds. Scans will be disabled until sync completes.'
        : undefined,
    })
  } catch {
    return NextResponse.json({ available: false, ready: false })
  }
}
