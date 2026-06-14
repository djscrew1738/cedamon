/**
 * Unit tests for GET /api/recon/[projectId]/attacks/suggestions.
 *
 * Run: npx vitest run src/app/api/recon/\[projectId\]/attacks/suggestions/route.test.ts
 */

import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockProjectFindUnique = vi.fn()
const mockSessionRun = vi.fn()
const mockSessionClose = vi.fn()
const mockGetSession = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => mockProjectFindUnique(...a) },
  },
}))

vi.mock('@/app/api/graph/neo4j', () => ({
  getSession: () => mockGetSession(),
}))

import { GET } from './route'

function makeRequest(projectId: string) {
  return new Request(`http://localhost/api/recon/${projectId}/attacks/suggestions`) as never
}

function makeParams(projectId: string) {
  return Promise.resolve({ projectId }) as never
}

function intNode(value: number) {
  return { toNumber: () => value }
}

function record(count: number) {
  return { get: (key: string) => (key === 'count' ? intNode(count) : null) }
}

beforeEach(() => {
  mockProjectFindUnique.mockReset()
  mockSessionRun.mockReset()
  mockSessionClose.mockReset()
  mockGetSession.mockReset()

  mockProjectFindUnique.mockResolvedValue({ targetDomain: 'example.com' })
  mockGetSession.mockReturnValue({
    run: mockSessionRun,
    close: mockSessionClose,
  })
})

describe('GET /api/recon/[projectId]/attacks/suggestions', () => {
  test('returns suggestions when graph nodes exist', async () => {
    // Return non-zero counts for every suggestion query in order
    mockSessionRun.mockResolvedValue({ records: [record(1)] })

    const res = await GET(makeRequest('proj-1'), { params: makeParams('proj-1') })
    expect(res.status).toBe(200)

    const json = await res.json()
    expect(json.suggestions.length).toBeGreaterThan(0)
    expect(json.projectId).toBe('proj-1')

    // Each suggestion should carry the project domain in graphInputs
    for (const s of json.suggestions) {
      expect(s.graphInputs.domain).toBe('example.com')
      expect(s.graphInputs.projectId).toBe('proj-1')
      expect(s.matchedNodeCount).toBeGreaterThan(0)
    }
  })

  test('returns empty suggestions when no graph nodes match', async () => {
    mockSessionRun.mockResolvedValue({ records: [record(0)] })

    const res = await GET(makeRequest('proj-1'), { params: makeParams('proj-1') })
    expect(res.status).toBe(200)

    const json = await res.json()
    expect(json.suggestions).toEqual([])
  })

  test('marks a tool as alreadyRun when its output nodes exist in the graph', async () => {
    // Match counts for all suggestions, then output-node checks for tools with alreadyRunCypher.
    // We return 1 for every call so all suggestions are present and all alreadyRun checks pass.
    mockSessionRun.mockResolvedValue({ records: [record(1)] })

    const res = await GET(makeRequest('proj-1'), { params: makeParams('proj-1') })
    const json = await res.json()

    const nuclei = json.suggestions.find((s: { id: string }) => s.id === 'nuclei-scan')
    expect(nuclei).toBeDefined()
    expect(nuclei.alreadyRun).toBe(true)
  })

  test('returns 404 when project does not exist', async () => {
    mockProjectFindUnique.mockResolvedValue(null)

    const res = await GET(makeRequest('proj-1'), { params: makeParams('proj-1') })
    expect(res.status).toBe(404)
  })
})
