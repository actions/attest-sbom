import {
  calculateSHA256,
  generateReferencePredicate,
  getMediaType,
  REFERENCE_PREDICATE_TYPE
} from '../src/reference'
import * as fs from 'fs'
import os from 'os'
import * as path from 'path'

describe('calculateSHA256', () => {
  let tempDir = '/'

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'reference'))
  })

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true })
  })

  it('calculates correct SHA-256 digest', async () => {
    const content = 'test content for hashing'
    const filePath = path.join(tempDir, 'test.json')
    fs.writeFileSync(filePath, content)

    const digest = await calculateSHA256(filePath)

    // Expected SHA-256 of 'test content for hashing'
    expect(digest).toBe(
      'e25dd806d495b413931f4eea50b677a7a5c02d00460924661283f211a37f7e7f'
    )
  })

  it('produces different digests for different content', async () => {
    const file1 = path.join(tempDir, 'file1.json')
    const file2 = path.join(tempDir, 'file2.json')
    fs.writeFileSync(file1, 'content one')
    fs.writeFileSync(file2, 'content two')

    const digest1 = await calculateSHA256(file1)
    const digest2 = await calculateSHA256(file2)

    expect(digest1).not.toBe(digest2)
  })
})

describe('generateReferencePredicate', () => {
  it('generates correct reference predicate structure', () => {
    const params = {
      attesterId: 'https://github.com/owner/repo/.github/workflows/ci.yml',
      downloadLocation:
        'https://github.com/owner/repo/releases/download/sbom/sbom.json',
      digest: 'abc123def456',
      mediaType: 'application/spdx+json'
    }

    const predicate = generateReferencePredicate(params)

    expect(predicate.type).toBe(REFERENCE_PREDICATE_TYPE)
    expect(predicate.params).toEqual({
      attester: {
        id: 'https://github.com/owner/repo/.github/workflows/ci.yml'
      },
      references: [
        {
          downloadLocation:
            'https://github.com/owner/repo/releases/download/sbom/sbom.json',
          digest: {
            sha256: 'abc123def456'
          },
          mediaType: 'application/spdx+json'
        }
      ]
    })
  })
})

describe('getMediaType', () => {
  it('returns correct media type for SPDX', () => {
    expect(getMediaType('spdx')).toBe('application/spdx+json')
  })

  it('returns correct media type for CycloneDX', () => {
    expect(getMediaType('cyclonedx')).toBe('application/vnd.cyclonedx+json')
  })
})
