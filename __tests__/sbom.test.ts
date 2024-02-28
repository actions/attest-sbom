import {
  storePredicate,
  parseSBOMFromPath,
  generateSBOMPredicate,
  SBOM
} from '../src/sbom'
import type { Predicate } from '@actions/attest'
import * as fs from 'fs'
import os from 'os'
import * as path from 'path'

describe('parseSBOMFromPath', () => {
  let tempDir = '/'

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom'))
  })

  afterEach(() => {
    fs.rmdirSync(tempDir, { recursive: true })
  })

  it('correctly parses an SPDX file', async () => {
    const spdxSBOM = JSON.stringify({
      spdxVersion: 'SPDX-2.2',
      SPDXID: 'SPDXRef-DOCUMENT'
    })
    const filePath = path.join(tempDir, 'spdxSBOM.json')
    fs.writeFileSync(filePath, spdxSBOM)
    await expect(parseSBOMFromPath(filePath)).resolves.toEqual({
      type: 'spdx',
      object: JSON.parse(spdxSBOM)
    })
  })

  it('correctly parses a CycloneDX file', async () => {
    const cycloneDXSBOM = JSON.stringify({
      bomFormat: 'CycloneDX',
      serialNumber: '123',
      specVersion: '1.2'
    })
    const filePath = path.join(tempDir, 'cyclonedxSBOM.json')
    fs.writeFileSync(filePath, cycloneDXSBOM)

    await expect(parseSBOMFromPath(filePath)).resolves.toEqual({
      type: 'cyclonedx',
      object: JSON.parse(cycloneDXSBOM)
    })
  })

  it('throws an error for unsupported SBOM formats', async () => {
    const filePath = path.join(tempDir, 'random.json')
    fs.writeFileSync(filePath, JSON.stringify({ random: 'value' }))
    await expect(parseSBOMFromPath(filePath)).rejects.toThrow(
      'Unsupported SBOM format'
    )
  })
})

describe('storePredicate', () => {
  it('should store the predicate to a temporary file', () => {
    const predicate = { params: { key: 'value' } } as Predicate

    // Mocking the process.env['RUNNER_TEMP'] value
    const originalEnv = process.env
    process.env = { ...originalEnv, RUNNER_TEMP: '/tmp' }

    const tempFile = storePredicate(predicate)

    // Verify that the temporary file exists
    expect(fs.existsSync(tempFile)).toBe(true)

    // Read the content of the temporary file
    const fileContent = fs.readFileSync(tempFile, 'utf-8')

    // Verify that the content matches the predicate params
    expect(JSON.parse(fileContent)).toEqual(predicate.params)

    // Clean up the temporary file
    fs.unlinkSync(tempFile)

    // Restore the original process.env
    process.env = originalEnv
  })

  it('should throw an error if RUNNER_TEMP environment variable is missing', () => {
    const predicate = { params: { key: 'value' } } as Predicate

    // Mocking the process.env['RUNNER_TEMP'] value
    const originalEnv = process.env
    process.env = {}

    // Verify that an error is thrown
    expect(() => storePredicate(predicate)).toThrow(
      'Missing RUNNER_TEMP environment variable'
    )

    // Restore the original process.env
    process.env = originalEnv
  })
})

describe('generateSBOMPredicate', () => {
  it('generates SPDX predicate correctly', () => {
    const sbom = { type: 'spdx', object: { spdxVersion: 'SPDX-2.2' } } as SBOM
    const result = generateSBOMPredicate(sbom)
    expect(result.type).toContain('https://spdx.dev/Document/v2.2')
    expect(result.params).toEqual(sbom.object)
  })

  it('generates CycloneDX predicate correctly', () => {
    const sbom = { type: 'cyclonedx', object: {} } as SBOM
    const result = generateSBOMPredicate(sbom)
    expect(result.type).toEqual('https://cyclonedx.org/bom')
    expect(result.params).toEqual(sbom.object)
  })

  it('throws error for unsupported SBOM formats', () => {
    const sbom = { type: 'spdx', object: {} }
    // @ts-expect-error test error case
    expect(() => generateSBOMPredicate(sbom)).toThrow(
      'Cannot find spdxVersion in the SBOM'
    )
  })
})
