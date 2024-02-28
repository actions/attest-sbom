import {
  storePredicate,
  parseSBOMFromPath,
  generateSBOMPredicate,
  SBOM
} from '../src/sbom'
import type { Predicate } from '@actions/attest'
import * as fs from 'fs'

// Mock the specific function before your tests or in a beforeEach if you need it fresh for each test
fs.promises.readFile = jest.fn().mockImplementation(() => 'mocked value')

describe('parseSBOMFromPath', () => {
  it('correctly parses an SPDX file', async () => {
    const spdxSBOM = JSON.stringify({
      spdxVersion: 'SPDX-2.2',
      SPDXID: 'SPDXRef-DOCUMENT'
    })
    ;(fs.promises.readFile as jest.Mock).mockResolvedValue(spdxSBOM)
    await expect(parseSBOMFromPath('dummyPath')).resolves.toEqual({
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
    ;(fs.promises.readFile as jest.Mock).mockResolvedValue(cycloneDXSBOM)
    await expect(parseSBOMFromPath('dummyPath')).resolves.toEqual({
      type: 'cyclonedx',
      object: JSON.parse(cycloneDXSBOM)
    })
  })

  it('throws an error for unsupported SBOM formats', async () => {
    (fs.promises.readFile as jest.Mock).mockResolvedValue('{}')
    await expect(parseSBOMFromPath('dummyPath')).rejects.toThrow(
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
