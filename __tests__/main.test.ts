import * as core from '@actions/core'
import * as github from '@actions/github'
import * as main from '../src/main'
import * as fs from 'fs'
import os from 'os'
import * as path from 'path'
import { REFERENCE_PREDICATE_TYPE } from '../src/reference'

// Mock the GitHub Actions core library
jest.mock('@actions/core')
jest.mock('@actions/github')

const getInputMock = jest.spyOn(core, 'getInput')
const setOutputMock = jest.spyOn(core, 'setOutput')
const setFailedMock = jest.spyOn(core, 'setFailed')

// Ensure that setFailed doesn't set an exit code during tests
setFailedMock.mockImplementation(() => {})

// Mock Octokit
const mockUploadReleaseAsset = jest.fn()
const mockGetReleaseByTag = jest.fn()
const mockCreateRelease = jest.fn()

const mockOctokit = {
  rest: {
    repos: {
      uploadReleaseAsset: mockUploadReleaseAsset,
      getReleaseByTag: mockGetReleaseByTag,
      createRelease: mockCreateRelease
    }
  }
}

describe('SBOM Action', () => {
  let tempDir = '/'
  let outputs = {} as Record<string, string>

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom'))

    jest.resetAllMocks()
    setOutputMock.mockImplementation((key, value) => {
      outputs[key] = value
    })

    // Setup GitHub mock
    ;(github.getOctokit as jest.Mock).mockReturnValue(mockOctokit)

    // Default mock responses
    mockGetReleaseByTag.mockResolvedValue({ data: { id: 999 } })
    mockUploadReleaseAsset.mockResolvedValue({
      data: {
        browser_download_url:
          'https://github.com/test-owner/test-repo/releases/download/sbom/12345-spdxSBOM.json'
      }
    })
  })

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true })
    outputs = {}
  })

  it('successfully processes an SBOM and generates reference predicate', async () => {
    const spdxSBOM = JSON.stringify({
      spdxVersion: 'SPDX-2.2',
      SPDXID: 'SPDXRef-DOCUMENT',
      packages: []
    })
    const filePath = path.join(tempDir, 'spdxSBOM.json')
    fs.writeFileSync(filePath, spdxSBOM)

    const inputs: Record<string, string> = {
      'sbom-path': filePath,
      'github-token': 'fake-token'
    }
    getInputMock.mockImplementation(mockInput(inputs))
    const originalEnv = process.env
    process.env = { ...originalEnv, RUNNER_TEMP: '/tmp' }

    // Run the main function
    await main.run()

    // Verify that outputs were set correctly
    expect(setOutputMock).toHaveBeenCalledTimes(2)
    expect(setOutputMock).toHaveBeenCalledWith(
      'predicate-type',
      REFERENCE_PREDICATE_TYPE
    )
    expect(outputs['predicate-path']).toBeTruthy()
    const predicatePath = outputs['predicate-path']

    // Verify that the temporary file exists
    expect(fs.existsSync(predicatePath)).toBe(true)

    // Read the content of the temporary file
    const fileContent = fs.readFileSync(predicatePath, 'utf-8')
    const predicate = JSON.parse(fileContent) as {
      attester: { id: string }
      references: {
        downloadLocation: string
        mediaType: string
        digest: { sha256: string }
      }[]
    }

    // Verify reference predicate structure
    expect(predicate.attester.id).toBe(
      'https://github.com/test-owner/test-repo/.github/workflows/ci.yml'
    )
    expect(predicate.references).toHaveLength(1)
    expect(predicate.references[0].downloadLocation).toBe(
      'https://github.com/test-owner/test-repo/releases/download/sbom/12345-spdxSBOM.json'
    )
    expect(predicate.references[0].mediaType).toBe('application/spdx+json')
    expect(predicate.references[0].digest.sha256).toBeTruthy()

    // Verify GitHub API calls
    expect(github.getOctokit).toHaveBeenCalledWith('fake-token')
    expect(mockGetReleaseByTag).toHaveBeenCalledWith({
      owner: 'test-owner',
      repo: 'test-repo',
      tag: 'sbom'
    })
    expect(mockUploadReleaseAsset).toHaveBeenCalled()

    // Clean up the temporary file
    fs.unlinkSync(predicatePath)

    process.env = originalEnv
  })

  it('creates release if it does not exist', async () => {
    const spdxSBOM = JSON.stringify({
      spdxVersion: 'SPDX-2.2',
      SPDXID: 'SPDXRef-DOCUMENT'
    })
    const filePath = path.join(tempDir, 'spdxSBOM.json')
    fs.writeFileSync(filePath, spdxSBOM)

    const inputs: Record<string, string> = {
      'sbom-path': filePath,
      'github-token': 'fake-token'
    }
    getInputMock.mockImplementation(mockInput(inputs))
    const originalEnv = process.env
    process.env = { ...originalEnv, RUNNER_TEMP: '/tmp' }

    // Mock release not found
    mockGetReleaseByTag.mockRejectedValue({ status: 404 })
    mockCreateRelease.mockResolvedValue({ data: { id: 1000 } })

    await main.run()

    expect(mockCreateRelease).toHaveBeenCalledWith({
      owner: 'test-owner',
      repo: 'test-repo',
      tag_name: 'sbom',
      name: 'SBOM Attestations',
      body: 'This release contains SBOM files referenced by attestations.',
      draft: false,
      prerelease: false
    })

    process.env = originalEnv
  })

  it('fails when an error occurs without input', async () => {
    await main.run()
    expect(setFailedMock).toHaveBeenCalled()
  })

  it('fails when an error occurs with wrong sbom format', async () => {
    const invalidSBOM = JSON.stringify({
      SPDXID: 'SPDXRef-DOCUMENT'
    })
    const filePath = path.join(tempDir, 'invalid.json')
    fs.writeFileSync(filePath, invalidSBOM)

    const inputs: Record<string, string> = {
      'sbom-path': filePath,
      'github-token': 'fake-token'
    }
    getInputMock.mockImplementation(mockInput(inputs))
    const originalEnv = process.env
    process.env = { ...originalEnv, RUNNER_TEMP: '/tmp' }

    // Run the main function
    await main.run()
    expect(setFailedMock).toHaveBeenCalledWith('Unsupported SBOM format')

    process.env = originalEnv
  })
})

function mockInput(inputs: Record<string, string>): typeof core.getInput {
  return (name: string): string => {
    if (name in inputs) {
      return inputs[name]
    }
    return ''
  }
}
