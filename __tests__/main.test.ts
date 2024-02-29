import * as core from '@actions/core'
import * as main from '../src/main'
import * as fs from 'fs'
import os from 'os'
import * as path from 'path'

// Mock the GitHub Actions core library
jest.mock('@actions/core')
const getInputMock = jest.spyOn(core, 'getInput')
const setOutputMock = jest.spyOn(core, 'setOutput')
const setFailedMock = jest.spyOn(core, 'setFailed')

// Ensure that setFailed doesn't set an exit code during tests
setFailedMock.mockImplementation(() => {})

describe('SBOM Action', () => {
  let tempDir = '/'
  let outputs = {} as Record<string, string>

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom'))

    jest.resetAllMocks()
    setOutputMock.mockImplementation((key, value) => {
      outputs[key] = value
    })
  })

  afterEach(() => {
    fs.rmdirSync(tempDir, { recursive: true })
    outputs = {}
  })

  it('successfully processes an SBOM', async () => {
    const spdxSBOM = JSON.stringify({
      spdxVersion: 'SPDX-2.2',
      SPDXID: 'SPDXRef-DOCUMENT',
      packages: []
    })
    const filePath = path.join(tempDir, 'spdxSBOM.json')
    fs.writeFileSync(filePath, spdxSBOM)

    const inputs = {
      'sbom-path': filePath
    }
    getInputMock.mockImplementation(mockInput(inputs))
    const originalEnv = process.env
    process.env = { ...originalEnv, RUNNER_TEMP: '/tmp' }

    // Run the main function
    await main.run()

    // Verify that outputs were set correctly
    expect(setOutputMock).toHaveBeenCalledTimes(2)
    expect(setOutputMock).toHaveBeenNthCalledWith(
      2,
      'predicate-type',
      'https://spdx.dev/Document/v2.2'
    )
    expect(outputs['predicate-path']).toBeTruthy()
    const predicatePath = outputs['predicate-path']

    // Verify that the temporary file exists
    expect(fs.existsSync(predicatePath)).toBe(true)

    // Read the content of the temporary file
    const fileContent = fs.readFileSync(predicatePath, 'utf-8')

    // Verify that the content matches the predicate params
    expect(JSON.parse(fileContent)).toEqual(JSON.parse(spdxSBOM))

    // Clean up the temporary file
    fs.unlinkSync(predicatePath)

    process.env = originalEnv
  })

  it('fails when an error occurs without input', async () => {
    await main.run()
    expect(setFailedMock).toHaveBeenCalledWith(
      'TypeError [ERR_INVALID_ARG_TYPE]: The "path" argument must be of type string or an instance of Buffer or URL. Received undefined'
    )
  })

  it('fails when an error occurs with wrong sbom format', async () => {
    const spdxSBOM = JSON.stringify({
      SPDXID: 'SPDXRef-DOCUMENT'
    })
    const filePath = path.join(tempDir, 'spdxSBOM.json')
    fs.writeFileSync(filePath, spdxSBOM)

    const inputs = {
      'sbom-path': filePath
    }
    getInputMock.mockImplementation(mockInput(inputs))
    const originalEnv = process.env
    process.env = { ...originalEnv, RUNNER_TEMP: '/tmp' }

    // Run the main function
    await main.run()
    expect(setFailedMock).toHaveBeenCalledWith('Unsupported SBOM format')
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
