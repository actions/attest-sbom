import * as core from '@actions/core'
import * as main from '../src/main'
import * as fs from 'fs'

// Mock the GitHub Actions core library
jest.mock('@actions/core')
const getInputMock = jest.spyOn(core, 'getInput')

// Mock the specific function before your tests or in a beforeEach if you need it fresh for each test
fs.promises.readFile = jest.fn().mockImplementation(() => 'mocked value')

describe('SBOM Action', () => {
  beforeEach(() => {
    jest.resetAllMocks()
  })

  it('successfully processes an SBOM', async () => {
    const inputs = {
      'sbom-path': '/path/to/sbom'
    }
    getInputMock.mockImplementation(mockInput(inputs))
    const originalEnv = process.env
    process.env = { ...originalEnv, RUNNER_TEMP: '/tmp' }
    const spdxSBOM = JSON.stringify({
      spdxVersion: 'SPDX-2.2',
      SPDXID: 'SPDXRef-DOCUMENT'
    })
    ;(fs.promises.readFile as jest.Mock).mockResolvedValue(spdxSBOM)

    // Run the main function
    await main.run()

    // Verify that outputs were set correctly
    expect(core.setOutput).toHaveBeenCalledTimes(2)
    expect(core.setOutput).toHaveBeenNthCalledWith(
      2,
      'predicate-type',
      'https://spdx.dev/Document/v2.2'
    )
    process.env = originalEnv
  })

  it('fails when an error occurs without input', async () => {
    await main.run()
    expect(core.setFailed).toHaveBeenCalledWith(
      'Unexpected token u in JSON at position 0'
    )
  })

  it('fails when an error occurs with wrong sbom format', async () => {
    const inputs = {
      'sbom-path': '/path/to/sbom'
    }
    getInputMock.mockImplementation(mockInput(inputs))
    const originalEnv = process.env
    process.env = { ...originalEnv, RUNNER_TEMP: '/tmp' }
    const spdxSBOM = JSON.stringify({
      SPDXID: 'SPDXRef-DOCUMENT'
    })
    ;(fs.promises.readFile as jest.Mock).mockResolvedValue(spdxSBOM)

    // Run the main function
    await main.run()
    expect(core.setFailed).toHaveBeenCalledWith('Unsupported SBOM format')
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
