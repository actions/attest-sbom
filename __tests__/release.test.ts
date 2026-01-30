import { generateAssetName, buildAttesterId } from '../src/release'

describe('generateAssetName', () => {
  it('generates asset name with run ID prefix', () => {
    const result = generateAssetName(12345, '/path/to/sbom.json')
    expect(result).toBe('12345-sbom.json')
  })

  it('handles paths with multiple directories', () => {
    const result = generateAssetName(99999, '/a/b/c/d/my-sbom.spdx.json')
    expect(result).toBe('99999-my-sbom.spdx.json')
  })
})

describe('buildAttesterId', () => {
  it('builds correct attester ID URL', () => {
    const result = buildAttesterId('octocat', 'hello-world', 'ci.yml')
    expect(result).toBe(
      'https://github.com/octocat/hello-world/.github/workflows/ci.yml'
    )
  })

  it('handles workflow names with spaces', () => {
    const result = buildAttesterId('owner', 'repo', 'Build and Test.yml')
    expect(result).toBe(
      'https://github.com/owner/repo/.github/workflows/Build and Test.yml'
    )
  })
})
