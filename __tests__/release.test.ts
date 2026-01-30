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
  it('builds correct attester ID URL from workflow ref', () => {
    const result = buildAttesterId(
      'https://github.com',
      'octocat/hello-world/.github/workflows/ci.yml@refs/heads/main'
    )
    expect(result).toBe(
      'https://github.com/octocat/hello-world/.github/workflows/ci.yml'
    )
  })

  it('handles workflow refs with tags', () => {
    const result = buildAttesterId(
      'https://github.com',
      'owner/repo/.github/workflows/release.yml@refs/tags/v1.0.0'
    )
    expect(result).toBe(
      'https://github.com/owner/repo/.github/workflows/release.yml'
    )
  })

  it('handles enterprise server URLs', () => {
    const result = buildAttesterId(
      'https://github.example.com',
      'owner/repo/.github/workflows/build.yml@refs/heads/main'
    )
    expect(result).toBe(
      'https://github.example.com/owner/repo/.github/workflows/build.yml'
    )
  })
})
