import fs from 'fs'
import path from 'path'
import * as github from '@actions/github'

const RELEASE_TAG = 'sbom'

type Octokit = ReturnType<typeof github.getOctokit>

export type UploadResult = {
  downloadUrl: string
}

export async function uploadSBOMToRelease(
  octokit: Octokit,
  owner: string,
  repo: string,
  runId: number,
  sbomPath: string
): Promise<UploadResult> {
  const release = await findOrCreateRelease(octokit, owner, repo)
  const assetName = generateAssetName(runId, sbomPath)

  const fileContent = await fs.promises.readFile(sbomPath)

  const asset = await octokit.rest.repos.uploadReleaseAsset({
    owner,
    repo,
    release_id: release.id,
    name: assetName,
    // @ts-expect-error - octokit types expect string but Buffer works
    data: fileContent
  })

  return {
    downloadUrl: asset.data.browser_download_url
  }
}

async function findOrCreateRelease(
  octokit: Octokit,
  owner: string,
  repo: string
): Promise<{ id: number }> {
  try {
    const { data: release } = await octokit.rest.repos.getReleaseByTag({
      owner,
      repo,
      tag: RELEASE_TAG
    })
    return { id: release.id }
  } catch (error) {
    // Release doesn't exist, create it
    if (isNotFoundError(error)) {
      const { data: release } = await octokit.rest.repos.createRelease({
        owner,
        repo,
        tag_name: RELEASE_TAG,
        name: 'SBOM Attestations',
        body: 'This release contains SBOM files referenced by attestations.',
        draft: false,
        prerelease: false
      })
      return { id: release.id }
    }
    throw error
  }
}

function isNotFoundError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'status' in error &&
    error.status === 404
  )
}

export function generateAssetName(runId: number, sbomPath: string): string {
  const originalName = path.basename(sbomPath)
  return `${runId}-${originalName}`
}

export function buildAttesterId(
  serverUrl: string,
  workflowRef: string
): string {
  // workflowRef is in the format: owner/repo/.github/workflows/file.yml@refs/heads/branch
  // Extract just the owner/repo/.github/workflows/file.yml part
  const workflowPath = workflowRef.split('@')[0]
  return `${serverUrl}/${workflowPath}`
}
