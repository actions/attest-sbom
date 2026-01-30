import * as core from '@actions/core'
import * as github from '@actions/github'
import { parseSBOMFromPath, storePredicate } from './sbom'
import {
  calculateSHA256,
  generateReferencePredicate,
  getMediaType
} from './reference'
import { uploadSBOMToRelease, buildAttesterId } from './release'

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  try {
    const sbomPath = core.getInput('sbom-path')
    const token = core.getInput('github-token')

    core.debug(`Reading SBOM from ${sbomPath}`)
    const sbom = await parseSBOMFromPath(sbomPath)

    // Calculate SHA-256 digest of the SBOM file
    core.debug('Calculating SBOM digest')
    const digest = await calculateSHA256(sbomPath)

    // Get context for release upload
    const { owner, repo } = github.context.repo
    const runId = github.context.runId
    const serverUrl = github.context.serverUrl
    const workflowRef = process.env.GITHUB_WORKFLOW_REF

    if (!workflowRef) {
      throw new Error('Missing GITHUB_WORKFLOW_REF environment variable')
    }

    // Upload SBOM to release
    core.debug('Uploading SBOM to release')
    const octokit = github.getOctokit(token)
    const { downloadUrl } = await uploadSBOMToRelease(
      octokit,
      owner,
      repo,
      runId,
      sbomPath
    )

    // Generate reference predicate
    const attesterId = buildAttesterId(serverUrl, workflowRef)
    const mediaType = getMediaType(sbom.type)
    const predicate = generateReferencePredicate({
      attesterId,
      downloadLocation: downloadUrl,
      digest,
      mediaType
    })

    const predicatePath = storePredicate(predicate)

    core.setOutput('predicate-path', predicatePath)
    core.setOutput('predicate-type', predicate.type)
  } catch (err) {
    const error = err instanceof Error ? err : new Error(`${err}`)
    // Fail the workflow run if an error occurs
    core.setFailed(error.message)
  }
}
