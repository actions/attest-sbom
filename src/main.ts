import * as core from '@actions/core'
import { parseSBOMFromPath, storePredicate } from './sbom'
import { generateSBOMPredicate } from '@actions/attest'

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  try {
    const sbomPath = core.getInput('sbom-path')

    core.debug(`Reading SBOM from ${sbomPath}`)
    const sbom = await parseSBOMFromPath(sbomPath)

    // Calculate subject from inputs and generate provenance
    const predicate = generateSBOMPredicate(sbom)

    const predicatePath = storePredicate(predicate)

    core.setOutput('predicate-path', predicatePath)
    core.setOutput('predicate-type', predicate.type)
  } catch (err) {
    const error = err instanceof Error ? err : new Error(`${err}`)
    // Fail the workflow run if an error occurs
    core.setFailed(error.message)
  }
}
