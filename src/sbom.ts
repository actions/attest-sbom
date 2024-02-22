import fs from 'fs'
import { SBOM } from '@actions/attest'
import * as path from 'path'
import type { Predicate } from '@actions/attest'

export async function parseSBOMFromPath(filePath: string): Promise<SBOM> {
  // Read the file content
  const fileContent = await fs.promises.readFile(filePath, 'utf8')

  const sbom = JSON.parse(fileContent)

  if (checkIsSPDX(sbom)) {
    return { type: 'spdx', object: sbom }
  } else if (checkIsCycloneDX(sbom)) {
    return { type: 'cyclonedx', object: sbom }
  }
  throw new Error('Unsupported SBOM format')
}

function checkIsSPDX(sbomObject: {
  spdxVersion?: string
  SPDXID?: string
}): boolean {
  if (sbomObject?.spdxVersion && sbomObject?.SPDXID) {
    return true
  } else {
    return false
  }
}

function checkIsCycloneDX(sbomObject: {
  bomFormat?: string
  serialNumber?: string
  specVersion?: string
}): boolean {
  if (
    sbomObject?.bomFormat &&
    sbomObject?.serialNumber &&
    sbomObject?.specVersion
  ) {
    return true
  } else {
    return false
  }
}

export const storePredicate = (predicate: Predicate): string => {
  // random tempfile
  const basePath = process.env['RUNNER_TEMP']

  if (!basePath) {
    throw new Error('Missing RUNNER_TEMP environment variable')
  }

  const tmpDir = fs.mkdtempSync(path.join(basePath, path.sep))
  const tempFile = path.join(tmpDir, 'predicate.json')

  // write predicate to file
  fs.writeFileSync(tempFile, JSON.stringify(predicate.params))
  return tempFile
}
