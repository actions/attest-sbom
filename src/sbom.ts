import fs from 'fs'
import * as path from 'path'

import type { Predicate } from '@actions/attest'

export type SBOM = {
  type: 'spdx' | 'cyclonedx'
  object: object
}

export async function parseSBOMFromPath(filePath: string): Promise<SBOM> {
  // Read the file content
  const fileContent = await fs.promises.readFile(filePath, 'utf8')

  const sbom = JSON.parse(fileContent) as object

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

export const generateSBOMPredicate = (sbom: SBOM): Predicate => {
  if (sbom.type === 'spdx') {
    return generateSPDXIntoto(sbom.object)
  }
  if (sbom.type === 'cyclonedx') {
    return generateCycloneDXIntoto(sbom.object)
  }
  throw new Error('Unsupported SBOM format')
}

// ref: https://github.com/in-toto/attestation/blob/main/spec/predicates/spdx.md
const generateSPDXIntoto = (sbom: object): Predicate => {
  const spdxVersion = (sbom as { spdxVersion?: string })?.['spdxVersion']
  if (!spdxVersion) {
    throw new Error('Cannot find spdxVersion in the SBOM')
  }

  const version = spdxVersion.split('-')[1]

  return {
    type: `https://spdx.dev/Document/v${version}`,
    params: sbom
  }
}

// ref: https://github.com/in-toto/attestation/blob/main/spec/predicates/cyclonedx.md
const generateCycloneDXIntoto = (sbom: object): Predicate => {
  return {
    type: 'https://cyclonedx.org/bom',
    params: sbom
  }
}
