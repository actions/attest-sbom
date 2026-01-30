import fs from 'fs'
import crypto from 'crypto'
import type { Predicate } from '@actions/attest'

export const REFERENCE_PREDICATE_TYPE =
  'https://in-toto.io/attestation/reference/v0.1'

export type ReferencePredicate = {
  attester: {
    id: string
  }
  references: ResourceDescriptor[]
}

export type ResourceDescriptor = {
  downloadLocation: string
  digest: {
    sha256: string
  }
  mediaType: string
}

export async function calculateSHA256(filePath: string): Promise<string> {
  const fileBuffer = await fs.promises.readFile(filePath)
  const hash = crypto.createHash('sha256')
  hash.update(fileBuffer)
  return hash.digest('hex')
}

export type ReferencePredicateParams = {
  attesterId: string
  downloadLocation: string
  digest: string
  mediaType: string
}

export function generateReferencePredicate(
  params: ReferencePredicateParams
): Predicate {
  const predicate: ReferencePredicate = {
    attester: {
      id: params.attesterId
    },
    references: [
      {
        downloadLocation: params.downloadLocation,
        digest: {
          sha256: params.digest
        },
        mediaType: params.mediaType
      }
    ]
  }

  return {
    type: REFERENCE_PREDICATE_TYPE,
    params: predicate
  }
}

export function getMediaType(sbomType: 'spdx' | 'cyclonedx'): string {
  switch (sbomType) {
    case 'spdx':
      return 'application/spdx+json'
    case 'cyclonedx':
      return 'application/vnd.cyclonedx+json'
  }
}
