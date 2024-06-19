# `actions/attest-sbom`

Generate signed SBOM attestations for workflow artifacts. Internally powered by
the [@actions/attest][1] package.

Attestations bind some subject (a named artifact along with its digest) to a a
Software Bill of Materials (SBOM) using the [in-toto][2] format. The action
accepts SBOMs which have been generated by external tools. Provided SBOMs must
be in either the [SPDX][4] or [CycloneDX][5] JSON-serialized format.

A verifiable signature is generated for the attestation using a short-lived
[Sigstore][6]-issued signing certificate. If the repository initiating the
GitHub Actions workflow is public, the public-good instance of Sigstore will be
used to generate the attestation signature. If the repository is
private/internal, it will use the GitHub private Sigstore instance.

Once the attestation has been created and signed, it will be uploaded to the GH
attestations API and associated with the repository from which the workflow was
initiated.

Attestations can be verified using the [`attestation` command in the GitHub
CLI][7].

See [Using artifact attestations to establish provenance for builds][11] for
more information on artifact attestations.

## Usage

Within the GitHub Actions workflow which builds some artifact you would like to
attest:

1. Ensure that the following permissions are set:

   ```yaml
   permissions:
     id-token: write
     attestations: write
   ```

   The `id-token` permission gives the action the ability to mint the OIDC token
   necessary to request a Sigstore signing certificate. The `attestations`
   permission is necessary to persist the attestation.

1. Add the following to your workflow after your artifact has been built and
   your SBOM has been generated:

   ```yaml
   - uses: actions/attest-sbom@v1
     with:
       subject-path: '<PATH TO ARTIFACT>'
       sbom-path: '<PATH TO SBOM>'
   ```

   The `subject-path` parameter should identify the artifact for which you want
   to generate an SBOM attestation. The `sbom-path` parameter should identify
   the SBOM document to be associated with the subject.

### Inputs

See [action.yml](action.yml)

```yaml
- uses: actions/attest-sbom@v1
  with:
    # Path to the artifact serving as the subject of the attestation. Must
    # specify exactly one of "subject-path" or "subject-digest". May contain a
    # glob pattern or list of paths (total subject count cannot exceed 2500).
    subject-path:

    # SHA256 digest of the subject for the attestation. Must be in the form
    # "sha256:hex_digest" (e.g. "sha256:abc123..."). Must specify exactly one
    # of "subject-path" or "subject-digest".
    subject-digest:

    # Subject name as it should appear in the attestation. Required unless
    # "subject-path" is specified, in which case it will be inferred from the
    # path.
    subject-name:

    # Path to the JSON-formatted SBOM file to attest. File size cannot exceed
    # 16MB.
    sbom-path:

    # Whether to push the attestation to the image registry. Requires that the
    # "subject-name" parameter specify the fully-qualified image name and that
    # the "subject-digest" parameter be specified. Defaults to false.
    push-to-registry:

    # The GitHub token used to make authenticated API requests. Default is
    # ${{ github.token }}
    github-token:
```

### Outputs

<!-- markdownlint-disable MD013 -->

| Name          | Description                                                    | Example                 |
| ------------- | -------------------------------------------------------------- | ----------------------- |
| `bundle-path` | Absolute path to the file containing the generated attestation | `/tmp/attestaion.jsonl` |

<!-- markdownlint-enable MD013 -->

Attestations are saved in the JSON-serialized [Sigstore bundle][8] format.

If multiple subjects are being attested at the same time, each attestation will
be written to the output file on a separate line (using the [JSON Lines][9]
format).

## Attestation Limits

### Subject Limits

No more than 2500 subjects can be attested at the same time. Subjects will be
processed in batches 50. After the initial group of 50, each subsequent batch
will incur an exponentially increasing amount of delay (capped at 1 minute of
delay per batch) to avoid overwhelming the attestation API.

### SBOM Limits

The SBOM supplied via the `sbom-path` input cannot exceed 16MB.

## Examples

### Identify Subject and SBOM by Path

For the basic use case, simply add the `attest-sbom` action to your workflow and
supply the path to the artifact and SBOM for which you want to generate
attestation.

```yaml
name: build-attest

on:
  workflow_dispatch:

jobs:
  build:
    permissions:
      id-token: write
      contents: read
      attestations: write

    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Build artifact
        run: make my-app
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          format: 'spdx-json'
          output-file: 'sbom.spdx.json'
      - name: Attest
        uses: actions/attest-sbom@v1
        with:
          subject-path: '${{ github.workspace }}/my-app'
          sbom-path: 'sbom.spdx.json'
```

### Identify Multiple Subjects

If you are generating multiple artifacts, you can generate an attestation for
each by using a wildcard in the `subject-path` input.

```yaml
- uses: actions/attest-sbom@v1
  with:
    subject-path: 'dist/**/my-bin-*'
    sbom-path: '${{ github.workspace }}/my-bin.sbom.spdx.json'
```

For supported wildcards along with behavior and documentation, see
[@actions/glob][10] which is used internally to search for files.

Alternatively, you can explicitly list multiple subjects with either a comma or
newline delimited list:

```yaml
- uses: actions/attest-sbom@v1
  with:
    subject-path: 'dist/foo, dist/bar'
```

```yaml
- uses: actions/attest-build-provenance@v1
  with:
    subject-path: |
      dist/foo
      dist/bar
```

### Container Image

When working with container images you can invoke the action with the
`subject-name` and `subject-digest` inputs.

If you want to publish the attestation to the container registry with the
`push-to-registry` option, it is important that the `subject-name` specify the
fully-qualified image name (e.g. "ghcr.io/user/app" or
"acme.azurecr.io/user/app"). Do NOT include a tag as part of the image name --
the specific image being attested is identified by the supplied digest.

> **NOTE**: When pushing to Docker Hub, please use "index.docker.io" as the
> registry portion of the image name.

```yaml
name: build-attested-image

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      packages: write
      contents: read
      attestations: write
    env:
      REGISTRY: ghcr.io
      IMAGE_NAME: ${{ github.repository }}

    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Login to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - name: Build and push image
        id: push
        uses: docker/build-push-action@v5.0.0
        with:
          context: .
          push: true
          tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
          format: 'cyclonedx-json'
          output-file: 'sbom.cyclonedx.json'
      - name: Attest
        uses: actions/attest-sbom@v1
        id: attest
        with:
          subject-name: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          subject-digest: ${{ steps.push.outputs.digest }}
          sbom-path: 'sbom.cyclonedx.json'
          push-to-registry: true
```

[1]: https://github.com/actions/toolkit/tree/main/packages/attest
[2]: https://github.com/in-toto/attestation/tree/main/spec/v1
[4]: https://spdx.dev/
[5]: https://cyclonedx.org/
[6]: https://www.sigstore.dev/
[7]: https://cli.github.com/manual/gh_attestation_verify
[8]:
  https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto
[9]: https://jsonlines.org/
[10]: https://github.com/actions/toolkit/tree/main/packages/glob#patterns
[11]:
  https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds
