<p align="center">
  <img style="max-width: 100%;width: 300px;" src="https://raw.githubusercontent.com/sigstore/community/main/artwork/policy-controller/Horizontal/Full%20Color/sigstore_policycontroller-horizontal-color.svg" alt="Cosign logo"/>
</p>

# Policy Controller

The `policy-controller` admission controller can be used to enforce policy on a Kubernetes cluster based on verifiable supply-chain metadata from `cosign`.

[![Go Report Card](https://goreportcard.com/badge/github.com/sigstore/policy-controller)](https://goreportcard.com/report/github.com/sigstore/policy-controller)
[![e2e-tests](https://github.com/sigstore/policy-controller/actions/workflows/kind-e2e-cosigned.yaml/badge.svg)](https://github.com/sigstore/policy-controller/actions/workflows/kind-e2e-cosigned.yaml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sigstore/policy-controller/badge)](https://api.securityscorecards.dev/projects/github.com/sigstore/policy-controller)

`policy-controller` also resolves the image tags to ensure the image being ran is not different from when it was admitted.

See the [installation instructions](https://docs.sigstore.dev/policy-controller/installation) for more information.

Today, `policy-controller` can automatically validate signatures and
attestations on container images.
Enforcement is configured on a per-namespace basis, and multiple keys are supported.

We're actively working on more features here.

For more information about the `policy-controller`, have a look at our documentation website [here](https://docs.sigstore.dev/policy-controller/overview).

## Examples

Please see the [examples/](./examples/) directory for example policies etc.

## Policy Testing

This repo includes a `policy-tester` tool which enables checking a policy against
various images.

In the root of this repo, run the following to build:
```
make policy-tester
```

Then run it pointing to a YAML file containing a ClusterImagePolicy, and an image to evaluate the policy against:
```
(set -o pipefail && \
    ./policy-tester \
        --policy=test/testdata/policy-controller/tester/cip-public-keyless.yaml \
        --image=ghcr.io/sigstore/cosign/cosign:v1.9.0 | jq)
```

## Local Development

You can spin up a local [Kind](https://kind.sigs.k8s.io/) K8s cluster to test local changes to the policy controller using the `local-dev`
CLI tool. Build the tool with `make local-dev` and then run it with `./bin/local-dev setup`.

It optionally accepts the following:

```
--cluster-name
--k8s-version
--registry-url
```

You can clean up the cluster with `./bin/local-dev clean --cluster-name=<my cluster name>`.

You will need to have the following tools installed to use this:
- [Docker](https://docs.docker.com/get-docker/)
- [kind](https://kind.sigs.k8s.io/)
- [ko](https://ko.build/install/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)

### Use local registry

If you would like to use the local Kind registry instead of a live one,
do not include the `registry-url` flag when calling the CLI. It will default to using the local registry. But before running the CLI, you must add the following line to your `/etc/hosts` file first:
`127.0.0.1 registry.local`

## Support Policy

This policy-controller's versions are able to run in the following versions of Kubernetes:

|  | policy-controller `> 0.2.x` | policy-controller `> 0.10.x` |
|---|:---:|:---:|
| Kubernetes 1.23 | ✓ |   |
| Kubernetes 1.24 | ✓ |   |
| Kubernetes 1.25 | ✓ |   |
| Kubernetes 1.27 |   | ✓ |
| Kubernetes 1.28 |   | ✓ |
| Kubernetes 1.29 |   | ✓ |

note: not fully tested yet, but can be installed

## Release Cadence

We are intending to move to a monthly cadence for minor releases.
Minor releases will be published around the beginning of the month.
We may cut a patch release instead, if the changes are small enough not to warrant a minor release.
We will also cut patch releases periodically as needed to address bugs.

## Security

Should you discover any security issues, please refer to Sigstore's [security
policy](https://github.com/sigstore/policy-controller/security/policy).
