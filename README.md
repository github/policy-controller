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

## Using Policy Controller with Azure Container Registry (ACR)

To allow the webhook to make requests to ACR, you must use one of the following
methods to authenticate:

1. Managed identities (used with AKS clusters)
1. Service principals (used with AKS clusters)
1. Pod imagePullSecrets (used with non AKS clusters)

See the [official documentation](https://learn.microsoft.com/en-us/azure/container-registry/authenticate-kubernetes-options#scenarios).

### Managed Identities for AKS Clusters

See the [official documentation](https://learn.microsoft.com/en-us/azure/aks/cluster-container-registry-integration?toc=%2Fazure%2Fcontainer-registry%2Ftoc.json&bc=%2Fazure%2Fcontainer-registry%2Fbreadcrumb%2Ftoc.json&tabs=azure-cli) for more details.

1. You must enable managed identities for the cluster using the `--enable-managed-identities` flag with either the `az aks create` or `az aks update` commands
1. You must attach the ACR to the AKS cluster using the `--attach-acr` with either
the `az aks create` or `az aks update` commands. See [here](https://learn.microsoft.com/en-us/azure/aks/cluster-container-registry-integration?toc=%2Fazure%2Fcontainer-registry%2Ftoc.json&bc=%2Fazure%2Fcontainer-registry%2Fbreadcrumb%2Ftoc.json&tabs=azure-cli#create-a-new-aks-cluster-and-integrate-with-an-existing-acr) for more details
1. You must set the `AZURE_CLIENT_ID` environment variable to the managed identity's client ID.
1. You must set the `AZURE_TENANT_ID` environment
variable to the Azure tenant the managed identity
resides in.

These will detected by the Azure credential manager.

When you create a cluster that has managed identities enabled,
a user assigned managed identity called
`<AKS cluster name>-agentpool`. Use this identity's client ID
when setting `AZURE_CLIENT_ID`. Make sure the ACR is attached to
your cluster.

#### Installing Policy Controller locally from this repository

If you are deploying policy-controller directly from this repository with
`make ko-apply`, you will need to add `AZURE_CLIENT_ID` and `AZURE_TENANT_ID` to the list of environment
variables in the [webhook deployment configuration](config/webhook.yaml).

#### Installing Policy Controller from the Helm chart

You can provide the managed identity's client ID as a custom environment
variable when installing the Helm chart:

```bash
helm install policy-controller sigstore/policy-controller --version 0.9.0 \
--set webhook.env.AZURE_CLIENT_ID=my-managed-id-client-id,webhook.env.AZURE_TENANT_ID=tenant-id
```

### Service Principals for AKS Clusters

#### Installing Policy Controller from the Helm chart

You should be able to provide the service principal client ID and tenant ID
as a workload identity annotations:

```bash
helm upgrade --install policy-controller sigstore/policy-controller --version 0.9.0 \
--set-json webhook.serviceAccount.annotations="{\"azure.workload.identity/client-id\": \"${SERVICE_PRINCIPAL_CLIENT_ID}\", \"azure.workload.identity/tenant-id\": \"${TENANT_ID}\"}"
```

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

## Cutting a new release

The branch `release` on the private fork is used for customer-facing released code. 

In order to push a new release, follow these steps:

1. Merge any changes into the `release` branch.
1. Tag as `v0.9.0+githubX` (incrementing the `X` as needed).
1. Push the tag to the private fork.
1. The [Release GitHub Action workflow](https://github.com/github/policy-controller/actions/workflows/release.yaml) will triggered automatically when the tag is pushed

## Security

Should you discover any security issues, please refer to Sigstore's [security
policy](https://github.com/sigstore/policy-controller/security/policy).
