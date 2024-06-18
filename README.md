# GitHub Managed Policy Controller

This repository hosts a temporary GitHub owned 
fork of the [Sigstore Policy Controller repository](https://github.com/sigstore/policy-controller). Once functionality only present in this fork is merged upstream to [sigstore/policy-controller](https://github.com/sigstore/policy-controller), this
fork will be archived.

The `policy-controller` admission controller can be used to enforce policy on a Kubernetes cluster based on verifiable supply-chain metadata from `cosign` and
artifacts attestations produced by the [attest-build-provenance GitHub Action](https://github.com/actions/attest-build-provenance).

For more information about the `policy-controller`, have a look at the Sigstore documentation
[here](https://docs.sigstore.dev/policy-controller/overview).

## Background 

See the [official documentation](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) on
using artifact attestations to establish build provenance and
the [blog post](https://github.blog/2024-05-02-introducing-artifact-attestations-now-in-public-beta/) introducing Artifact Attestations.

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
helm install policy-controller oci://ghcr.io/artifact-attestations-helm-charts/policy-controller \
    --version 0.9.0 \
    --set webhook.env.AZURE_CLIENT_ID=my-managed-id-client-id,webhook.env.AZURE_TENANT_ID=tenant-id
```

### Service Principals for AKS Clusters

#### Installing Policy Controller from the Helm chart

You should be able to provide the service principal client ID and tenant ID
as a workload identity annotations:

```bash
helm install policy-controller oci://ghcr.io/artifact-attestations-helm-charts/policy-controller \  
    --version 0.9.0 \
    --set-json webhook.serviceAccount.annotations="{\"azure.workload.identity/client-id\": \"${SERVICE_PRINCIPAL_CLIENT_ID}\", \"azure.workload.identity/tenant-id\": \"${TENANT_ID}\"}"
```

## License 

This project is licensed under the terms of the Apache 2.0 open source license. Please refer to [Apache 2.0](./LICENSE) for the full terms.

## Maintainers 

See [CODEOWNERS](./CODEOWNERS) for a list of maintainers.

## Support

If you have any questions or issues following examples outlined in this repository,
please file an [issue](https://github.com/github/policy-controller-helm/issues/new?template=Blank+issue) and we will assist you.

## K8s Support Policy

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

## Security

Should you discover any security issues, please refer to Sigstore's [security
policy](https://github.com/sigstore/policy-controller/security/policy).

## Maintainer Documentation

### Cutting a new release

The branch `release` on the private fork is used for customer-facing released code. 

In order to push a new release, follow these steps:

1. Merge any changes into the `release` branch.
1. Tag as `v0.9.0+githubX` (incrementing the `X` as needed).
1. Push the tag to the private fork.
1. The [Release GitHub Action workflow](https://github.com/github/policy-controller/actions/workflows/release.yaml) will triggered automatically when the tag is pushed
