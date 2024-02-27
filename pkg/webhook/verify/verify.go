package verify

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	_ "embed"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

//go:embed trusted-root-github-staging.json
var trustedRootGithubStaging []byte

// TODO: Replace with TUF from TrustRoot CRD when TUF client is updated to support TrustedRoot files.
func TrustedRootGithubStaging() (root.TrustedMaterial, error) {
	return root.NewTrustedRootFromJSON(trustedRootGithubStaging)
}

func AttestationBundle(ref name.Reference, trustedMaterial root.TrustedMaterial, kc authn.Keychain, policyOption verify.PolicyOption) (*bundle.ProtobufBundle, *verify.VerificationResult, error) {
	b, imageDigest, err := getBundle(ref, kc)
	if err != nil {
		return nil, nil, err
	}
	_ = imageDigest

	verifierConfig := []verify.VerifierOption{}
	var artifactPolicy verify.ArtifactPolicyOption

	verifierConfig = append(verifierConfig, verify.WithObserverTimestamps(1))

	sev, err := verify.NewSignedEntityVerifier(trustedMaterial, verifierConfig...)
	if err != nil {
		return nil, nil, err
	}

	digestBytes, err := hex.DecodeString(imageDigest.Hex)
	if err != nil {
		return nil, nil, err
	}
	artifactPolicy = verify.WithArtifactDigest(imageDigest.Algorithm, digestBytes)

	result, err := sev.Verify(b, verify.NewPolicy(artifactPolicy, policyOption))
	if err != nil {
		return nil, nil, err
	}
	return b, result, nil
}

func getBundle(ref name.Reference, kc authn.Keychain) (*bundle.ProtobufBundle, *v1.Hash, error) {
	desc, err := remote.Get(ref, remote.WithAuthFromKeychain(kc))
	if err != nil {
		return nil, nil, fmt.Errorf("error getting image descriptor: %w", err)
	}

	digest := ref.Context().Digest(desc.Digest.String())

	referrers, err := remote.Referrers(digest, remote.WithAuthFromKeychain(kc))
	if err != nil {
		return nil, nil, fmt.Errorf("error getting referrers: %w", err)
	}
	refManifest, err := referrers.IndexManifest()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting referrers manifest: %w", err)
	}

	var bundleBytes []byte
	for _, refDesc := range refManifest.Manifests {
		if !strings.HasPrefix(refDesc.ArtifactType, "application/vnd.dev.sigstore.bundle+json") {
			continue
		}

		refImg, err := remote.Image(ref.Context().Digest(refDesc.Digest.String()), remote.WithAuthFromKeychain(kc))
		if err != nil {
			return nil, nil, fmt.Errorf("error getting referrer image: %w", err)
		}
		layers, err := refImg.Layers()
		if err != nil {
			return nil, nil, fmt.Errorf("error getting referrer image: %w", err)
		}
		layer0, err := layers[0].Uncompressed()
		if err != nil {
			return nil, nil, fmt.Errorf("error getting referrer image: %w", err)
		}
		bundleBytes, err = io.ReadAll(layer0)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting referrer image: %w", err)
		}
	}
	if len(refManifest.Manifests) == 0 || len(bundleBytes) == 0 {
		return nil, nil, fmt.Errorf("no bundle found in referrers")
	}
	b := &bundle.ProtobufBundle{}
	err = b.UnmarshalJSON(bundleBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error unmarshalling bundle: %w", err)
	}
	return b, &desc.Digest, nil
}
