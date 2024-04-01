package verify

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

func AttestationBundle(ref name.Reference, trustedMaterial root.TrustedMaterial, remoteOpts []remote.Option, policyOption verify.PolicyOption) (*bundle.ProtobufBundle, *verify.VerificationResult, error) {
	b, imageDigest, err := getBundle(ref, remoteOpts)
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

func getBundle(ref name.Reference, remoteOpts []remote.Option) (*bundle.ProtobufBundle, *v1.Hash, error) {
	desc, err := remote.Get(ref, remoteOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting image descriptor: %w", err)
	}

	digest := ref.Context().Digest(desc.Digest.String())

	referrers, err := remote.Referrers(digest, remoteOpts...)
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

		refImg, err := remote.Image(ref.Context().Digest(refDesc.Digest.String()), remoteOpts...)
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
