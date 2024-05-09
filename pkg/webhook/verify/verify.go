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

type VerifiedBundle struct {
	Bundle *bundle.ProtobufBundle
	Result *verify.VerificationResult
}

func AttestationBundles(ref name.Reference, trustedMaterial root.TrustedMaterial, remoteOpts []remote.Option, policyOptions []verify.PolicyOption) ([]VerifiedBundle, error) {
	verifierConfig := []verify.VerifierOption{verify.WithObserverTimestamps(1)}
	sev, err := verify.NewSignedEntityVerifier(trustedMaterial, verifierConfig...)
	if err != nil {
		return nil, err
	}

	bundles, imageDigest, err := getBundles(ref, remoteOpts)
	if err != nil {
		return nil, err
	}

	digestBytes, err := hex.DecodeString(imageDigest.Hex)
	if err != nil {
		return nil, err
	}
	artifactPolicy := verify.WithArtifactDigest(imageDigest.Algorithm, digestBytes)
	policy := verify.NewPolicy(artifactPolicy, policyOptions...)

	verifiedBundles := make([]VerifiedBundle, 0)
	for _, b := range bundles {
		// TODO: should these be done in parallel? (as is done in cosign?)
		result, err := sev.Verify(b, policy)
		if err == nil {
			verifiedBundles = append(verifiedBundles, VerifiedBundle{Bundle: b, Result: result})
		}
	}
	return verifiedBundles, nil
}

func getBundles(ref name.Reference, remoteOpts []remote.Option) ([]*bundle.ProtobufBundle, *v1.Hash, error) {
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

	bundles := make([]*bundle.ProtobufBundle, 0)

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
		bundleBytes, err := io.ReadAll(layer0)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting referrer image: %w", err)
		}
		b := &bundle.ProtobufBundle{}
		err = b.UnmarshalJSON(bundleBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("error unmarshalling bundle: %w", err)
		}
		bundles = append(bundles, b)
	}
	if len(bundles) == 0 {
		return nil, nil, fmt.Errorf("no bundle found in referrers")
	}
	return bundles, &desc.Digest, nil
}
