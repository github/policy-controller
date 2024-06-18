package webhook

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type noncompliantRegistryTransport struct{}

// RoundTrip will check if a request and associated response fulfill the following:
// 1. The response returns a 406 status code
// 2. The request path contains /referrers/
// If both conditions are met, the response's status code will be overwritten to 404
// This is a temporary solution to handle non compliant registries that return
// an unexpected status code 406 when the go-containerregistry library used
// by this code attempts to make a request to the referrers API.
// The go-contqainerregistry library can handle 404 response but not a 406 response.
func (a *noncompliantRegistryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if resp.StatusCode == http.StatusNotAcceptable && strings.Contains(req.URL.Path, "/referrers/") {
		resp.StatusCode = http.StatusNotFound
	}

	return resp, err
}

type VerifiedBundle struct {
	SGBundle *bundle.ProtobufBundle
	Result   *verify.VerificationResult
	Hash     v1.Hash
}

// VerifiedBundle implements Signature
var _ Signature = &VerifiedBundle{}

func (vb *VerifiedBundle) Digest() (v1.Hash, error) {
	return vb.Hash, nil
}

func (vb *VerifiedBundle) Payload() ([]byte, error) {
	// todo: this should return the json-serialized dsse envelope
	envelope := vb.SGBundle.GetDsseEnvelope()
	if envelope == nil {
		return nil, fmt.Errorf("no dsse envelope found")
	}
	return json.Marshal(envelope)
}

func (vb *VerifiedBundle) Signature() ([]byte, error) {
	// TODO: implement this
	return []byte{}, nil
}

func (vb *VerifiedBundle) Cert() (*x509.Certificate, error) {
	vc, err := vb.SGBundle.VerificationContent()
	if err != nil {
		return nil, err
	}
	if cert, ok := vc.HasCertificate(); ok {
		return &cert, nil
	}
	return nil, errors.New("bundle does not contain a certificate")
}

func VerifiedBundles(ref name.Reference, trustedMaterial root.TrustedMaterial, remoteOpts []remote.Option, policyOptions []verify.PolicyOption, verifierOptions []verify.VerifierOption) ([]Signature, error) {
	sev, err := verify.NewSignedEntityVerifier(trustedMaterial, verifierOptions...)
	if err != nil {
		return nil, err
	}

	bundles, hash, err := getBundles(ref, remoteOpts)
	if err != nil {
		return nil, err
	}

	digestBytes, err := hex.DecodeString(hash.Hex)
	if err != nil {
		return nil, err
	}
	artifactPolicy := verify.WithArtifactDigest(hash.Algorithm, digestBytes)
	policy := verify.NewPolicy(artifactPolicy, policyOptions...)

	verifiedBundles := make([]Signature, 0)
	for _, b := range bundles {
		// TODO: should these be done in parallel? (as is done in cosign?)
		result, err := sev.Verify(b, policy)
		if err == nil {
			verifiedBundles = append(verifiedBundles, &VerifiedBundle{SGBundle: b, Result: result, Hash: *hash})
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

	transportOpts := []remote.Option{remote.WithTransport(&noncompliantRegistryTransport{})}
	transportOpts = append(transportOpts, remoteOpts...)
	referrers, err := remote.Referrers(digest, transportOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting referrers: %w", err)
	}
	refManifest, err := referrers.IndexManifest()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting referrers manifest: %w", err)
	}

	bundles := make([]*bundle.ProtobufBundle, 0)

	for _, refDesc := range refManifest.Manifests {
		if !strings.HasPrefix(refDesc.ArtifactType, "application/vnd.dev.sigstore.bundle") {
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
