//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package webhook

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"knative.dev/pkg/logging"

	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/policy"
	"github.com/sigstore/sigstore/pkg/signature"
)

func valid(ctx context.Context, ref name.Reference, keys []crypto.PublicKey, hashAlgo crypto.Hash, checkOpts *cosign.CheckOpts) ([]Signature, error) {
	if len(keys) == 0 {
		return validSignatures(ctx, ref, checkOpts)
	}
	// We return nil if ANY key matches
	var lastErr error
	for _, k := range keys {
		verifier, err := signature.LoadVerifier(k, hashAlgo)
		if err != nil {
			logging.FromContext(ctx).Errorf("error creating verifier: %v", err)
			lastErr = err
			continue
		}
		checkOpts.SigVerifier = verifier
		sps, err := validSignatures(ctx, ref, checkOpts)
		if err != nil {
			logging.FromContext(ctx).Errorf("error validating signatures: %v", err)
			lastErr = err
			continue
		}
		return sps, nil
	}
	logging.FromContext(ctx).Debug("No valid signatures were found.")
	return nil, lastErr
}

// For testing
var cosignVerifySignatures = cosign.VerifyImageSignatures
var cosignVerifyAttestations = cosign.VerifyImageAttestations

func validSignatures(ctx context.Context, ref name.Reference, checkOpts *cosign.CheckOpts) ([]Signature, error) {
	checkOpts.ClaimVerifier = cosign.SimpleClaimVerifier
	sigs, _, err := cosignVerifySignatures(ctx, ref, checkOpts)
	sigList := make([]Signature, len(sigs))
	for i, s := range sigs {
		sigList[i] = s
	}
	return sigList, err
}

func validAttestations(ctx context.Context, ref name.Reference, checkOpts *cosign.CheckOpts) ([]Signature, error) {
	checkOpts.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	attestations, _, err := cosignVerifyAttestations(ctx, ref, checkOpts)
	sigList := make([]Signature, len(attestations))
	for i, s := range attestations {
		sigList[i] = s
	}
	return sigList, err
}

func parsePems(b []byte) []*pem.Block {
	p, rest := pem.Decode(b)
	if p == nil {
		return nil
	}
	pems := []*pem.Block{p}

	if rest != nil {
		return append(pems, parsePems(rest)...)
	}
	return pems
}

func AttestationToPayloadJSON(ctx context.Context, predicateType string, sig Signature) ([]byte, string, error) {
	return policy.AttestationToPayloadJSON(ctx, predicateType, &OCISig{sig})
}

// This shim type is needed because AttestationToPayloadJSON expects an oci.Signature
// TODO: Remove once https://github.com/sigstore/cosign/pull/3693 is merged.
type OCISig struct {
	Sig Signature
}

func (s *OCISig) Digest() (v1.Hash, error) {
	return s.Sig.Digest()
}

func (s *OCISig) Payload() ([]byte, error) {
	return s.Sig.Payload()
}

func (s *OCISig) Signature() ([]byte, error) {
	return s.Sig.Signature()
}

func (s *OCISig) Cert() (*x509.Certificate, error) {
	return s.Sig.Cert()
}

func (s *OCISig) DiffID() (v1.Hash, error) {
	panic("unimplemented")
}

func (s *OCISig) Compressed() (io.ReadCloser, error) {
	panic("unimplemented")
}

func (s *OCISig) Uncompressed() (io.ReadCloser, error) {
	panic("unimplemented")
}

func (s *OCISig) Size() (int64, error) {
	panic("unimplemented")
}

func (s *OCISig) MediaType() (types.MediaType, error) {
	panic("unimplemented")
}

func (s *OCISig) Annotations() (map[string]string, error) {
	panic("unimplemented")
}

func (s *OCISig) Base64Signature() (string, error) {
	panic("unimplemented")
}

func (s *OCISig) Chain() ([]*x509.Certificate, error) {
	panic("unimplemented")
}

func (s *OCISig) Bundle() (*cbundle.RekorBundle, error) {
	panic("unimplemented")
}

func (s *OCISig) RFC3161Timestamp() (*cbundle.RFC3161Timestamp, error) {
	panic("unimplemented")
}
