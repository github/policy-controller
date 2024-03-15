// Copyright 2022 The Sigstore Authors.
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

package trustroot

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"knative.dev/pkg/apis"
	logtesting "knative.dev/pkg/logging/testing"

	"github.com/sigstore/policy-controller/pkg/apis/config"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	fakecosignclient "github.com/sigstore/policy-controller/pkg/client/injection/client/fake"
	"github.com/sigstore/policy-controller/pkg/client/injection/reconciler/policy/v1alpha1/trustroot"
	pbcommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgotesting "k8s.io/client-go/testing"
	fakekubeclient "knative.dev/pkg/client/injection/kube/client/fake"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/system"

	. "github.com/sigstore/policy-controller/pkg/reconciler/testing/v1alpha1"
	"github.com/sigstore/policy-controller/pkg/reconciler/trustroot/resources"
	. "knative.dev/pkg/reconciler/testing"
	_ "knative.dev/pkg/system/testing"
)

const (
	trName   = "test-trustroot"
	testKey  = "test-trustroot"
	tkName2  = "test-trustroot-2"
	testKey2 = "test-trustroot-2"

	resourceVersion = "0123456789"
	uid             = "test-uid"
	uid2            = "test-uid-2"

	// NOTE: To generate these values, I deployed the scaffolding bits on a kind clusters
	// using the setup-kind.sh and setup-scaffolding-from-release.sh scripts.
	// Then I extracted the root.json from the tuf-system secrets 'tuf-root' and 'tuf-secrets'.
	// Finally I extracted the rest of public keys from other secrets (ctlog-public-key, fulcio-pub-key)
	// located in the cluster under the tuf-system namespace.
	ctfePublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvffI/l54rF7zt3/3BfNoX1twzqH7
7upU19F2Y+wuGoa2VcDZs2K98Q+gro8Ed8mAqA2zTTtHezAoi2oAueg78Q==
-----END PUBLIC KEY-----
`
	// This is the LogID for above PublicKey
	ctfeLogID = "bbe211cdeecb41c47c88fb8e71ecc98196976a1c596cb563427004c02297b838"

	fulcioCert = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
`
	rekorPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkv2fy2jJU+j8G2YeHkIUo+QRxnbG
09agOlsJ0yGUkNIVC1rBZjxVJp1JwcEiltd5TnQZvgbA89ceC+uTDaILWQ==
-----END PUBLIC KEY-----
`
	// This is the Rekor LogID constructed from above public key.
	rekorLogID = "0b2d9e709031929627f2b11ca95e033288e7f47d19284d184ce09f38a91ec35e"

	tsaCertChain = `-----BEGIN CERTIFICATE-----
MIIBzDCCAXKgAwIBAgIUZUPH+OO1avjh6yXuC5ULzb1+k2UwCgYIKoZIzj0EAwIw
MDEOMAwGA1UEChMFbG9jYWwxHjAcBgNVBAMTFVRlc3QgVFNBIEludGVybWVkaWF0
ZTAeFw0yMzEyMTQxODQ5MTdaFw0zMjEyMTQxODUyMTdaMDAxDjAMBgNVBAoTBWxv
Y2FsMR4wHAYDVQQDExVUZXN0IFRTQSBUaW1lc3RhbXBpbmcwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAR993Thn59aej2hIsxermMDZtkWPGiI/Mpt8832Aai09hpe
t0eAxZs63YZxpsaxe8dyPFRGPybqhcnS2ZCuDZBio2owaDAOBgNVHQ8BAf8EBAMC
B4AwHQYDVR0OBBYEFLVrD1+j0NPcLasvTR8dK7XKHBODMB8GA1UdIwQYMBaAFPFk
kA4uYP9CJQquNfmYzOoevKF7MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAoGCCqG
SM49BAMCA0gAMEUCIHGg+5vmjV8IVjF1YozA6T1/BfSvrzLdnYTzKcFifqt6AiEA
9wcCu+WOvXKjDHs2zBg+TMT7qXpAlBkOnnMm4yAGMSs=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB0jCCAXigAwIBAgIURSspcypzjzFrHLwUtNszm0BP+/YwCgYIKoZIzj0EAwIw
KDEOMAwGA1UEChMFbG9jYWwxFjAUBgNVBAMTDVRlc3QgVFNBIFJvb3QwHhcNMjMx
MjE0MTg0NzE3WhcNMzMxMjE0MTg1MjE3WjAwMQ4wDAYDVQQKEwVsb2NhbDEeMBwG
A1UEAxMVVGVzdCBUU0EgSW50ZXJtZWRpYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEr64R6A+yPiaGiy8415wiNR2O+stQRBV6lZd4CRj3X1TRscubloPg8rqC
hI+rkKxZcorUcbttY8czAX2dfbKTF6N4MHYwDgYDVR0PAQH/BAQDAgEGMBMGA1Ud
JQQMMAoGCCsGAQUFBwMIMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFPFkkA4u
YP9CJQquNfmYzOoevKF7MB8GA1UdIwQYMBaAFKvIdE0MNqeYCWwwXRgRSTZXUTEN
MAoGCCqGSM49BAMCA0gAMEUCIQD8GIA7qFSNDydORnYXXIwrJ5uO32FSaW0qcHMb
WOlolwIgb2kn+VSg4BmcKbmCgHeuFbTwFUqU6eFqfhBh8nvmtsA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBlTCCATqgAwIBAgIUTKlhisZwtRxym+KutMpP3tucKkQwCgYIKoZIzj0EAwIw
KDEOMAwGA1UEChMFbG9jYWwxFjAUBgNVBAMTDVRlc3QgVFNBIFJvb3QwHhcNMjMx
MjE0MTg0NzE3WhcNMzMxMjE0MTg1MjE3WjAoMQ4wDAYDVQQKEwVsb2NhbDEWMBQG
A1UEAxMNVGVzdCBUU0EgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABA8X
+xFvyn5ErnM2ChAN4iF9h/RUhjsB97jyWStGt3UdjytbmOo6j6h9XNV0+txX5Bjy
zkUl2IXJQ0pum6IoRECjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTAD
AQH/MB0GA1UdDgQWBBSryHRNDDanmAlsMF0YEUk2V1ExDTAKBggqhkjOPQQDAgNJ
ADBGAiEAvjuFxcqrLptUj7oBl69g8lc/6xsb3rD5Yb6sr/3izHMCIQDJuZQFmoxe
hw3P1+pEhW1KFW0aig+q9lK0xNcidCTcxA==
-----END CERTIFICATE-----
`

	// This is the marshalled entry from above keys/certs with fixed values
	// (for ease of testing) for other parts.
	marshalledEntry = `{"tlogs":[{"baseUrl":"https://rekor.example.com","hashAlgorithm":"SHA2_256","publicKey":{"rawBytes":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkv2fy2jJU+j8G2YeHkIUo+QRxnbG09agOlsJ0yGUkNIVC1rBZjxVJp1JwcEiltd5TnQZvgbA89ceC+uTDaILWQ=="},"logId":{"keyId":"MGIyZDllNzA5MDMxOTI5NjI3ZjJiMTFjYTk1ZTAzMzI4OGU3ZjQ3ZDE5Mjg0ZDE4NGNlMDlmMzhhOTFlYzM1ZQ=="}}],"certificateAuthorities":[{"subject":{"organization":"fulcio-organization","commonName":"fulcio-common-name"},"uri":"https://fulcio.example.com","certChain":{"certificates":[{"rawBytes":"MIIFwzCCA6ugAwIBAgIIfUmh4cIZr8QwDQYJKoZIhvcNAQELBQAwfjEMMAoGA1UEBhMDVVNBMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRYwFAYDVQQJEw01NDggTWFya2V0IFN0MQ4wDAYDVQQREwU1NzI3NDEZMBcGA1UEChMQTGludXggRm91bmRhdGlvbjAeFw0yMzEyMTQxODUxMzlaFw0yNDEyMTQxODUxMzlaMH4xDDAKBgNVBAYTA1VTQTETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEWMBQGA1UECRMNNTQ4IE1hcmtldCBTdDEOMAwGA1UEERMFNTcyNzQxGTAXBgNVBAoTEExpbnV4IEZvdW5kYXRpb24wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDHVwB8bv84fUgVOqjjWtMAK4i5Zl93I9aizh9S/qIuJNnKx1tA87xZcAuO5riq/kXA2fZGnnP4Vsp9VaVjK9o7+1QP2rFJ4p5rrQlZFovvrD1e6jEaoMc06v+YY4yl37b17W9sfd+5x5wZ0ArRjPAihpdVjYJwlqDRB0AlSo6Vq/aM9QejMG4CS1jXrEEUV8MwRNjyT2xdR4vkc6wj47A1/rknjCtMsieSeSmH/ZDamUGuUh5ej4/dmCiLw93Rou/yLlDcvAcFVzrrLMF/lRwUDUgoH1XDlpeCC1r5HB6jp1Huap9gcLNS3UCIZVpNDO0A3pjYaLBQ3bfHe6QxKuQcEd+VKqyP9SoPdNn31cygF28VR+k+0jU5uXxW7ilXrv7DVYMOcMNZCDA0BQdH/A3fO0ri+8t2Luo+EilRWROBsJTuC28sesYc5NUUoszxVUoQFAhkxE6k5rGIzxO8XplgLjx0IPxU0wjjVhcBa7AKkAMT7gDrPXijhJbv7Q3QVkChOdj6VTPagCS+JtWBkzGvCNJmaIrbLdWFTtDMXfSSZoRyn/aXjQr/OFzBf6dDxJqEMvdD5T5Gg1sldZ00KLKqEx25i8HVZ8XoV4jrZOH1b9nZa3DGZOPmditlqUppvJ7c6OIGqkpE1o8mcNKko/p0dCwcHQtXgIN576foyNG+twIDAQABo0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQU6A9czPqMog/PFdvjxH3V/56BBhcwDQYJKoZIhvcNAQELBQADggIBAAGqm7dJS+pNgCEUDE79S2r6c+BcH6DwTFvAujE0yvdTRdAVIo73CsqPW4cDFuCw2ekOhD17JUT+9PEGJv++u16X4tLHVI5QHPleU/qzZHSEIYt0AE+y9JELR2RT0g11YToGzhIAto5OpOvBb1z+Q8uP5g4eK7Y8J2lVRkDk/62EtsaHTWgv9hJJqsdwoUMVWxn/s0oanPjyGBMSwpoFDXX/k14NDsCGp7d2e5/DxjgYAenDTtnID3VKkvP46spBZ4yEbNIywjaubSXnNLsx2cY8Ypih23e8c1uQJ3O44FDYXVcqYZX9UOrKHS0aE5VpU5J/j2fr4hGE3SfRXXDizcZJcVWPL+k1DHKWlCREMYw12ha3Oe0uIlwKW7syTNnn8NgxxRgM4f83n0C/00CSqiTm8MYya3ue0m2gmCg6TguALbcIqZ3tEK3KvvNIbgxM0ZSePI8YktvtLTQsRK8bbianOht+CwYD2NnFKo68G0l57ByKXze0wG18i943+NTOvU/Le+8SEwJ4asRld3v3L8pCpNAM7JX12zoqisAnCCj3hu6waA5XvMehSTj8yYtIxP1l1I1qfRJzMB9nGv9KzwmozHiw3oGJr/G3j1u1krrQfj4S6z16Bq29nfILFnmk/MoeqYS6DBRY80b60289+R7CSCB5OQbQYvmjy/sxvcNO"}]}}],"ctlogs":[{"baseUrl":"https://ctfe.example.com","hashAlgorithm":"SHA2_256","publicKey":{"rawBytes":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvffI/l54rF7zt3/3BfNoX1twzqH77upU19F2Y+wuGoa2VcDZs2K98Q+gro8Ed8mAqA2zTTtHezAoi2oAueg78Q=="},"logId":{"keyId":"YmJlMjExY2RlZWNiNDFjNDdjODhmYjhlNzFlY2M5ODE5Njk3NmExYzU5NmNiNTYzNDI3MDA0YzAyMjk3YjgzOA=="}}],"timestampAuthorities":[{"subject":{"organization":"tsa-organization","commonName":"tsa-common-name"},"uri":"https://tsa.example.com","certChain":{"certificates":[{"rawBytes":"MIIBzDCCAXKgAwIBAgIUZUPH+OO1avjh6yXuC5ULzb1+k2UwCgYIKoZIzj0EAwIwMDEOMAwGA1UEChMFbG9jYWwxHjAcBgNVBAMTFVRlc3QgVFNBIEludGVybWVkaWF0ZTAeFw0yMzEyMTQxODQ5MTdaFw0zMjEyMTQxODUyMTdaMDAxDjAMBgNVBAoTBWxvY2FsMR4wHAYDVQQDExVUZXN0IFRTQSBUaW1lc3RhbXBpbmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR993Thn59aej2hIsxermMDZtkWPGiI/Mpt8832Aai09hpet0eAxZs63YZxpsaxe8dyPFRGPybqhcnS2ZCuDZBio2owaDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFLVrD1+j0NPcLasvTR8dK7XKHBODMB8GA1UdIwQYMBaAFPFkkA4uYP9CJQquNfmYzOoevKF7MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAoGCCqGSM49BAMCA0gAMEUCIHGg+5vmjV8IVjF1YozA6T1/BfSvrzLdnYTzKcFifqt6AiEA9wcCu+WOvXKjDHs2zBg+TMT7qXpAlBkOnnMm4yAGMSs="},{"rawBytes":"MIIB0jCCAXigAwIBAgIURSspcypzjzFrHLwUtNszm0BP+/YwCgYIKoZIzj0EAwIwKDEOMAwGA1UEChMFbG9jYWwxFjAUBgNVBAMTDVRlc3QgVFNBIFJvb3QwHhcNMjMxMjE0MTg0NzE3WhcNMzMxMjE0MTg1MjE3WjAwMQ4wDAYDVQQKEwVsb2NhbDEeMBwGA1UEAxMVVGVzdCBUU0EgSW50ZXJtZWRpYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr64R6A+yPiaGiy8415wiNR2O+stQRBV6lZd4CRj3X1TRscubloPg8rqChI+rkKxZcorUcbttY8czAX2dfbKTF6N4MHYwDgYDVR0PAQH/BAQDAgEGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFPFkkA4uYP9CJQquNfmYzOoevKF7MB8GA1UdIwQYMBaAFKvIdE0MNqeYCWwwXRgRSTZXUTENMAoGCCqGSM49BAMCA0gAMEUCIQD8GIA7qFSNDydORnYXXIwrJ5uO32FSaW0qcHMbWOlolwIgb2kn+VSg4BmcKbmCgHeuFbTwFUqU6eFqfhBh8nvmtsA="},{"rawBytes":"MIIBlTCCATqgAwIBAgIUTKlhisZwtRxym+KutMpP3tucKkQwCgYIKoZIzj0EAwIwKDEOMAwGA1UEChMFbG9jYWwxFjAUBgNVBAMTDVRlc3QgVFNBIFJvb3QwHhcNMjMxMjE0MTg0NzE3WhcNMzMxMjE0MTg1MjE3WjAoMQ4wDAYDVQQKEwVsb2NhbDEWMBQGA1UEAxMNVGVzdCBUU0EgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABA8X+xFvyn5ErnM2ChAN4iF9h/RUhjsB97jyWStGt3UdjytbmOo6j6h9XNV0+txX5BjyzkUl2IXJQ0pum6IoRECjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSryHRNDDanmAlsMF0YEUk2V1ExDTAKBggqhkjOPQQDAgNJADBGAiEAvjuFxcqrLptUj7oBl69g8lc/6xsb3rD5Yb6sr/3izHMCIQDJuZQFmoxehw3P1+pEhW1KFW0aig+q9lK0xNcidCTcxA=="}]}}]}`

	// validRepository is a valid tar/gzipped repository representing an air-gap
	// TUF repository.
	validRepository = `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`

	// IMPORTANT: The next expiration is on '2024-06-14T18:52:45Z'
	// rootJSON is a valid base64 encoded root.json for above TUF repository.
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDI0LTA2LTE0VDE4OjUyOjQ1WiIsCiAgImtleXMiOiB7CiAgICIwOGYzZThjZTZiYzMwYTA2YjBhMTQzODNmMjg2YzJmODZmM2YzYzZlMWJjZjNkNDgxNmNiMGIwNDUxZmY2NGFjIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICI0NGFlNzMzZDk1MWY1YzM5MWJhZjQ5NmNiMDExNzMzYjFjZDFjYmZhYzg1ZTViMTg0YjJiMjI4N2YzMDgxMDA2IgogICAgfQogICB9LAogICAiMjUwZGFlNzZlOWVkNTM3MjU4MmViMzE5OGMyZDUzNDBjNmM2NWY0ZTdiYmUyMzAzNmJjNWExZjkwN2ZkNDUwOSI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiY2VhNmE0OGJmNGQ1YzFkZDc1MDQ0NmMxMzVjZWNhZjkyMDczZGU2OGRjMjVjYTkxZjgwNTgzZjE3NzYzZjI5NSIKICAgIH0KICAgfSwKICAgIjRlMDA0ZDRlMDM3ZThjMzBkN2YxZTMzODU1MmRlNDcyNzg2ZDkyYTM3NzEwYjExYTc2YTVjNDdiMDBkOTZkOTkiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogIjIwOTkyNGE0OTAxMDBkNDhhNWVkYTcyYjg1OTE4NThmZGUyMGU1MTVkMDgyZGNiMTBhNDllNzA1NDAwZTg5ZTMiCiAgICB9CiAgIH0sCiAgICJhMGUyMTFlMjQyNzVlZTJlY2NlYmI3Yzc5YTJhYzc4NjhkMGIzMDhjMTBmNjBjYTgxZTA2YmIxMzIxNjY3ZjFmIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICJlOGM1NzhjNDJmMDEzZTJjNTk1N2JmOWI3ZGI2N2RjNjgwODUwOWJhNzQxMTM2OGY4Y2M1YzNjM2ZiOTBkNGI5IgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiMjUwZGFlNzZlOWVkNTM3MjU4MmViMzE5OGMyZDUzNDBjNmM2NWY0ZTdiYmUyMzAzNmJjNWExZjkwN2ZkNDUwOSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICJhMGUyMTFlMjQyNzVlZTJlY2NlYmI3Yzc5YTJhYzc4NjhkMGIzMDhjMTBmNjBjYTgxZTA2YmIxMzIxNjY3ZjFmIgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiNGUwMDRkNGUwMzdlOGMzMGQ3ZjFlMzM4NTUyZGU0NzI3ODZkOTJhMzc3MTBiMTFhNzZhNWM0N2IwMGQ5NmQ5OSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiMDhmM2U4Y2U2YmMzMGEwNmIwYTE0MzgzZjI4NmMyZjg2ZjNmM2M2ZTFiY2YzZDQ4MTZjYjBiMDQ1MWZmNjRhYyIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IGZhbHNlCiB9LAogInNpZ25hdHVyZXMiOiBbCiAgewogICAia2V5aWQiOiAiMjUwZGFlNzZlOWVkNTM3MjU4MmViMzE5OGMyZDUzNDBjNmM2NWY0ZTdiYmUyMzAzNmJjNWExZjkwN2ZkNDUwOSIsCiAgICJzaWciOiAiMzJkNDUwYjBmMmFiZDI0NmY3M2NlNzZkMGNkYWE3MTEzZGFmNWRjMTYxN2MyZTEwODZmYmI1MWYyYTU4NDU4YjExNTUzN2YwYWM0MTdlZTM0NjllZWM2ZTFiOWE0YmQwZmIwZWEyNzEzZWE0MTdiNGExZGQ5ZDViODIxZjRkMGMiCiAgfQogXQp9`

	// These are the public keys from an airgapped TUF repository.
	/* TODO(vaikas): Uncomment and test these make the roundtrip
		tufCTFE = `-----BEGIN PUBLIC KEY-----
		MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJvCJi707fv5tMJ1U2TVMZ+uO4dKG
		aEcvjlCkgBCKXbrkumZV0m0dSlK1V1gxEiyQ8y6hk1MxJNe2AZrZUt7a4w==
		-----END PUBLIC KEY-----
	`
		tufFulcio = `-----BEGIN CERTIFICATE-----
		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
		-----END CERTIFICATE-----
	`
		tufRekor = `-----BEGIN PUBLIC KEY-----
		MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEenlW+tMJ9ymhl858kKiD14CC06x9
		r36rTqTSiLYrdl2ZVE3mOD/KcbyBZM1/RHVKx/g1r3d0YSoVCKbF4DAvcQ==
		-----END PUBLIC KEY-----
	`
	*/

	// this is the marshalled entry for when we construct from the repository.
	marshalledEntryFromMirrorFS = `{"tlogs":[{"publicKey":{"rawBytes":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkv2fy2jJU+j8G2YeHkIUo+QRxnbG09agOlsJ0yGUkNIVC1rBZjxVJp1JwcEiltd5TnQZvgbA89ceC+uTDaILWQ=="},"logId":{"keyId":"MGIyZDllNzA5MDMxOTI5NjI3ZjJiMTFjYTk1ZTAzMzI4OGU3ZjQ3ZDE5Mjg0ZDE4NGNlMDlmMzhhOTFlYzM1ZQ=="}}],"certificateAuthorities":[{"certChain":{"certificates":[{"rawBytes":"MIIFwzCCA6ugAwIBAgIIfUmh4cIZr8QwDQYJKoZIhvcNAQELBQAwfjEMMAoGA1UEBhMDVVNBMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRYwFAYDVQQJEw01NDggTWFya2V0IFN0MQ4wDAYDVQQREwU1NzI3NDEZMBcGA1UEChMQTGludXggRm91bmRhdGlvbjAeFw0yMzEyMTQxODUxMzlaFw0yNDEyMTQxODUxMzlaMH4xDDAKBgNVBAYTA1VTQTETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEWMBQGA1UECRMNNTQ4IE1hcmtldCBTdDEOMAwGA1UEERMFNTcyNzQxGTAXBgNVBAoTEExpbnV4IEZvdW5kYXRpb24wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDHVwB8bv84fUgVOqjjWtMAK4i5Zl93I9aizh9S/qIuJNnKx1tA87xZcAuO5riq/kXA2fZGnnP4Vsp9VaVjK9o7+1QP2rFJ4p5rrQlZFovvrD1e6jEaoMc06v+YY4yl37b17W9sfd+5x5wZ0ArRjPAihpdVjYJwlqDRB0AlSo6Vq/aM9QejMG4CS1jXrEEUV8MwRNjyT2xdR4vkc6wj47A1/rknjCtMsieSeSmH/ZDamUGuUh5ej4/dmCiLw93Rou/yLlDcvAcFVzrrLMF/lRwUDUgoH1XDlpeCC1r5HB6jp1Huap9gcLNS3UCIZVpNDO0A3pjYaLBQ3bfHe6QxKuQcEd+VKqyP9SoPdNn31cygF28VR+k+0jU5uXxW7ilXrv7DVYMOcMNZCDA0BQdH/A3fO0ri+8t2Luo+EilRWROBsJTuC28sesYc5NUUoszxVUoQFAhkxE6k5rGIzxO8XplgLjx0IPxU0wjjVhcBa7AKkAMT7gDrPXijhJbv7Q3QVkChOdj6VTPagCS+JtWBkzGvCNJmaIrbLdWFTtDMXfSSZoRyn/aXjQr/OFzBf6dDxJqEMvdD5T5Gg1sldZ00KLKqEx25i8HVZ8XoV4jrZOH1b9nZa3DGZOPmditlqUppvJ7c6OIGqkpE1o8mcNKko/p0dCwcHQtXgIN576foyNG+twIDAQABo0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQU6A9czPqMog/PFdvjxH3V/56BBhcwDQYJKoZIhvcNAQELBQADggIBAAGqm7dJS+pNgCEUDE79S2r6c+BcH6DwTFvAujE0yvdTRdAVIo73CsqPW4cDFuCw2ekOhD17JUT+9PEGJv++u16X4tLHVI5QHPleU/qzZHSEIYt0AE+y9JELR2RT0g11YToGzhIAto5OpOvBb1z+Q8uP5g4eK7Y8J2lVRkDk/62EtsaHTWgv9hJJqsdwoUMVWxn/s0oanPjyGBMSwpoFDXX/k14NDsCGp7d2e5/DxjgYAenDTtnID3VKkvP46spBZ4yEbNIywjaubSXnNLsx2cY8Ypih23e8c1uQJ3O44FDYXVcqYZX9UOrKHS0aE5VpU5J/j2fr4hGE3SfRXXDizcZJcVWPL+k1DHKWlCREMYw12ha3Oe0uIlwKW7syTNnn8NgxxRgM4f83n0C/00CSqiTm8MYya3ue0m2gmCg6TguALbcIqZ3tEK3KvvNIbgxM0ZSePI8YktvtLTQsRK8bbianOht+CwYD2NnFKo68G0l57ByKXze0wG18i943+NTOvU/Le+8SEwJ4asRld3v3L8pCpNAM7JX12zoqisAnCCj3hu6waA5XvMehSTj8yYtIxP1l1I1qfRJzMB9nGv9KzwmozHiw3oGJr/G3j1u1krrQfj4S6z16Bq29nfILFnmk/MoeqYS6DBRY80b60289+R7CSCB5OQbQYvmjy/sxvcNO"}]}}],"ctlogs":[{"publicKey":{"rawBytes":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvffI/l54rF7zt3/3BfNoX1twzqH77upU19F2Y+wuGoa2VcDZs2K98Q+gro8Ed8mAqA2zTTtHezAoi2oAueg78Q=="},"logId":{"keyId":"YmJlMjExY2RlZWNiNDFjNDdjODhmYjhlNzFlY2M5ODE5Njk3NmExYzU5NmNiNTYzNDI3MDA0YzAyMjk3YjgzOA=="}}]}`

	// Just some formatting strings that make it easier to construct patches
	// to config map.
	replacePatchFmtString = `[{"op":"replace","path":"/data/%s","value":"%s"}]`
	removePatchFmtString  = `[{"op":"remove","path":"/data/%s"}]`
)

// testmap with prepopulated (grabbed from an instance of scaffolding) entries
// for creating TrustRoot resource.
// ctfe   => CTLog Public Key
// fulcio => CertificateAuthority certificate
// rekor  => TLog PublicKey
// tsa    => TimeStampAuthorities certificate chain (root, intermediate, leaf)
var sigstoreKeys = map[string]string{
	"ctfe":   ctfePublicKey,
	"fulcio": fulcioCert,
	"rekor":  rekorPublicKey,
	"tsa":    tsaCertChain,
}

// canonicalizeSigstoreKeys round-trips the SigstoreKeys through protojson so
// the output is deterministic for the current test run. This is necessary
// because protojson has "randomly deterministic" output, meaning it will add
// whitespace randomly depending on the digest of the executable.
// See https://go-review.googlesource.com/c/protobuf/+/151340 and
// https://github.com/golang/protobuf/issues/1121
func canonicalizeSigstoreKeys(in string) string {
	keys := &config.SigstoreKeys{}
	err := protojson.Unmarshal([]byte(in), keys)
	if err != nil {
		panic(err)
	}
	out, err := protojson.Marshal(keys)
	if err != nil {
		panic(err)
	}
	return string(out)
}

func TestReconcile(t *testing.T) {
	rootJSONDecoded, err := base64.StdEncoding.DecodeString(rootJSON)
	if err != nil {
		t.Fatalf("Failed to decode rootJSON for testing: %v", err)
	}
	validRepositoryDecoded, err := base64.StdEncoding.DecodeString(validRepository)
	if err != nil {
		t.Fatalf("Failed to decode validRepository for testing: %v", err)
	}

	table := TableTest{{
		Name: "bad workqueue key",
		// Make sure Reconcile handles bad keys.
		Key: "too/many/parts",
	}, {
		Name: "key not found",
		// Make sure Reconcile handles good keys that don't exist.
		Key: "foo/not-found",
	}, {
		Name: "TrustRoot not found",
		Key:  testKey,
	}, {
		Name: "TrustRoot is being deleted, doesn't exist, no changes",
		Key:  testKey,
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootDeletionTimestamp),
		},
	}, {
		Name: "TrustRoot with SigstoreKeys, cm created and finalizer",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
			)},
		WantCreates: []runtime.Object{
			makeConfigMapWithSigstoreKeys(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			patchFinalizers(system.Namespace(), trName),
		},
		WantEvents: []string{
			Eventf(corev1.EventTypeNormal, "FinalizerUpdate", `Updated "test-trustroot" finalizers`),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				MarkReadyTrustRoot,
			)}},
	}, {
		Name: "TrustRoot with SigstoreKeys, cm exists with entry, no changes",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
			),
			makeConfigMapWithSigstoreKeys(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			patchFinalizers(system.Namespace(), trName),
		},
		WantEvents: []string{
			Eventf(corev1.EventTypeNormal, "FinalizerUpdate", `Updated "test-trustroot" finalizers`),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				MarkReadyTrustRoot,
			)}},
	}, {
		Name: "TrustRoot with SigstoreKeys, cm exists with different, replace patched",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
			),
			makeDifferentConfigMap(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			makePatch(replacePatchFmtString, trName, canonicalizeSigstoreKeys(marshalledEntry)),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
				MarkReadyTrustRoot,
			)}},
	}, {
		Name: "TrustRoot with SigstoreKeys, cm exists with different, replace patched but fails",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
			),
			makeDifferentConfigMap(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			makePatch(replacePatchFmtString, trName, canonicalizeSigstoreKeys(marshalledEntry)),
		},
		WithReactors: []clientgotesting.ReactionFunc{
			InduceFailure("patch", "configmaps"),
		},
		WantErr: true,
		WantEvents: []string{
			Eventf(corev1.EventTypeWarning, "InternalError", "inducing failure for patch configmaps"),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
				WithInitConditionsTrustRoot,
				WithObservedGenerationTrustRoot(1),
				WithMarkInlineKeysOkTrustRoot,
				WithMarkCMUpdateFailedTrustRoot("inducing failure for patch configmaps"),
			)}},
	}, {
		Name: "Two SigstoreKeys, one deleted, verify it is removed",
		Key:  testKey2,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
			),
			NewTrustRoot(tkName2,
				WithTrustRootUID(uid2),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
				WithTrustRootDeletionTimestamp,
			),
			makeConfigMapWithTwoEntries(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			patchRemoveFinalizers(system.Namespace(), testKey2),
			makeRemovePatch(tkName2),
		},
		WantEvents: []string{
			Eventf(corev1.EventTypeNormal, "FinalizerUpdate", `Updated "test-trustroot-2" finalizers`),
		},
	}, {
		Name: "With repository",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithRepository("targets", rootJSONDecoded, validRepositoryDecoded),
				WithTrustRootFinalizer,
			),
		},
		WantCreates: []runtime.Object{
			makeConfigMapWithMirrorFS(),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithRepository("targets", rootJSONDecoded, validRepositoryDecoded),
				WithTrustRootFinalizer,
				MarkReadyTrustRoot,
			)}},
	}}

	logger := logtesting.TestLogger(t)
	table.Test(t, MakeFactory(func(ctx context.Context, listers *Listers, cmw configmap.Watcher) controller.Reconciler {
		r := &Reconciler{
			configmaplister: listers.GetConfigMapLister(),
			kubeclient:      fakekubeclient.Get(ctx),
		}
		return trustroot.NewReconciler(ctx, logger,
			fakecosignclient.Get(ctx), listers.GetTrustRootLister(),
			controller.GetEventRecorder(ctx),
			r)
	},
		false,
		logger,
		nil, // Only meaningful for CIP reconciler, but reuse the same factory.
	))
}

func makeConfigMapWithSigstoreKeys() *corev1.ConfigMap {
	ret := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.SigstoreKeysConfigName,
		},
		Data: make(map[string]string),
	}
	source := NewTrustRoot(trName, WithSigstoreKeys(sigstoreKeys))
	c := config.ConvertSigstoreKeys(context.Background(), source.Spec.SigstoreKeys)
	for i := range c.Tlogs {
		c.Tlogs[i].LogId = &config.LogId{KeyId: []byte(rekorLogID)}

	}
	for i := range c.Ctlogs {
		c.Ctlogs[i].LogId = &config.LogId{KeyId: []byte(ctfeLogID)}
	}
	marshalled, err := resources.Marshal(c)
	if err != nil {
		panic("failed to marshal test SigstoreKeys")
	}
	ret.Data[trName] = marshalled
	return ret
}

func makeConfigMapWithMirrorFS() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.SigstoreKeysConfigName,
		},
		Data: map[string]string{"test-trustroot": canonicalizeSigstoreKeys(marshalledEntryFromMirrorFS)},
	}
}

// Same as above, just forcing an update because the entry in the configMap
// is not what we expect, it doesn't really matter what it is.
func makeDifferentConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.SigstoreKeysConfigName,
		},
		Data: map[string]string{
			trName: `{"uid":"test-uid","resourceVersion":"0123456789",
images":[{"glob":"ghcr.io/example/*"}],"authorities":[{"name":"authority-0","key":{"data":"-----BEGIN NOTPUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\n-----END NOTPUBLIC KEY-----"}}]}`,
		},
	}
}

// Same as MakeConfigMap but a placeholder for second entry so we can remove it.
func makeConfigMapWithTwoEntries() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.SigstoreKeysConfigName,
		},
		Data: map[string]string{
			trName:  canonicalizeSigstoreKeys(marshalledEntry),
			tkName2: "remove me please",
		},
	}
}

// makePatch makes a patch that one would be able to patch ConfigMap with.
// fmtstr defines the ops/targets, key is the actual key the operation is
// in the configmap. patch is the unescape quoted (for ease of readability in
// constants) that will then be escaped before creating the patch.
func makePatch(fmtstr, key, patch string) clientgotesting.PatchActionImpl {
	escapedPatch := strings.ReplaceAll(patch, "\"", "\\\"")
	out := fmt.Sprintf(fmtstr, key, escapedPatch)
	return clientgotesting.PatchActionImpl{
		ActionImpl: clientgotesting.ActionImpl{
			Namespace: system.Namespace(),
		},
		Name:  config.SigstoreKeysConfigName,
		Patch: []byte(out),
	}
}

// makeRemovePatch makes a patch suitable for removing from a configmap.
func makeRemovePatch(key string) clientgotesting.PatchActionImpl {
	return clientgotesting.PatchActionImpl{
		ActionImpl: clientgotesting.ActionImpl{
			Namespace: system.Namespace(),
		},
		Name:  config.SigstoreKeysConfigName,
		Patch: []byte(fmt.Sprintf(removePatchFmtString, key)),
	}
}

func patchFinalizers(namespace, name string) clientgotesting.PatchActionImpl {
	action := clientgotesting.PatchActionImpl{}
	action.Name = name
	action.Namespace = namespace
	patch := `{"metadata":{"finalizers":["` + FinalizerName + `"],"resourceVersion":"` + resourceVersion + `"}}`
	action.Patch = []byte(patch)
	return action
}

func patchRemoveFinalizers(namespace, name string) clientgotesting.PatchActionImpl {
	action := clientgotesting.PatchActionImpl{}
	action.Name = name
	action.Namespace = namespace
	patch := `{"metadata":{"finalizers":[],"resourceVersion":"` + resourceVersion + `"}}`
	action.Patch = []byte(patch)
	return action
}

// TestConvertSigstoreKeys tests marshalling / unmarshalling to the configmap and back.
// This is here instead of in the pkg/apis/config because of import cycles and
// having both types v1alpha1.SigstoreTypes and config.SigstoreTypes being
// available makes testing way easier, and due to import cycles we can't put
// that in config and yet import v1alpha1.
func TestConvertSigstoreKeys(t *testing.T) {
	itemsPerEntry := 2

	type key struct {
		pem []byte
		der []byte
	}
	type testTlog struct {
		url           string
		hashAlgorithm string
		publicKey     key
	}
	type testCA struct {
		url        string
		org        string
		commonName string
		certChain  []key
	}
	type testData struct {
		tlogs  []testTlog
		ctlogs []testTlog
		cas    []testCA
		tsas   []testCA
	}

	hashAlgorithms := []string{"sha-256", "sha-512"}
	hashAlgorithmMap := map[string]pbcommon.HashAlgorithm{"sha-256": pbcommon.HashAlgorithm_SHA2_256, "sha-512": pbcommon.HashAlgorithm_SHA2_512}

	test := testData{}

	// construct test data
	for i := 0; i < itemsPerEntry; i++ {
		for _, service := range []string{"tlog", "ctlog"} {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ecdsa key: %v", err)
			}
			der, err := x509.MarshalPKIXPublicKey(priv.Public().(*ecdsa.PublicKey))
			if err != nil {
				t.Fatalf("failed to marshal ecdsa key: %v", err)
			}
			pem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
			tlog := testTlog{
				url:           fmt.Sprintf("https://%s-%d.example.com", service, i),
				hashAlgorithm: hashAlgorithms[i%2],
				publicKey:     key{pem, der},
			}

			switch service {
			case "tlog":
				test.tlogs = append(test.tlogs, tlog)
			case "ctlog":
				test.ctlogs = append(test.ctlogs, tlog)
			}
		}
		for _, service := range []string{"fulcio", "tsa"} {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ecdsa key: %v", err)
			}
			template := x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					CommonName: "Test Certificate",
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().AddDate(1, 0, 0),
				KeyUsage:              x509.KeyUsageDigitalSignature,
				BasicConstraintsValid: true,
			}
			der, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
			if err != nil {
				t.Fatalf("failed to create x509 certificate: %v", err)
			}
			pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			ca := testCA{
				url:        fmt.Sprintf("https://%s-%d.example.com", service, i),
				org:        fmt.Sprintf("Test Org %d for %s", i, service),
				commonName: fmt.Sprintf("Test CA %d for %s", i, service),
				certChain:  []key{{pem, der}},
			}

			switch service {
			case "fulcio":
				test.cas = append(test.cas, ca)
			case "tsa":
				test.tsas = append(test.tsas, ca)
			}
		}
	}

	// create and populate source
	source := v1alpha1.SigstoreKeys{}

	for _, tlog := range test.tlogs {
		url, err := apis.ParseURL(tlog.url)
		if err != nil {
			t.Fatalf("failed to parse url: %v", err)
		}
		source.TLogs = append(source.TLogs, v1alpha1.TransparencyLogInstance{
			BaseURL:       *url,
			HashAlgorithm: tlog.hashAlgorithm,
			PublicKey:     tlog.publicKey.pem,
		})
	}
	for _, ctlog := range test.ctlogs {
		url, err := apis.ParseURL(ctlog.url)
		if err != nil {
			t.Fatalf("failed to parse url: %v", err)
		}
		source.CTLogs = append(source.CTLogs, v1alpha1.TransparencyLogInstance{
			BaseURL:       *url,
			HashAlgorithm: ctlog.hashAlgorithm,
			PublicKey:     ctlog.publicKey.pem,
		})
	}
	for _, ca := range test.cas {
		url, err := apis.ParseURL(ca.url)
		if err != nil {
			t.Fatalf("failed to parse url: %v", err)
		}
		source.CertificateAuthorities = append(source.CertificateAuthorities, v1alpha1.CertificateAuthority{
			Subject: v1alpha1.DistinguishedName{
				Organization: ca.org,
				CommonName:   ca.commonName,
			},
			URI:       *url,
			CertChain: ca.certChain[0].pem,
		})
	}
	for _, tsa := range test.tsas {
		url, err := apis.ParseURL(tsa.url)
		if err != nil {
			t.Fatalf("failed to parse url: %v", err)
		}
		source.TimeStampAuthorities = append(source.TimeStampAuthorities, v1alpha1.CertificateAuthority{
			Subject: v1alpha1.DistinguishedName{
				Organization: tsa.org,
				CommonName:   tsa.commonName,
			},
			URI:       *url,
			CertChain: tsa.certChain[0].pem,
		})
	}

	// convert from v1alpha1 to config and let's marshal to configmap and back
	// to make sure we exercise the path from:
	// v1alpha1 => config => configMap => back (this is what reconciler will
	// use to call cosign verification functions with).
	converted := config.ConvertSigstoreKeys(context.Background(), &source)
	marshalled, err := resources.Marshal(converted)
	if err != nil {
		t.Fatalf("Failed to marshal entry: %v", err)
	}
	tkMap := map[string]string{"test-entry": marshalled}
	skMap, err := config.NewSigstoreKeysFromMap(tkMap)
	if err != nil {
		t.Fatalf("Failed to construct from map entry: %v", err)
	}
	sk := skMap.SigstoreKeys["test-entry"]
	if len(sk.Tlogs) != 2 {
		t.Errorf("Not enough TLog entries, want 2 got %d", len(sk.Tlogs))
	}
	if len(sk.Ctlogs) != 2 {
		t.Errorf("Not enough CTLog entries, want 2 got %d", len(sk.Ctlogs))
	}
	if len(sk.CertificateAuthorities) != 2 {
		t.Errorf("Not enough CertificateAuthority entries, want 2 got %d", len(sk.CertificateAuthorities))
	}
	if len(sk.TimestampAuthorities) != 2 {
		t.Errorf("Not enough TimestampAuthorities entries, want 2 got %d", len(sk.TimestampAuthorities))
	}
	// Verify TLog, CTLog
	for i := 0; i < itemsPerEntry; i++ {
		for _, service := range []string{"tlog", "ctlog"} {
			var entry *config.TransparencyLogInstance
			var tlog testTlog
			switch service {
			case "tlog":
				entry = sk.Tlogs[i]
				tlog = test.tlogs[i]
			case "ctlog":
				entry = sk.Ctlogs[i]
				tlog = test.ctlogs[i]
			default:
				panic("invalid type")
			}
			if entry.BaseUrl != tlog.url {
				t.Errorf("Unexpected BaseUrl for %s %d wanted %s got %s", service, i, tlog.url, entry.BaseUrl)
			}
			if entry.HashAlgorithm != hashAlgorithmMap[tlog.hashAlgorithm] {
				t.Errorf("Unexpected HashAlgorithm for %s %d wanted %s got %s", service, i, tlog.hashAlgorithm, entry.HashAlgorithm)
			}
			if !bytes.Equal(entry.PublicKey.RawBytes, tlog.publicKey.der) {
				t.Errorf("Unexpected PublicKey for %s %d wanted %s got %s", service, i, tlog.publicKey.der, entry.PublicKey.RawBytes)
			}
		}
	}
	// Verify CertificateAuthority, TimestampAuthorities
	for i := 0; i < itemsPerEntry; i++ {
		for _, prefix := range []string{"fulcio", "tsa"} {
			var entry *config.CertificateAuthority
			var ca testCA
			switch prefix {
			case "fulcio":
				entry = sk.CertificateAuthorities[i]
				ca = test.cas[i]
			case "tsa":
				entry = sk.TimestampAuthorities[i]
				ca = test.tsas[i]
			default:
				panic("invalid type")
			}
			if entry.Uri != ca.url {
				t.Errorf("Unexpected Uri for %s %d wanted %s got %s", prefix, i, ca.url, entry.Uri)
			}
			if entry.Subject.Organization != ca.org {
				t.Errorf("Unexpected Organization for %s %d wanted %s got %s", prefix, i, ca.org, entry.Subject.Organization)
			}
			if entry.Subject.CommonName != ca.commonName {
				t.Errorf("Unexpected CommonName for %s %d wanted %s got %s", prefix, i, ca.commonName, entry.Subject.CommonName)
			}
			if !bytes.Equal(entry.CertChain.Certificates[0].RawBytes, ca.certChain[0].der) {
				t.Errorf("Unexpected CertChain for %s %d wanted %s got %s", prefix, i, ca.certChain[0].der, entry.CertChain.Certificates[0].RawBytes)
			}
		}
	}
}
