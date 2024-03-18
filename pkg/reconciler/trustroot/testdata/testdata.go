package testdata

import (
	_ "embed"
)

// NOTE: To generate these values, I deployed the scaffolding bits on a kind clusters
// using the setup-kind.sh and setup-scaffolding-from-release.sh scripts.
// Then I extracted the root.json from the tuf-system secrets 'tuf-root' and 'tuf-secrets'.
// Finally I extracted the rest of public keys from other secrets (ctlog-public-key, fulcio-pub-key)
// located in the cluster under the tuf-system namespace.

//go:embed ctfePublicKey.pem
var CtfePublicKey string

//go:embed fulcioCert.pem
var FulcioCert string

//go:embed rekorPublicKey.pem
var RekorPublicKey string

//go:embed tsaCertChain.pem
var TsaCertChain string

// This is the marshalled entry from above keys/certs with fixed values
// (for ease of testing) for other parts.
//
//go:embed marshalledEntry.json
var MarshalledEntry string

// this is the marshalled entry for when we construct from the repository.
//
//go:embed marshalledEntryFromMirrorFS.json
var MarshalledEntryFromMirrorFS string

// testmap with prepopulated (grabbed from an instance of scaffolding) entries
// for creating TrustRoot resource.
// ctfe   => CTLog Public Key
// fulcio => CertificateAuthority certificate
// rekor  => TLog PublicKey
// tsa    => TimeStampAuthorities certificate chain (root, intermediate, leaf)
var SigstoreKeys = map[string]string{
	"ctfe":   CtfePublicKey,
	"fulcio": FulcioCert,
	"rekor":  RekorPublicKey,
	"tsa":    TsaCertChain,
}
