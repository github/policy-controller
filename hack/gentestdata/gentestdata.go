package main

// This is a simple program to convert the testdata.SigstoreKeys map into a
// marshalled proto. This is useful for generating testdata for the trustroot
// reconciler.
//
// To run this program, you can use the following command:
// go run hack/gentestdata/gentestdata.go
//
// The output of this program can be used to update the `marshalledEntry.json`
// file in the `pkg/reconciler/trustroot/testdata` package.
//
// Do not rely on the output of this program to produce valid results. Always
// verify the output manually before updating the `marshalledEntry.json` file,
// because if config.ConvertSigstoreKeys produces invalid output, the tests
// will likely produce the same invalid output, causing a false positive.

import (
	"context"
	"fmt"

	"github.com/sigstore/policy-controller/pkg/apis/config"
	testing "github.com/sigstore/policy-controller/pkg/reconciler/testing/v1alpha1"
	"github.com/sigstore/policy-controller/pkg/reconciler/trustroot/testdata"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	trustRoot := testing.NewTrustRoot("test-trustroot", testing.WithSigstoreKeys(testdata.SigstoreKeys))
	trustedRoot := config.ConvertSigstoreKeys(context.Background(), trustRoot.Spec.SigstoreKeys)
	json := protojson.Format(trustedRoot)
	fmt.Println(json)
}
