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

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	scheme "github.com/sigstore/policy-controller/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// TrustRootsGetter has a method to return a TrustRootInterface.
// A group's client should implement this interface.
type TrustRootsGetter interface {
	TrustRoots() TrustRootInterface
}

// TrustRootInterface has methods to work with TrustRoot resources.
type TrustRootInterface interface {
	Create(ctx context.Context, trustRoot *v1alpha1.TrustRoot, opts v1.CreateOptions) (*v1alpha1.TrustRoot, error)
	Update(ctx context.Context, trustRoot *v1alpha1.TrustRoot, opts v1.UpdateOptions) (*v1alpha1.TrustRoot, error)
	UpdateStatus(ctx context.Context, trustRoot *v1alpha1.TrustRoot, opts v1.UpdateOptions) (*v1alpha1.TrustRoot, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.TrustRoot, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.TrustRootList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.TrustRoot, err error)
	TrustRootExpansion
}

// trustRoots implements TrustRootInterface
type trustRoots struct {
	client rest.Interface
}

// newTrustRoots returns a TrustRoots
func newTrustRoots(c *PolicyV1alpha1Client) *trustRoots {
	return &trustRoots{
		client: c.RESTClient(),
	}
}

// Get takes name of the trustRoot, and returns the corresponding trustRoot object, and an error if there is any.
func (c *trustRoots) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.TrustRoot, err error) {
	result = &v1alpha1.TrustRoot{}
	err = c.client.Get().
		Resource("trustroots").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of TrustRoots that match those selectors.
func (c *trustRoots) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.TrustRootList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.TrustRootList{}
	err = c.client.Get().
		Resource("trustroots").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested trustRoots.
func (c *trustRoots) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("trustroots").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a trustRoot and creates it.  Returns the server's representation of the trustRoot, and an error, if there is any.
func (c *trustRoots) Create(ctx context.Context, trustRoot *v1alpha1.TrustRoot, opts v1.CreateOptions) (result *v1alpha1.TrustRoot, err error) {
	result = &v1alpha1.TrustRoot{}
	err = c.client.Post().
		Resource("trustroots").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(trustRoot).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a trustRoot and updates it. Returns the server's representation of the trustRoot, and an error, if there is any.
func (c *trustRoots) Update(ctx context.Context, trustRoot *v1alpha1.TrustRoot, opts v1.UpdateOptions) (result *v1alpha1.TrustRoot, err error) {
	result = &v1alpha1.TrustRoot{}
	err = c.client.Put().
		Resource("trustroots").
		Name(trustRoot.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(trustRoot).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *trustRoots) UpdateStatus(ctx context.Context, trustRoot *v1alpha1.TrustRoot, opts v1.UpdateOptions) (result *v1alpha1.TrustRoot, err error) {
	result = &v1alpha1.TrustRoot{}
	err = c.client.Put().
		Resource("trustroots").
		Name(trustRoot.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(trustRoot).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the trustRoot and deletes it. Returns an error if one occurs.
func (c *trustRoots) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("trustroots").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *trustRoots) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("trustroots").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched trustRoot.
func (c *trustRoots) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.TrustRoot, err error) {
	result = &v1alpha1.TrustRoot{}
	err = c.client.Patch(pt).
		Resource("trustroots").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
