// RAINBOND, Application Management Platform
// Copyright (C) 2014-2021 Goodrain Co., Ltd.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version. For any non-GPL usage of Rainbond,
// one or multiple Commercial Licenses authorized by Goodrain Co., Ltd.
// must be obtained first.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "github.com/goodrain/rainbond/pkg/apis/rainbond/v1alpha1"
	scheme "github.com/goodrain/rainbond/pkg/generated/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// ComponentDefinitionsGetter has a method to return a ComponentDefinitionInterface.
// A group's client should implement this interface.
type ComponentDefinitionsGetter interface {
	ComponentDefinitions(namespace string) ComponentDefinitionInterface
}

// ComponentDefinitionInterface has methods to work with ComponentDefinition resources.
type ComponentDefinitionInterface interface {
	Create(ctx context.Context, componentDefinition *v1alpha1.ComponentDefinition, opts v1.CreateOptions) (*v1alpha1.ComponentDefinition, error)
	Update(ctx context.Context, componentDefinition *v1alpha1.ComponentDefinition, opts v1.UpdateOptions) (*v1alpha1.ComponentDefinition, error)
	UpdateStatus(ctx context.Context, componentDefinition *v1alpha1.ComponentDefinition, opts v1.UpdateOptions) (*v1alpha1.ComponentDefinition, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.ComponentDefinition, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.ComponentDefinitionList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ComponentDefinition, err error)
	ComponentDefinitionExpansion
}

// componentDefinitions implements ComponentDefinitionInterface
type componentDefinitions struct {
	client rest.Interface
	ns     string
}

// newComponentDefinitions returns a ComponentDefinitions
func newComponentDefinitions(c *RainbondV1alpha1Client, namespace string) *componentDefinitions {
	return &componentDefinitions{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the componentDefinition, and returns the corresponding componentDefinition object, and an error if there is any.
func (c *componentDefinitions) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.ComponentDefinition, err error) {
	result = &v1alpha1.ComponentDefinition{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("componentdefinitions").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of ComponentDefinitions that match those selectors.
func (c *componentDefinitions) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.ComponentDefinitionList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.ComponentDefinitionList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("componentdefinitions").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested componentDefinitions.
func (c *componentDefinitions) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("componentdefinitions").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a componentDefinition and creates it.  Returns the server's representation of the componentDefinition, and an error, if there is any.
func (c *componentDefinitions) Create(ctx context.Context, componentDefinition *v1alpha1.ComponentDefinition, opts v1.CreateOptions) (result *v1alpha1.ComponentDefinition, err error) {
	result = &v1alpha1.ComponentDefinition{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("componentdefinitions").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(componentDefinition).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a componentDefinition and updates it. Returns the server's representation of the componentDefinition, and an error, if there is any.
func (c *componentDefinitions) Update(ctx context.Context, componentDefinition *v1alpha1.ComponentDefinition, opts v1.UpdateOptions) (result *v1alpha1.ComponentDefinition, err error) {
	result = &v1alpha1.ComponentDefinition{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("componentdefinitions").
		Name(componentDefinition.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(componentDefinition).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *componentDefinitions) UpdateStatus(ctx context.Context, componentDefinition *v1alpha1.ComponentDefinition, opts v1.UpdateOptions) (result *v1alpha1.ComponentDefinition, err error) {
	result = &v1alpha1.ComponentDefinition{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("componentdefinitions").
		Name(componentDefinition.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(componentDefinition).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the componentDefinition and deletes it. Returns an error if one occurs.
func (c *componentDefinitions) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("componentdefinitions").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *componentDefinitions) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("componentdefinitions").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched componentDefinition.
func (c *componentDefinitions) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ComponentDefinition, err error) {
	result = &v1alpha1.ComponentDefinition{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("componentdefinitions").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
