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

package fake

import (
	"context"

	v1alpha1 "github.com/goodrain/rainbond/pkg/apis/rainbond/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeComponentDefinitions implements ComponentDefinitionInterface
type FakeComponentDefinitions struct {
	Fake *FakeRainbondV1alpha1
	ns   string
}

var componentdefinitionsResource = schema.GroupVersionResource{Group: "rainbond.io", Version: "v1alpha1", Resource: "componentdefinitions"}

var componentdefinitionsKind = schema.GroupVersionKind{Group: "rainbond.io", Version: "v1alpha1", Kind: "ComponentDefinition"}

// Get takes name of the componentDefinition, and returns the corresponding componentDefinition object, and an error if there is any.
func (c *FakeComponentDefinitions) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.ComponentDefinition, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(componentdefinitionsResource, c.ns, name), &v1alpha1.ComponentDefinition{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ComponentDefinition), err
}

// List takes label and field selectors, and returns the list of ComponentDefinitions that match those selectors.
func (c *FakeComponentDefinitions) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.ComponentDefinitionList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(componentdefinitionsResource, componentdefinitionsKind, c.ns, opts), &v1alpha1.ComponentDefinitionList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.ComponentDefinitionList{ListMeta: obj.(*v1alpha1.ComponentDefinitionList).ListMeta}
	for _, item := range obj.(*v1alpha1.ComponentDefinitionList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested componentDefinitions.
func (c *FakeComponentDefinitions) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(componentdefinitionsResource, c.ns, opts))

}

// Create takes the representation of a componentDefinition and creates it.  Returns the server's representation of the componentDefinition, and an error, if there is any.
func (c *FakeComponentDefinitions) Create(ctx context.Context, componentDefinition *v1alpha1.ComponentDefinition, opts v1.CreateOptions) (result *v1alpha1.ComponentDefinition, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(componentdefinitionsResource, c.ns, componentDefinition), &v1alpha1.ComponentDefinition{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ComponentDefinition), err
}

// Update takes the representation of a componentDefinition and updates it. Returns the server's representation of the componentDefinition, and an error, if there is any.
func (c *FakeComponentDefinitions) Update(ctx context.Context, componentDefinition *v1alpha1.ComponentDefinition, opts v1.UpdateOptions) (result *v1alpha1.ComponentDefinition, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(componentdefinitionsResource, c.ns, componentDefinition), &v1alpha1.ComponentDefinition{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ComponentDefinition), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeComponentDefinitions) UpdateStatus(ctx context.Context, componentDefinition *v1alpha1.ComponentDefinition, opts v1.UpdateOptions) (*v1alpha1.ComponentDefinition, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(componentdefinitionsResource, "status", c.ns, componentDefinition), &v1alpha1.ComponentDefinition{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ComponentDefinition), err
}

// Delete takes name of the componentDefinition and deletes it. Returns an error if one occurs.
func (c *FakeComponentDefinitions) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(componentdefinitionsResource, c.ns, name), &v1alpha1.ComponentDefinition{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeComponentDefinitions) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(componentdefinitionsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.ComponentDefinitionList{})
	return err
}

// Patch applies the patch and returns the patched componentDefinition.
func (c *FakeComponentDefinitions) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ComponentDefinition, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(componentdefinitionsResource, c.ns, name, pt, data, subresources...), &v1alpha1.ComponentDefinition{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ComponentDefinition), err
}
