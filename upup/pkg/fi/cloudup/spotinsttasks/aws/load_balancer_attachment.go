/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package aws

import (
	"context"
	"fmt"

	"github.com/golang/glog"
	"github.com/spotinst/spotinst-sdk-go/service/elastigroup/providers/aws"
	spotinstsdk "github.com/spotinst/spotinst-sdk-go/spotinst"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/cloudup/spotinst"
)

//go:generate fitask -type=LoadBalancerAttachment
type LoadBalancerAttachment struct {
	Name      *string
	Lifecycle *fi.Lifecycle

	LoadBalancer *LoadBalancer

	// LoadBalancerAttachments now support ASGs or direct instances
	AutoscalingGroup *AutoscalingGroup
	Subnet           *Subnet
}

func (e *LoadBalancerAttachment) Find(c *fi.Context) (*LoadBalancerAttachment, error) {
	cloud := c.Cloud.(*spotinst.SpotinstCloud)

	if spotinstsdk.StringValue(e.LoadBalancer.LoadBalancerName) == "" {
		return nil, fmt.Errorf("LoadBalancer did not have LoadBalancerName set")
	}

	g, err := findAutoscalingGroup(cloud, *e.AutoscalingGroup.Name)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, nil
	}
	if g.Compute.LaunchSpecification.LoadBalancersConfig == nil {
		return nil, nil
	}
	for _, lb := range g.Compute.LaunchSpecification.LoadBalancersConfig.LoadBalancers {
		if spotinstsdk.StringValue(lb.Name) != *e.LoadBalancer.LoadBalancerName {
			continue
		}

		actual := &LoadBalancerAttachment{}
		actual.LoadBalancer = e.LoadBalancer
		actual.AutoscalingGroup = e.AutoscalingGroup

		// Prevent spurious changes
		actual.Name = e.Name // ELB attachments don't have tags

		return actual, nil
	}

	return nil, nil
}

func (e *LoadBalancerAttachment) Run(c *fi.Context) error {
	return fi.DefaultDeltaRunMethod(e, c)
}

func (s *LoadBalancerAttachment) CheckChanges(a, e, changes *LoadBalancerAttachment) error {
	if a == nil {
		if e.LoadBalancer == nil {
			return fi.RequiredField("LoadBalancer")
		}
		if e.AutoscalingGroup == nil {
			return fi.RequiredField("AutoscalingGroup")
		}
	}
	return nil
}

func (_ *LoadBalancerAttachment) RenderAWS(t *spotinst.SpotinstAPITarget, a, e, changes *LoadBalancerAttachment) error {
	if e.LoadBalancer == nil {
		return fi.RequiredField("LoadBalancer")
	}
	loadBalancerName := fi.StringValue(e.LoadBalancer.LoadBalancerName)
	if loadBalancerName == "" {
		return fi.RequiredField("LoadBalancer.LoadBalancerName")
	}
	if e.AutoscalingGroup != nil {
		balancers := []*aws.LoadBalancer{
			{
				Name: spotinstsdk.String(loadBalancerName),
				Type: spotinstsdk.String("CLASSIC"),
			},
		}
		balancersConfig := new(aws.LoadBalancersConfig)
		balancersConfig.SetLoadBalancers(balancers)

		launchSpec := new(aws.LaunchSpecification)
		launchSpec.SetLoadBalancersConfig(balancersConfig)

		compute := new(aws.Compute)
		compute.SetLaunchSpecification(launchSpec)

		update := new(aws.Group)
		update.SetId(e.AutoscalingGroup.ID)
		update.SetCompute(compute)

		input := &aws.UpdateGroupInput{
			Group: update,
		}

		glog.V(2).Infof("Attaching ELB %q to group %q", loadBalancerName, fi.StringValue(e.AutoscalingGroup.ID))
		_, err := t.Cloud.Service.CloudProviderAWS().Update(context.Background(), input)
		if err != nil {
			return fmt.Errorf("error attaching ELB to group: %v", err)
		}
	}
	return nil
}
