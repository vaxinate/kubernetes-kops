/*
Copyright 2017 The Kubernetes Authors.

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

package spotinst

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/blang/semver"
	"github.com/golang/glog"
	"github.com/spotinst/spotinst-sdk-go/service/elastigroup"
	"github.com/spotinst/spotinst-sdk-go/service/elastigroup/providers/aws"
	"github.com/spotinst/spotinst-sdk-go/spotinst"
	"github.com/spotinst/spotinst-sdk-go/spotinst/credentials"
	"github.com/spotinst/spotinst-sdk-go/spotinst/session"
	"k8s.io/api/core/v1"
	kopsv "k8s.io/kops"
	"k8s.io/kops/pkg/apis/kops"
	"k8s.io/kops/pkg/apis/kops/util"
	"k8s.io/kops/pkg/cloudinstances"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/cloudup/awsup"
	"k8s.io/kops/upup/pkg/fi/cloudup/gce"
	"k8s.io/kubernetes/federation/pkg/dnsprovider"
)

// SpotinstCloud represents a Spotinst cloud instance.
type SpotinstCloud struct {
	Cloud   fi.Cloud
	Service elastigroup.Service
}

var _ fi.Cloud = &SpotinstCloud{}

// NewSpotinstCloud returns SpotinstCloud instance for given ClusterSpec.
func NewSpotinstCloud(cluster *kops.Cluster) (*SpotinstCloud, error) {
	glog.V(2).Info("Creating Spotinst cloud")

	var cloud fi.Cloud
	var cloudProviderID kops.CloudProviderID
	var err error

	if cluster.Spec.CloudConfig.SpotinstCloudProvider == nil {
		for _, subnet := range cluster.Spec.Subnets {
			id, known := fi.GuessCloudForZone(subnet.Zone)
			if known {
				glog.V(2).Infof("Inferred cloud=%s from zone %q", id, subnet.Zone)
				cloudProviderID = kops.CloudProviderID(id)
				break
			}
		}
		if cloudProviderID == "" {
			return nil, fmt.Errorf("spotinst: unable to infer cloud provider from zones")
		}
	} else {
		cloudProviderID = kops.CloudProviderID(*cluster.Spec.CloudConfig.SpotinstCloudProvider)
	}

	switch cloudProviderID {
	case kops.CloudProviderAWS, kops.CloudProviderGCE:
		glog.V(2).Infof("Cloud provider detected: %s", cloudProviderID)
		cloud, err = buildCloud(cloudProviderID, cluster)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("spotinst: unknown cloud provider: %s", cloudProviderID)
	}

	creds := credentials.NewChainCredentials(
		new(credentials.EnvProvider),
		new(credentials.FileProvider),
	)
	if _, err := creds.Get(); err != nil {
		fmt.Errorf("spotinst: unable to find Spotinst credentials: %s", err)
	}

	config := spotinst.DefaultConfig()
	config.WithCredentials(creds)
	config.WithUserAgent("Kubernetes-Kops/" + kopsv.Version)
	config.WithLogger(newStdLogger())

	return &SpotinstCloud{
		Cloud:   cloud,
		Service: elastigroup.New(session.New(config)),
	}, nil
}

func (c *SpotinstCloud) ProviderID() kops.CloudProviderID {
	return kops.CloudProviderSpotinst
}

func (c *SpotinstCloud) DNS() (dnsprovider.Interface, error) {
	return c.Cloud.DNS()
}

func (c *SpotinstCloud) FindVPCInfo(id string) (*fi.VPCInfo, error) {
	return c.Cloud.FindVPCInfo(id)
}

func (c *SpotinstCloud) DeleteInstance(instance *cloudinstances.CloudInstanceGroupMember) error {
	nodeName := instance.Node.Name
	instanceID := instance.ID
	groupID := instance.CloudInstanceGroup.Raw.(*aws.Group).ID

	glog.V(2).Infof("Stopping instance %q, node %q in group %q", instanceID, nodeName, groupID)
	input := &aws.DetachGroupInput{
		GroupID:                       groupID,
		InstanceIDs:                   []string{instanceID},
		ShouldDecrementTargetCapacity: fi.Bool(false),
		ShouldTerminateInstances:      fi.Bool(true),
	}
	if _, err := c.Service.CloudProviderAWS().Detach(context.Background(), input); err != nil {
		if nodeName != "" {
			return fmt.Errorf("error deleting instance %q, node %q: %v", instanceID, nodeName, err)
		}
		return fmt.Errorf("error deleting instance %q: %v", instanceID, err)
	}

	return nil
}

func (c *SpotinstCloud) DeleteGroup(group *cloudinstances.CloudInstanceGroup) error {
	groupID := fi.StringValue(group.Raw.(*aws.Group).ID)

	glog.V(2).Infof("Deleting group %q", groupID)
	input := &aws.DeleteGroupInput{
		GroupID: fi.String(groupID),
	}
	_, err := c.Service.CloudProviderAWS().Delete(context.Background(), input)
	if err != nil {
		return fmt.Errorf("error deleting group %q: %v", groupID, err)
	}

	return nil
}

func (c *SpotinstCloud) GetCloudGroups(cluster *kops.Cluster, instancegroups []*kops.InstanceGroup, warnUnmatched bool, nodes []v1.Node) (map[string]*cloudinstances.CloudInstanceGroup, error) {
	groups := make(map[string]*cloudinstances.CloudInstanceGroup)
	nodeMap := cloudinstances.GetNodeMap(nodes)

	var filters []string
	for _, ig := range instancegroups {
		if name := getGroupNameByRole(cluster, ig); name != "" {
			filters = append(filters, name)
		}
	}

	resources, err := c.ListResources(filters)
	if err != nil {
		return nil, fmt.Errorf("unable to find groups: %v", err)
	}

	for _, resource := range resources {
		group, ok := resource.Raw.(*aws.Group)
		if !ok {
			continue
		}
		var instancegroup *kops.InstanceGroup
		for _, ig := range instancegroups {
			name := getGroupNameByRole(cluster, ig)
			if name == "" {
				continue
			}
			if name == resource.Name {
				if instancegroup != nil {
					return nil, fmt.Errorf("found multiple instance groups matching group %q", name)
				}
				instancegroup = ig
			}
		}
		if instancegroup == nil {
			if warnUnmatched {
				glog.Warningf("Found group with no corresponding instance group %q", resource.Name)
			}
			continue
		}
		input := &aws.StatusGroupInput{
			GroupID: group.ID,
		}
		output, err := c.Service.CloudProviderAWS().Status(context.Background(), input)
		if err != nil {
			return nil, err
		}
		ig, err := buildInstanceGroup(instancegroup, group, output.Instances, nodeMap)
		if err != nil {
			return nil, fmt.Errorf("failed to build instance group: %v", err)
		}
		groups[instancegroup.ObjectMeta.Name] = ig
	}

	return groups, nil
}

func (c *SpotinstCloud) CloudProvider() fi.Cloud {
	return c.Cloud
}

// Default machine types for various types of instance group machine.
const (
	defaultMasterMachineTypeGCE = "n1-standard-1"
	defaultMasterMachineTypeAWS = "m3.medium"

	defaultNodeMachineTypeGCE = "n1-standard-2"
	defaultNodeMachineTypeAWS = "m3.medium"

	defaultBastionMachineTypeGCE = "f1-micro"
	defaultBastionMachineTypeAWS = "m3.medium"
)

func (c *SpotinstCloud) DefaultMachineType(cluster *kops.Cluster, ig *kops.InstanceGroup) (string, error) {
	var machineType string

	switch ig.Spec.Role {
	case kops.InstanceGroupRoleMaster:
		switch c.Cloud.ProviderID() {
		case kops.CloudProviderAWS:
			machineType = defaultMasterMachineTypeAWS
		case kops.CloudProviderGCE:
			machineType = defaultMasterMachineTypeGCE
		}

	case kops.InstanceGroupRoleNode:
		switch c.Cloud.ProviderID() {
		case kops.CloudProviderAWS:
			machineType = defaultNodeMachineTypeAWS
		case kops.CloudProviderGCE:
			machineType = defaultNodeMachineTypeGCE
		}

	case kops.InstanceGroupRoleBastion:
		switch c.Cloud.ProviderID() {
		case kops.CloudProviderAWS:
			machineType = defaultBastionMachineTypeAWS
		case kops.CloudProviderGCE:
			machineType = defaultBastionMachineTypeGCE
		}

	default:
		return "", fmt.Errorf("spotinst: unknown instance group role: %s", ig.Spec.Role)
	}

	return machineType, nil
}

func (c *SpotinstCloud) DefaultImage(cluster *kops.Cluster, channel *kops.Channel) string {
	var image string

	if channel != nil {
		var kubernetesVersion *semver.Version
		if cluster.Spec.KubernetesVersion != "" {
			var err error
			kubernetesVersion, err = util.ParseKubernetesVersion(cluster.Spec.KubernetesVersion)
			if err != nil {
				glog.Warningf("spotinst: cannot parse KubernetesVersion %q in cluster", cluster.Spec.KubernetesVersion)
			}
		}
		if kubernetesVersion != nil {
			imageSpec := channel.FindImage(c.Cloud.ProviderID(), *kubernetesVersion)
			if imageSpec != nil {
				image = imageSpec.Name
			}
		}
	}

	return image
}

func (c *SpotinstCloud) ValidateSSHPublicKeys(cluster *kops.Cluster, keys [][]byte) error {
	switch c.Cloud.ProviderID() {
	case kops.CloudProviderAWS:
		if len(keys) == 0 {
			return fmt.Errorf("spotinst: SSH public key must be specified "+
				"when running with Spotinst (create with `kops create secret --"+
				"name %s sshpublickey admin -i ~/.ssh/id_rsa.pub`)",
				cluster.ObjectMeta.Name)
		}
		if len(keys) != 1 {
			return fmt.Errorf("spotinst: exactly one 'admin' SSH public key " +
				"can be specified when running with Spotinst; please delete a key " +
				"using `kops delete secret`")
		}
	case kops.CloudProviderGCE:
		return nil
	}
	return nil
}

func (c *SpotinstCloud) Region() string {
	var region string

	switch c.Cloud.ProviderID() {
	case kops.CloudProviderAWS:
		cloud := c.Cloud.(awsup.AWSCloud)
		region = cloud.Region()
	case kops.CloudProviderGCE:
		cloud := c.Cloud.(gce.GCECloud)
		region = cloud.Region()
	}

	return region
}

func (c *SpotinstCloud) DNSProvider() string {
	var provider string

	switch c.Cloud.ProviderID() {
	case kops.CloudProviderAWS:
		provider = "aws-route53"
	case kops.CloudProviderGCE:
		provider = "google-clouddns"
	}

	return provider
}

func (c *SpotinstCloud) Tags() []string {
	tags := []string{"_spotinst"}

	switch c.Cloud.ProviderID() {
	case kops.CloudProviderAWS:
		tags = append(tags, "_aws")
	case kops.CloudProviderGCE:
		tags = append(tags, "_gce")
	}

	return tags
}

func (c *SpotinstCloud) DNSControllerArgv() []string {
	var argv []string

	switch c.Cloud.ProviderID() {
	case kops.CloudProviderAWS:
		if strings.HasPrefix(os.Getenv("AWS_REGION"), "cn-") {
			argv = append(argv, "--dns=gossip")
		} else {
			argv = append(argv, "--dns=aws-route53")
		}
	case kops.CloudProviderGCE:
		argv = append(argv, "--dns=google-clouddns")
	}

	return argv
}

const ResourceTypeGroup = "Group"

type Resource struct {
	ID   string
	Name string
	Type string
	Raw  interface{}
}

func (c *SpotinstCloud) ListResources(filters []string) ([]*Resource, error) {
	var resources []*Resource
	ctx := context.Background()

	glog.V(2).Info("Listing resources...")
	switch c.CloudProvider().ProviderID() {
	case kops.CloudProviderAWS:
		{
			out, err := c.Service.CloudProviderAWS().List(ctx, nil)
			if err != nil {
				return nil, err
			}
			for _, group := range out.Groups {
				id := spotinst.StringValue(group.ID)
				name := spotinst.StringValue(group.Name)
				for _, filter := range filters {
					if strings.Contains(name, filter) {
						glog.V(2).Infof("Discovered resource: %s (%s)", id, name)
						resource := &Resource{
							ID:   id,
							Name: name,
							Type: ResourceTypeGroup,
							Raw:  group,
						}
						resources = append(resources, resource)
					}
				}
			}
		}
	case kops.CloudProviderGCE:
		{
			// TODO(liran): Not implemented yet.
		}
	}

	return resources, nil
}

func (c *SpotinstCloud) DeleteResource(resource interface{}) error {
	ctx := context.Background()

	rs, ok := resource.(*Resource)
	if !ok {
		return fmt.Errorf("spotinst: unknown resource: %T", resource)
	}
	glog.V(2).Infof("Deleting resource: %s", rs.ID)

	switch c.CloudProvider().ProviderID() {
	case kops.CloudProviderAWS:
		{
			switch rs.Type {
			case ResourceTypeGroup:
				{
					input := &aws.DeleteGroupInput{
						GroupID: spotinst.String(rs.ID),
					}
					_, err := c.Service.CloudProviderAWS().Delete(ctx, input)
					if err != nil {
						return err
					}
				}
			}
		}
	case kops.CloudProviderGCE:
		{
			// TODO(liran): Not implemented yet.
		}
	}
	return nil
}

func (c *SpotinstCloud) FindClusterStatus(cluster *kops.Cluster) (*kops.ClusterStatus, error) {
	var status *kops.ClusterStatus
	var err error

	switch c.Cloud.ProviderID() {
	case kops.CloudProviderAWS:
		status, err = findEtcdStatusAWS(c.Cloud.(awsup.AWSCloud), cluster)
		if err != nil {
			return nil, err
		}
	case kops.CloudProviderGCE:
		status, err = findEtcdStatusGCE(c.Cloud.(gce.GCECloud), cluster)
		if err != nil {
			return nil, err
		}
	}

	return status, nil
}

func (c *SpotinstCloud) GetApiIngressStatus(cluster *kops.Cluster) ([]kops.ApiIngressStatus, error) {
	var status []kops.ApiIngressStatus
	var err error

	switch c.Cloud.ProviderID() {
	case kops.CloudProviderAWS:
		status, err = getApiIngressStatusAWS(c.Cloud.(awsup.AWSCloud), cluster)
		if err != nil {
			return nil, err
		}
	case kops.CloudProviderGCE:
		status, err = getApiIngressStatusGCE(c.Cloud.(gce.GCECloud), cluster)
		if err != nil {
			return nil, err
		}
	}

	return status, nil
}
