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
	"k8s.io/kops/pkg/apis/kops"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/cloudup/awsup"
	"k8s.io/kops/upup/pkg/fi/cloudup/gce"
)

// SpotinstAPITarget represents target for Spotinst.
type SpotinstAPITarget struct {
	Cloud  *SpotinstCloud
	Target fi.Target
}

var _ fi.Target = &SpotinstAPITarget{}

// NewSpotinstAPITarget returns SpotinstAPITarget instance for Spotinst cloud provider.
func NewSpotinstAPITarget(cloud *SpotinstCloud) *SpotinstAPITarget {
	var target fi.Target

	switch cloud.CloudProvider().ProviderID() {
	case kops.CloudProviderAWS:
		target = awsup.NewAWSAPITarget(cloud.Cloud.(awsup.AWSCloud))
	case kops.CloudProviderGCE:
		target = gce.NewGCEAPITarget(cloud.Cloud.(gce.GCECloud))
	}

	return &SpotinstAPITarget{
		Cloud:  cloud,
		Target: target,
	}
}

// Finish is no-op for Spotinst cloud.
func (t *SpotinstAPITarget) Finish(taskMap map[string]fi.Task) error {
	return t.Target.Finish(taskMap)
}

// ProcessDeletions is no-op for Spotinst cloud.
func (t *SpotinstAPITarget) ProcessDeletions() bool {
	return t.Target.ProcessDeletions()
}
