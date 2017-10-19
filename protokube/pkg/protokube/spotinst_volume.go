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

package protokube

import (
	"errors"
	"net"

	"cloud.google.com/go/compute/metadata"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"k8s.io/kops/pkg/apis/kops"
)

type SpotinstVolumes struct {
	CloudProviderID kops.CloudProviderID
	Volumes         Volumes
}

func NewSpotinstVolumes() (*SpotinstVolumes, error) {
	var cloudProviderID kops.CloudProviderID
	var volumes Volumes

	// First, let's try AWS.
	if sess, err := session.NewSession(); err == nil {
		meta := ec2metadata.New(sess, aws.NewConfig())
		if _, err := meta.Region(); err == nil {
			cloudProviderID = kops.CloudProviderAWS
			awsVolumes, err := NewAWSVolumes()
			if err != nil {
				return nil, err
			}
			volumes = awsVolumes
		}
	}

	// Otherwise, try GCE.
	if cloudProviderID == "" {
		if _, err := metadata.ProjectID(); err == nil {
			cloudProviderID = kops.CloudProviderGCE
			gceVolumes, err := NewGCEVolumes()
			if err != nil {
				return nil, err
			}
			volumes = gceVolumes
		}
	}

	// Unknown cloud provider.
	if cloudProviderID == "" {
		return nil, errors.New("spotinst: unknown cloud provider")
	}

	spotinstVolumes := &SpotinstVolumes{
		CloudProviderID: cloudProviderID,
		Volumes:         volumes,
	}

	return spotinstVolumes, nil
}

func (v *SpotinstVolumes) AttachVolume(volume *Volume) error {
	return v.Volumes.AttachVolume(volume)
}

func (v *SpotinstVolumes) FindVolumes() ([]*Volume, error) {
	return v.Volumes.FindVolumes()
}

func (v *SpotinstVolumes) ClusterID() string {
	switch v.CloudProviderID {
	case kops.CloudProviderAWS:
		return v.Volumes.(*AWSVolumes).ClusterID()
	case kops.CloudProviderGCE:
		return v.Volumes.(*GCEVolumes).ClusterID()
	default:
		return ""
	}
}

func (v *SpotinstVolumes) InternalIP() net.IP {
	switch v.CloudProviderID {
	case kops.CloudProviderAWS:
		return v.Volumes.(*AWSVolumes).InternalIP()
	case kops.CloudProviderGCE:
		return v.Volumes.(*GCEVolumes).InternalIP()
	default:
		return nil
	}
}
