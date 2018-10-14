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
	"github.com/golang/glog"
	"k8s.io/kops/pkg/apis/kops"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/cloudup/awsup"
)

// NewCloud returns Cloud instance for given ClusterSpec.
func NewCloud(cluster *kops.Cluster) (fi.Cloud, error) {
	glog.V(2).Info("Creating Spotinst cloud")
	cloudProviderID := kops.CloudProviderID(GuessCloudFromClusterSpec(&cluster.Spec))

	svc, err := NewService(cloudProviderID)
	if err != nil {
		return nil, err
	}

	return newCloud(cloudProviderID, svc, cluster)
}

func newCloud(cloudProvider kops.CloudProviderID, svc Service, cluster *kops.Cluster) (fi.Cloud, error) {
	var cloud fi.Cloud
	var err error

	switch cloudProvider {
	case kops.CloudProviderAWS:
		cloud, err = newAWSCloud(svc, cluster)
	}

	return cloud, err
}

func newAWSCloud(svc Service, cluster *kops.Cluster) (fi.Cloud, error) {
	region, err := awsup.FindRegion(cluster)
	if err != nil {
		return nil, err
	}

	tags := map[string]string{
		awsup.TagClusterName: cluster.ObjectMeta.Name,
	}

	cloud, err := awsup.NewAWSCloud(region, tags)
	if err != nil {
		return nil, err
	}

	return &awsCloud{
		AWSCloud: cloud.(awsup.AWSCloud),
		svc:      svc,
	}, nil
}
