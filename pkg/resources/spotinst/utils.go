/*
Copyright 2018 The Kubernetes Authors.

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
)

func GuessCloudFromClusterSpec(spec *kops.ClusterSpec) kops.CloudProviderID {
	var cloudProviderID kops.CloudProviderID

	for _, subnet := range spec.Subnets {
		id, known := fi.GuessCloudForZone(subnet.Zone)
		if known {
			glog.V(2).Infof("Inferred cloud=%s from zone %q", id, subnet.Zone)
			cloudProviderID = kops.CloudProviderID(id)
			break
		}
	}

	return cloudProviderID
}
