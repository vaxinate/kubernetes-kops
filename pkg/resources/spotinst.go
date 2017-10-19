package resources

import (
	"fmt"

	"k8s.io/kops/pkg/apis/kops"
	"k8s.io/kops/pkg/resources/tracker"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/cloudup/spotinst"
)

type clusterDiscoverySpotinst struct {
	cloud       *spotinst.SpotinstCloud
	clusterName string
}

type spotinstListFn func() ([]*tracker.Resource, error)

func (c *ClusterResources) listResourcesSpotinst() (map[string]*tracker.Resource, error) {
	spotinstCloud := c.Cloud.(*spotinst.SpotinstCloud)
	c.Cloud = spotinstCloud.CloudProvider()
	cloudProviderID := c.Cloud.ProviderID()

	var err error
	var resources map[string]*tracker.Resource

	switch cloudProviderID {
	case kops.CloudProviderAWS:
		resources, err = c.listResourcesAWS()
	case kops.CloudProviderGCE:
		resources, err = c.listResourcesGCE()
	default:
		return nil, fmt.Errorf("spotinst: unknown cloud provider: %s", cloudProviderID)
	}
	if err != nil {
		return nil, fmt.Errorf("spotinst: failed to list %s resources: %v", cloudProviderID, err)
	}

	d := &clusterDiscoverySpotinst{
		cloud:       spotinstCloud,
		clusterName: c.ClusterName,
	}

	listFunctions := []spotinstListFn{
		d.listResources,
	}

	for _, fn := range listFunctions {
		trackers, err := fn()
		if err != nil {
			return nil, err
		}
		for _, t := range trackers {
			resources[t.Type+":"+t.ID] = t
		}
	}

	for k, t := range resources {
		if t.Done {
			delete(resources, k)
		}
	}

	return resources, nil
}

func (d *clusterDiscoverySpotinst) listResources() ([]*tracker.Resource, error) {
	filterForMasterGroup := "masters." + d.clusterName
	filterForNodeGroup := "nodes." + d.clusterName

	resources, err := d.cloud.ListResources([]string{filterForMasterGroup, filterForNodeGroup})
	if err != nil {
		return nil, fmt.Errorf("spotinst: failed to list resources: %v", err)
	}

	var trackers []*tracker.Resource
	for _, resource := range resources {
		tracker := &tracker.Resource{
			ID:      resource.ID,
			Name:    resource.Name,
			Type:    resource.Type,
			Deleter: d.deleteResource,
			Dumper:  d.dumpResource,
			Obj:     resource,
		}
		trackers = append(trackers, tracker)
	}

	return trackers, nil
}

func (d *clusterDiscoverySpotinst) deleteResource(cloud fi.Cloud, r *tracker.Resource) error {
	return d.cloud.DeleteResource(r.Obj)
}

func (d *clusterDiscoverySpotinst) dumpResource(r *tracker.Resource) (interface{}, error) {
	data := make(map[string]interface{})
	data["id"] = r.ID
	data["type"] = r.Type
	data["raw"] = r.Obj
	return data, nil
}
