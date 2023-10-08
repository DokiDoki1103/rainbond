package handler

import (
	"context"
	"istio.io/client-go/pkg/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *ServiceAction) GetComponentAuthorizationPolicy(namespace, service_id string) (map[string]string, error) {
	ic, err := versioned.NewForConfig(s.config)
	if err != nil {
		return nil, err
	}
	aps, err := ic.SecurityV1().AuthorizationPolicies(namespace).List(context.Background(), metav1.ListOptions{LabelSelector: "service_id=" + service_id})
	if err != nil {
		return nil, err
	}
	apObject := make(map[string]string)
	apObject["name"] = ""
	apObject["resource_yaml"] = ""
	if len(aps.Items) > 0 {
		ap := aps.Items[0]
		apYaml, err := ObjectToJSONORYaml("yaml", ap)
		if err != nil {
			return nil, err
		}
		apObject["name"] = ap.GetName()
		apObject["resource_yaml"] = apYaml
	}
	return apObject, nil
}
