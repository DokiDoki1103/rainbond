package util

import (
	"context"
	v1 "istio.io/api/security/v1"
	"istio.io/client-go/pkg/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"strconv"
)

func UpdateAuthorizationPolicies(namespace, serviceID, operation string, port int, config *rest.Config, depSAName string) error {
	ic, err := versioned.NewForConfig(config)
	if err != nil {
		return err
	}
	aps, err := ic.SecurityV1().AuthorizationPolicies(namespace).List(context.Background(), metav1.ListOptions{LabelSelector: "service_id=" + serviceID})
	if err != nil {
		return err
	}
	if aps == nil || len(aps.Items) == 0 {
		return nil
	}
	ap := aps.Items[0]
	if ap.Spec.Rules == nil || len(ap.Spec.Rules) == 0 {
		return nil
	}
	ruleExist := false
	rules := ap.Spec.Rules
	for _, rule := range rules {
		if rule.When != nil && len(rule.When) > 0 {
			continue
		}
		if depSAName != "" {
			if rule.To != nil && len(rule.To) > 0 {
				continue
			}
			if rule.From != nil && len(rule.From) > 0 {
				ruleFrom := rule.From
				ruleExist = true
				principalExist := false
				for _, from := range ruleFrom {
					if from.Source.IpBlocks != nil && len(from.Source.IpBlocks) > 0 {
						continue
					}
					if from.Source.NotIpBlocks != nil && len(from.Source.NotIpBlocks) > 0 {
						continue
					}
					if from.Source.Namespaces != nil && len(from.Source.Namespaces) > 0 {
						continue
					}
					if from.Source.NotNamespaces != nil && len(from.Source.NotNamespaces) > 0 {
						continue
					}
					if from.Source.RemoteIpBlocks != nil && len(from.Source.RemoteIpBlocks) > 0 {
						continue
					}
					if from.Source.NotRemoteIpBlocks != nil && len(from.Source.NotRemoteIpBlocks) > 0 {
						continue
					}
					if from.Source.RequestPrincipals != nil && len(from.Source.RequestPrincipals) > 0 {
						continue
					}
					if from.Source.NotRequestPrincipals != nil && len(from.Source.NotRequestPrincipals) > 0 {
						continue
					}
					if from.Source.NotPrincipals != nil && len(from.Source.NotPrincipals) > 0 {
						continue
					}
					if from.Source.Principals != nil && len(from.Source.Principals) > 0 {
						principalExist = true
						if operation == "open" {
							from.Source.Principals = append(from.Source.Principals, depSAName)
							continue
						}
						for i := 0; i < len(from.Source.Principals); i++ {
							p := from.Source.Principals[i]
							if p == depSAName {
								from.Source.Principals = append(from.Source.Principals[:i], from.Source.Principals[i+1:]...)
								i--
							}
						}
						if len(from.Source.Principals) == 0 {
							from.Source = nil
						}
					}
				}
				if !principalExist && operation == "open" {
					rule.From = append(rule.From, &v1.Rule_From{Source: &v1.Source{Principals: []string{depSAName}}})
				}
			}
		}
		if port != 0 {
			if rule.From != nil && len(rule.From) > 0 {
				continue
			}
			if rule.To != nil && len(rule.To) > 0 {
				ruleTo := rule.To
				ruleExist = true
				toPortExist := false
				for _, to := range ruleTo {
					if to.Operation.Hosts != nil && len(to.Operation.Hosts) > 0 {
						continue
					}
					if to.Operation.NotHosts != nil && len(to.Operation.NotHosts) > 0 {
						continue
					}
					if to.Operation.Paths != nil && len(to.Operation.Paths) > 0 {
						continue
					}
					if to.Operation.NotPaths != nil && len(to.Operation.NotPaths) > 0 {
						continue
					}
					if to.Operation.Methods != nil && len(to.Operation.Methods) > 0 {
						continue
					}
					if to.Operation.NotMethods != nil && len(to.Operation.NotMethods) > 0 {
						continue
					}
					if to.Operation.NotPorts != nil && len(to.Operation.NotPorts) > 0 {
						continue
					}
					if to.Operation.Ports != nil && len(to.Operation.Ports) > 0 {
						toPortExist = true
						if operation == "open" {
							to.Operation.Ports = append(to.Operation.Ports, strconv.Itoa(port))
							continue
						}
						for i := 0; i < len(to.Operation.Ports); i++ {
							p := to.Operation.Ports[i]
							if p == strconv.Itoa(port) {
								to.Operation.Ports = append(to.Operation.Ports[:i], to.Operation.Ports[i+1:]...)
								i--
							}
						}
						if len(to.Operation.Ports) == 0 {
							to.Operation = nil
						}
					}
				}
				if !toPortExist && operation == "open" {
					rule.To = append(rule.To, &v1.Rule_To{Operation: &v1.Operation{Ports: []string{strconv.Itoa(port)}}})
				}
			}
		}
	}
	if !ruleExist && port != 0 && operation == "open" {
		rules = append(rules, &v1.Rule{
			To: []*v1.Rule_To{{Operation: &v1.Operation{Ports: []string{strconv.Itoa(port)}}}},
		})
	}
	if !ruleExist && depSAName != "" && operation == "open" {
		rules = append(rules, &v1.Rule{
			From: []*v1.Rule_From{{Source: &v1.Source{Principals: []string{depSAName}}}},
		})
	}
	_, err = ic.SecurityV1().AuthorizationPolicies(namespace).Update(context.Background(), ap, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}
