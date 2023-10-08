package handler

import (
	"context"
	"fmt"
	"github.com/goodrain/rainbond/api/model"
	"github.com/goodrain/rainbond/db"
	dbmodel "github.com/goodrain/rainbond/db/model"
	"github.com/sirupsen/logrus"
	v1 "istio.io/api/security/v1"
	"istio.io/api/security/v1beta1"
	typev1beta1 "istio.io/api/type/v1beta1"
	pkgv1 "istio.io/client-go/pkg/apis/security/v1"
	pkgv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	versionedclient "istio.io/client-go/pkg/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	k8serror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (a *ApplicationAction) GetAppPeerAuthentications(ctx context.Context, namespace, name string) (string, error) {
	ic, err := versionedclient.NewForConfig(a.config)
	if err != nil {
		return "close", err
	}
	_, err = ic.SecurityV1beta1().PeerAuthentications(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil && !k8serror.IsNotFound(err) {
		return "close", err
	}
	if k8serror.IsNotFound(err) {
		return "close", nil
	}
	return "open", nil
}

func (a *ApplicationAction) UpdateAppPeerAuthentications(ctx context.Context, pa model.AppPeerAuthentications) (*dbmodel.K8sResource, error) {
	ic, err := versionedclient.NewForConfig(a.config)
	if err != nil {
		return nil, err
	}
	labels := make(map[string]string)
	labels["app_id"] = pa.AppID
	if pa.OperateMode {
		peerAuthentication := &pkgv1beta1.PeerAuthentication{
			TypeMeta: metav1.TypeMeta{
				Kind:       model.PeerAuthenticationKind,
				APIVersion: model.PeerAuthenticationAPIVERSION,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:   pa.Name,
				Labels: labels,
			},
			Spec: v1beta1.PeerAuthentication{
				Selector: &typev1beta1.WorkloadSelector{
					MatchLabels: labels,
				},
				Mtls: &v1beta1.PeerAuthentication_MutualTLS{
					Mode: v1beta1.PeerAuthentication_MutualTLS_STRICT,
				},
			},
		}
		paResource, err := ic.SecurityV1beta1().PeerAuthentications(pa.Namespace).Create(ctx, peerAuthentication, metav1.CreateOptions{})
		if err != nil {
			return nil, err
		}
		paResource.Kind = model.PeerAuthenticationKind
		paResource.APIVersion = model.PeerAuthenticationAPIVERSION
		paResourceYaml, err := ObjectToJSONORYaml("yaml", &paResource)
		if err != nil {
			logrus.Errorf("app PeerAuthentication  object to yaml failure: %v", err)
			return nil, err
		}
		k8sResource := []*dbmodel.K8sResource{{
			AppID:         pa.AppID,
			Name:          pa.Name,
			Kind:          model.PeerAuthenticationKind,
			Content:       paResourceYaml,
			ErrorOverview: "创建成功",
			State:         model.CreateSuccess,
		}}
		err = db.GetManager().K8sResourceDao().CreateK8sResource(k8sResource)
		if err != nil {
			logrus.Errorf("database operation app PeerAuthentication create k8s resource failure: %v", err)
			return nil, err
		}
		return k8sResource[0], nil
	}
	err = ic.SecurityV1beta1().PeerAuthentications(pa.Namespace).Delete(ctx, pa.Name, metav1.DeleteOptions{})
	if err != nil {
		return nil, err
	}
	err = db.GetManager().K8sResourceDao().DeleteK8sResource(pa.AppID, pa.Name, model.PeerAuthenticationKind)
	if err != nil && !k8serror.IsNotFound(err) {
		return nil, err
	}
	return nil, nil
}

func (a *ApplicationAction) GetAppAuthorizationPolicy(ctx context.Context, namespace, name string) (string, error) {
	ic, err := versionedclient.NewForConfig(a.config)
	if err != nil {
		return "close", err
	}
	_, err = ic.SecurityV1().AuthorizationPolicies(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil && !k8serror.IsNotFound(err) {
		return "close", err
	}
	if k8serror.IsNotFound(err) {
		return "close", nil
	}
	return "open", nil
}

func (a *ApplicationAction) UpdateAppAuthorizationPolicy(ctx context.Context, ap model.AppAuthorizationPolicy) ([]*dbmodel.K8sResource, error) {
	ic, err := versionedclient.NewForConfig(a.config)
	if err != nil {
		return nil, err
	}
	//create
	if ap.OperateMode {
		var k8sResource []*dbmodel.K8sResource
		//create serviceAccount
		saResource, err := a.createServiceAccount(ctx, ap)
		if err != nil {
			return nil, err
		}
		k8sResource = append(k8sResource, saResource...)
		//create AuthorizationPolicy
		apResource, err := a.createAuthorizationPolicies(ic, ctx, ap)
		k8sResource = append(k8sResource, apResource...)
		err = db.GetManager().K8sResourceDao().CreateK8sResource(k8sResource)
		if err != nil {
			logrus.Errorf("database operation app AuthorizationPolicy create k8s resource failure: %v", err)
			return nil, err
		}
		return k8sResource, nil
	}
	//delete
	err = ic.SecurityV1().AuthorizationPolicies(ap.Namespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: "app_id=" + ap.AppID})
	if err != nil {
		return nil, err
	}
	err = db.GetManager().K8sResourceDao().DeleteK8sResourceByKind(ap.AppID, model.AuthorizationPolicyKind)
	if err != nil && !k8serror.IsNotFound(err) {
		return nil, err
	}
	return nil, nil
}

func (a *ApplicationAction) createAuthorizationPolicies(ic *versionedclient.Clientset, ctx context.Context, ap model.AppAuthorizationPolicy) ([]*dbmodel.K8sResource, error) {
	var k8sResource []*dbmodel.K8sResource
	labels := make(map[string]string)
	labels["app_id"] = ap.AppID
	//authorizationPolicy total control
	authorizationPolicy := &pkgv1.AuthorizationPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       model.AuthorizationPolicyKind,
			APIVersion: model.AuthorizationPolicyAPIVERSION,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   ap.Name,
			Labels: labels,
		},
		Spec: v1.AuthorizationPolicy{
			Selector: &typev1beta1.WorkloadSelector{
				MatchLabels: labels,
			},
		},
	}
	apResource, err := ic.SecurityV1().AuthorizationPolicies(ap.Namespace).Create(ctx, authorizationPolicy, metav1.CreateOptions{})
	apResource.Kind = model.AuthorizationPolicyKind
	apResource.APIVersion = model.AuthorizationPolicyAPIVERSION
	apResourceYaml, err := ObjectToJSONORYaml("yaml", &apResource)
	if err != nil {
		logrus.Errorf("app AuthorizationPolicy  object to yaml failure: %v", err)
		return nil, err
	}
	k8sResource = append(k8sResource, &dbmodel.K8sResource{
		AppID:         ap.AppID,
		Name:          ap.Name,
		Kind:          model.AuthorizationPolicyKind,
		Content:       apResourceYaml,
		ErrorOverview: "创建成功",
		State:         model.CreateSuccess,
	})
	//component authorizationPolicy
	for _, componentInfo := range ap.ComponentInfos {
		componentLabels := labels
		componentLabels["service_id"] = componentInfo.ComponentID
		var rules []*v1.Rule
		var principals []string
		for _, dependentComponentSAName := range componentInfo.DependentComponentSANames {
			principals = append(principals, fmt.Sprintf("cluster.local/ns/%v/sa/%v", ap.Namespace, dependentComponentSAName))
		}
		if len(componentInfo.DependentComponentSANames) > 0 {
			rules = append(rules, &v1.Rule{
				From: []*v1.Rule_From{
					{
						Source: &v1.Source{
							Principals: principals,
						},
					},
				},
			},
			)
		}
		if len(componentInfo.PortOuter) > 0 {
			rules = append(rules, &v1.Rule{
				To: []*v1.Rule_To{
					{
						Operation: &v1.Operation{
							Ports: componentInfo.PortOuter,
						},
					},
				},
			})
		}
		authorizationPolicy := &pkgv1.AuthorizationPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       model.AuthorizationPolicyKind,
				APIVersion: model.AuthorizationPolicyAPIVERSION,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:   componentInfo.SAName,
				Labels: componentLabels,
			},
			Spec: v1.AuthorizationPolicy{
				Action: v1.AuthorizationPolicy_ALLOW,
				Selector: &typev1beta1.WorkloadSelector{
					MatchLabels: componentLabels,
				},
				Rules: rules,
			},
		}
		apResource, err := ic.SecurityV1().AuthorizationPolicies(ap.Namespace).Create(ctx, authorizationPolicy, metav1.CreateOptions{})
		apResource.Kind = model.AuthorizationPolicyKind
		apResource.APIVersion = model.AuthorizationPolicyAPIVERSION
		apResourceYaml, err := ObjectToJSONORYaml("yaml", &apResource)
		if err != nil {
			logrus.Errorf("app AuthorizationPolicy  object to yaml failure: %v", err)
			return nil, err
		}
		k8sResource = append(k8sResource, &dbmodel.K8sResource{
			AppID:         ap.AppID,
			Name:          componentInfo.SAName,
			Kind:          model.AuthorizationPolicyKind,
			Content:       apResourceYaml,
			ErrorOverview: "创建成功",
			State:         model.CreateSuccess,
		})
	}
	return k8sResource, nil
}

func (a *ApplicationAction) createServiceAccount(ctx context.Context, ap model.AppAuthorizationPolicy) ([]*dbmodel.K8sResource, error) {
	var k8sResource []*dbmodel.K8sResource
	var attributes []*dbmodel.ComponentK8sAttributes
	for _, componentInfo := range ap.ComponentInfos {
		if !componentInfo.IsCreateSA {
			continue
		}
		attributes = append(attributes, &dbmodel.ComponentK8sAttributes{
			TenantID:       ap.TenantID,
			ComponentID:    componentInfo.ComponentID,
			Name:           dbmodel.K8sAttributeNameServiceAccountName,
			SaveType:       "string",
			AttributeValue: componentInfo.SAName,
		})
		sa := corev1.ServiceAccount{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name: componentInfo.SAName,
			},
		}
		saResource, err := a.kubeClient.CoreV1().ServiceAccounts(ap.Namespace).Create(ctx, &sa, metav1.CreateOptions{})
		if err != nil {
			return nil, err
		}
		saResource.Kind = model.ServiceAccount
		saResource.APIVersion = model.APIVersionServiceAccount
		saResourceYaml, err := ObjectToJSONORYaml("yaml", &saResource)
		if err != nil {
			logrus.Errorf("app ServiceAccount object to yaml failure: %v", err)
			return nil, err
		}
		k8sResource = append(k8sResource, &dbmodel.K8sResource{
			AppID:         ap.AppID,
			Name:          componentInfo.SAName,
			Kind:          model.ServiceAccount,
			Content:       saResourceYaml,
			ErrorOverview: "创建成功",
			State:         model.CreateSuccess,
		})
	}
	err := db.GetManager().ComponentK8sAttributeDao().CreateOrUpdateAttributesInBatch(attributes)
	if err != nil {
		return nil, err
	}
	return k8sResource, nil
}
