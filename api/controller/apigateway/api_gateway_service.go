package apigateway

import (
	v2 "github.com/apache/apisix-ingress-controller/pkg/kube/apisix/apis/config/v2"
	"github.com/go-chi/chi"
	"github.com/goodrain/rainbond/api/handler"
	"github.com/goodrain/rainbond/api/util/bcode"
	ctxutil "github.com/goodrain/rainbond/api/util/ctx"
	dbmodel "github.com/goodrain/rainbond/db/model"
	httputil "github.com/goodrain/rainbond/util/http"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"sigs.k8s.io/yaml"
)

// GetRBDService-
func (g Struct) GetRBDService(w http.ResponseWriter, r *http.Request) {
	panic("implement me")
}

// GetAPIService -
func (g Struct) GetAPIService(w http.ResponseWriter, r *http.Request) {
	tenant := r.Context().Value(ctxutil.ContextKey("tenant")).(*dbmodel.Tenants)
	resp := make(map[string]interface{})
	appID := r.URL.Query().Get("appID")
	labelSelector := ""
	if appID != "" {
		labelSelector = "app_id=" + appID
	}

	c := handler.GetAPIGatewayHandler().GetClient().ApisixV2()

	list, err := c.ApisixUpstreams(tenant.Namespace).List(r.Context(), v1.ListOptions{
		LabelSelector: labelSelector,
	})
	for _, v := range list.Items {
		resp[v.Name] = v.Spec
	}
	if err != nil {
		logrus.Errorf("get route error %s", err.Error())
		httputil.ReturnBcodeError(r, w, bcode.ErrRouteNotFound)
		return
	}
	httputil.ReturnSuccess(r, w, resp)
}

// UpdateAPIService -
func (g Struct) UpdateAPIService(w http.ResponseWriter, r *http.Request) {

}

// CreateAPIService -
func (g Struct) CreateAPIService(w http.ResponseWriter, r *http.Request) {
	tenant := r.Context().Value(ctxutil.ContextKey("tenant")).(*dbmodel.Tenants)
	var spec v2.ApisixUpstreamSpec
	if !httputil.ValidatorRequestStructAndErrorResponse(r, w, &spec, nil) {
		return
	}
	c := handler.GetAPIGatewayHandler().GetClient().ApisixV2()
	create, err := c.ApisixUpstreams(tenant.Namespace).Create(r.Context(), &v2.ApisixUpstream{
		TypeMeta: v1.TypeMeta{
			Kind:       ApisixUpstream,
			APIVersion: APIVersion,
		},
		ObjectMeta: v1.ObjectMeta{
			Name:         chi.URLParam(r, "name"),
			GenerateName: "rbd",
			Labels: map[string]string{
				"creator": "Rainbond",
				"app_id":  r.URL.Query().Get("appID"),
			},
		},
		Spec: &spec,
	}, v1.CreateOptions{})
	if err == nil {
		httputil.ReturnSuccess(r, w, marshalApisixUpstream(create))
		return
	}
	// 去更新 yaml
	get, err := c.ApisixUpstreams(tenant.Namespace).Get(r.Context(), chi.URLParam(r, "name"), v1.GetOptions{})
	if err != nil {
		logrus.Errorf("get service error %s", err.Error())
		httputil.ReturnBcodeError(r, w, bcode.ErrRouteNotFound)
		return
	}
	get.Spec = &spec
	update, err := c.ApisixUpstreams(tenant.Namespace).Update(r.Context(), get, v1.UpdateOptions{})
	if err != nil {
		logrus.Errorf("update service error %s", err.Error())
		httputil.ReturnBcodeError(r, w, bcode.ErrServiceUpdate)
		return
	}
	httputil.ReturnSuccess(r, w, marshalApisixUpstream(update))
}

func marshalApisixUpstream(r *v2.ApisixUpstream) map[string]interface{} {
	r.TypeMeta.Kind = ApisixUpstream
	r.TypeMeta.APIVersion = APIVersion
	r.ObjectMeta.ManagedFields = nil
	resp := make(map[string]interface{})
	contentBytes, _ := yaml.Marshal(r)
	resp["name"] = r.Name
	resp["kind"] = r.TypeMeta.Kind
	resp["content"] = string(contentBytes)
	return resp
}

// DeleteAPIService -
func (g Struct) DeleteAPIService(w http.ResponseWriter, r *http.Request) {
	tenant := r.Context().Value(ctxutil.ContextKey("tenant")).(*dbmodel.Tenants)
	name := chi.URLParam(r, "name")
	c := handler.GetAPIGatewayHandler().GetClient().ApisixV2()
	err := c.ApisixUpstreams(tenant.Namespace).Delete(r.Context(), name, v1.DeleteOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			httputil.ReturnSuccess(r, w, name)
		} else {
			logrus.Errorf("delete service error %s", err.Error())
			httputil.ReturnBcodeError(r, w, bcode.ErrServiceDelete)
		}
		return
	}
	httputil.ReturnSuccess(r, w, name)
}
