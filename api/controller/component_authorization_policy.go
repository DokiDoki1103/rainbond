package controller

import (
	"github.com/goodrain/rainbond/api/handler"
	ctxutil "github.com/goodrain/rainbond/api/util/ctx"
	httputil "github.com/goodrain/rainbond/util/http"
	"net/http"
)

func (t *TenantStruct) GetComponentAuthorizationPolicy(w http.ResponseWriter, r *http.Request) {
	namespace := r.FormValue("namespace")
	componentID := r.Context().Value(ctxutil.ContextKey("service_id")).(string)
	ret, err := handler.GetServiceManager().GetComponentAuthorizationPolicy(namespace, componentID)
	if err != nil {
		httputil.ReturnBcodeError(r, w, err)
		return
	}
	httputil.ReturnSuccess(r, w, ret)
}
