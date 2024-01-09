package interceptors

import (
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/middleware"
	"github.com/goodrain/rainbond/pkg/component/etcd"
	"net/http"
	"runtime/debug"
	"strings"
)

// Recoverer -
func Recoverer(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rvr := recover(); rvr != nil && rvr != http.ErrAbortHandler {
				// Check if the panic is a nil pointer exception
				if isNilPointerException(rvr) {
					handleServiceUnavailable(w, r)
					return
				}

				// Handle other types of panics or re-panic
				logEntry := middleware.GetLogEntry(r)
				if logEntry != nil {
					logEntry.Panic(rvr, debug.Stack())
				} else {
					middleware.PrintPrettyStack(rvr)
				}

				w.WriteHeader(http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

// isNilPointerException Check if the panic is a nil pointer exception
func isNilPointerException(p interface{}) bool {
	if p == nil {
		return false
	}

	errMsg := fmt.Sprintf("%v", p)
	return strings.Contains(errMsg, "runtime error: invalid memory address or nil pointer dereference")
}

// handleServiceUnavailable -
func handleServiceUnavailable(w http.ResponseWriter, r *http.Request) {
	// Additional information about why etcd service is not available
	errorMessage := "部分服务不可用"

	if etcd.Default().EtcdClient == nil {
		errorMessage = "Etcd 服务不可用"
	}

	// Create a response JSON
	response := map[string]interface{}{
		"error": errorMessage,
	}

	// Convert the response to JSON
	responseJSON, err := json.Marshal(response)
	if err != nil {
		// Handle JSON marshaling error
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Set appropriate headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)

	// Write the JSON response to the client
	_, _ = w.Write(responseJSON)
}
