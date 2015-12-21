package auth

import (
	"fmt"
	//"io/ioutil"
	"net/http"
	//"sync"
	//"golang.org/x/net/context"

	//"github.com/gorilla/mux"
	"github.com/docker/distribution/registry/api/v2"
	"github.com/docker/distribution/registry/auth"
	"github.com/docker/distribution/registry/handlers"
	"gopkg.in/macaron.v1"

	"github.com/containerops/dockyard/middleware"
	"github.com/containerops/wrench/setting"
	//_ "github.com/containerops/dockyard/middleware/auth/hwtoken"
	//ctxu "github.com/docker/distribution/context"
)

type authorization struct{}

var Controller auth.AccessController
var Ctx macaron.Context

func init() {
	middleware.Register("hwtoken", middleware.HandlerInterface(&authorization{}))
}

func (a *authorization) InitFunc() error {
	var err error

	name := setting.JSONConfCtx.Authors.Name()
	Controller, err = auth.GetAccessController(name, setting.JSONConfCtx.Authors[name])
	if err != nil {
		return fmt.Errorf("unable to configure authorization (%s): %v", name, err.Error())
	}

	return nil
}

func (a *authorization) Handler(ctx *macaron.Context) {
	if err := authorized(ctx); err != nil {
		ctx.Resp.WriteHeader(http.StatusUnauthorized)
	}
}

/*
func Authorized(ctx *macaron.Context) error {

	//ctx := getcontext(w, r)
	if err := authorized(ctx); err != nil {
		//ctxu.GetLogger(context).Warnf("error authorizing context: %v", err)
		return err
	}

	return nil
}
*/

func authorized(ctx *macaron.Context) error {
	//ctxu.GetLogger(context).Debug("authorizing request")
	//repo := getName(context)
	var repo string

	Ctx = *ctx
	w := ctx.Resp
	r := ctx.Req.Request

	namespace := ctx.Params(":namespace")
	repository := ctx.Params(":repository")
	if namespace == "" || repository == "" {
		repo = ""
	} else {
		repo = fmt.Sprintf("%v/%v", namespace, repository)
	}

	var accessRecords []auth.Access

	if repo != "" {
		accessRecords = appendAccessRecords(accessRecords, r.Method, repo)
	} else {
		if nameRequired(r) {
			//if repository == "" {
			return fmt.Errorf("forbidden: no repository name")
		}
		accessRecords = appendCatalogAccessRecord(accessRecords, r)
	}

	app := new(handlers.App)
	_, err := Controller.Authorized(app.Context, accessRecords...)
	if err != nil {
		switch err := err.(type) {
		case auth.Challenge:
			err.SetHeaders(w)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}

		return err
	}

	//context.Context = ctx
	return nil
}

/*
func getName(ctx context.Context) (name string) {
	return ctxu.GetStringValue(ctx, "vars.name")
}
*/

func nameRequired(r *http.Request) bool {
	/*
		route := mux.CurrentRoute(r)
		routeName := route.GetName()
		return route == nil || (routeName != v2.RouteNameBase && routeName != v2.RouteNameCatalog)
	*/
	return false
}

func appendAccessRecords(records []auth.Access, method string, repo string) []auth.Access {
	resource := auth.Resource{
		Type: "repository",
		Name: repo,
	}

	switch method {
	case "GET", "HEAD":
		records = append(records,
			auth.Access{
				Resource: resource,
				Action:   "pull",
			})
	case "POST", "PUT", "PATCH":
		records = append(records,
			auth.Access{
				Resource: resource,
				Action:   "pull",
			},
			auth.Access{
				Resource: resource,
				Action:   "push",
			})
	case "DELETE":
		// DELETE access requires full admin rights, which is represented
		// as "*". This may not be ideal.
		records = append(records,
			auth.Access{
				Resource: resource,
				Action:   "*",
			})
	}
	return records
}

func appendCatalogAccessRecord(accessRecords []auth.Access, r *http.Request) []auth.Access {
	//route := mux.CurrentRoute(r)
	//routeName := route.GetName()
	routeName := "base"
	if routeName == v2.RouteNameCatalog {
		resource := auth.Resource{
			Type: "registry",
			Name: "catalog",
		}

		accessRecords = append(accessRecords,
			auth.Access{
				Resource: resource,
				Action:   "*",
			})
	}
	return accessRecords
}

/*
func getcontext(w http.ResponseWriter, r *http.Request) *handlers.Context {
	app := new(handlers.App)

	ctx := newContextManager().context(app, w, r)
	ctx = ctxu.WithVars(ctx, r)
	ctx = ctxu.WithLogger(ctx, ctxu.GetLogger(ctx,
		"vars.name",
		"vars.reference",
		"vars.digest",
		"vars.uuid"))

	context := &handlers.Context{
		App:     app,
		Context: ctx,
		//urlBuilder: v2.NewURLBuilderFromRequest(r),
	}

	return context
}

type contextManager struct {
	contexts map[*http.Request]context.Context
	mu       sync.Mutex
}

func newContextManager() *contextManager {
	return &contextManager{
		contexts: make(map[*http.Request]context.Context),
	}
}

// context either returns a new context or looks it up in the manager.
func (cm *contextManager) context(parent context.Context, w http.ResponseWriter, r *http.Request) context.Context {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	ctx, ok := cm.contexts[r]
	if ok {
		return ctx
	}

	if parent == nil {
		parent = ctxu.Background()
	}

	ctx = ctxu.WithRequest(parent, r)
	ctx, w = ctxu.WithResponseWriter(ctx, w)
	ctx = ctxu.WithLogger(ctx, ctxu.GetRequestLogger(ctx))
	cm.contexts[r] = ctx

	return ctx
}
*/
