package web

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hellofresh/janus/pkg/api"
	"github.com/hellofresh/janus/pkg/errors"
	"github.com/hellofresh/janus/pkg/plugin"
	"github.com/hellofresh/janus/pkg/render"
	"github.com/hellofresh/janus/pkg/router"
	"go.opencensus.io/trace"
)

// APIHandler is the api rest controller
type APIHandler struct {
	configurationChan chan<- api.ConfigurationMessage
	Cfgs              *api.Configuration
}

// NewAPIHandler creates a new instance of Controller
func NewAPIHandler(cfgChan chan<- api.ConfigurationMessage) *APIHandler {
	return &APIHandler{
		configurationChan: cfgChan,
	}
}

// Get is the find all handler
func (c *APIHandler) Get() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, span := trace.StartSpan(r.Context(), "definitions.GetAll")
		defer span.End()

		if c.Cfgs.Definitions == nil {
			// id definitions list is empty - fake it with simple slice to get the empty JSON array in the output
			render.JSON(w, http.StatusOK, []int{})
			return
		}

		render.JSON(w, http.StatusOK, c.Cfgs.Definitions)
	}
}

// GetBy is the find by handler
func (c *APIHandler) GetBy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := router.URLParam(r, "name")
		_, span := trace.StartSpan(r.Context(), "definition.FindByName")
		cfg := c.findByName(name)
		span.End()

		if cfg == nil {
			errors.Handler(w, api.ErrAPIDefinitionNotFound)
			return
		}

		render.JSON(w, http.StatusOK, cfg)
	}
}

// PutBy is the update handler
func (c *APIHandler) PutBy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error

		name := router.URLParam(r, "name")
		_, span := trace.StartSpan(r.Context(), "definition.FindByName")
		cfg := c.findByName(name)
		span.End()

		if cfg == nil {
			errors.Handler(w, api.ErrAPIDefinitionNotFound)
			return
		}

		err = json.NewDecoder(r.Body).Decode(cfg)
		if err != nil {
			errors.Handler(w, err)
			return
		}

		isValid, err := cfg.Validate()
		if false == isValid && err != nil {
			errors.Handler(w, errors.New(http.StatusBadRequest, err.Error()))
			return
		}

		// Additionally validate plugin configuration
		for _, plg := range cfg.Plugins {
			isValid, err := plugin.ValidateConfig(plg.Name, plg.Config)
			if !isValid || err != nil {
				errors.Handler(w, errors.New(http.StatusBadRequest, err.Error()))
				return
			}
		}

		// avoid situation when trying to update existing definition with new path
		// that is already registered with another name
	/*	_, span = trace.StartSpan(r.Context(), "repo.FindByListenPath")
		existingCfg := c.findByListenPath(cfg.Proxy.ListenPath)
		span.End()

		if existingCfg != nil && existingCfg.Name != cfg.Name {
			errors.Handler(w, api.ErrAPIListenPathExists)
			return
		}*/

		_, span = trace.StartSpan(r.Context(), "repo.Update")
		c.configurationChan <- api.ConfigurationMessage{
			Operation:     api.UpdatedOperation,
			Configuration: cfg,
		}
		span.End()

		w.WriteHeader(http.StatusOK)
	}
}

// Post is the create handler
func (c *APIHandler) Post() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := api.NewDefinition()

		err := json.NewDecoder(r.Body).Decode(cfg)
		if nil != err {
			errors.Handler(w, err)
			return
		}

		isValid, err := cfg.Validate()
		if false == isValid && err != nil {
			errors.Handler(w, errors.New(http.StatusBadRequest, err.Error()))
			return
		}

		// Additionally validate plugin configuration
		for _, plg := range cfg.Plugins {
			isValid, err := plugin.ValidateConfig(plg.Name, plg.Config)
			if !isValid || err != nil {
				errors.Handler(w, errors.New(http.StatusBadRequest, err.Error()))
				return
			}
		}

		_, span := trace.StartSpan(r.Context(), "definition.Exists")
		exists, err := c.exists(cfg)
		span.End()

		if err != nil || exists {
			errors.Handler(w, err)
			return
		}

		_, span = trace.StartSpan(r.Context(), "repo.Add")
		c.configurationChan <- api.ConfigurationMessage{
			Operation:     api.AddedOperation,
			Configuration: cfg,
		}
		span.End()

		w.Header().Add("Location", fmt.Sprintf("/apis/%s", cfg.Name))
		w.WriteHeader(http.StatusCreated)
	}
}

// DeleteBy is the delete handler
func (c *APIHandler) DeleteBy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, span := trace.StartSpan(r.Context(), "repo.Remove")
		defer span.End()

		name := router.URLParam(r, "name")
		cfg := c.findByName(name)
		if cfg == nil {
			errors.Handler(w, api.ErrAPIDefinitionNotFound)
			return
		}

		c.configurationChan <- api.ConfigurationMessage{
			Operation:     api.RemovedOperation,
			Configuration: cfg,
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func (c *APIHandler) exists(cfg *api.Definition) (bool, error) {
	for _, storedCfg := range c.Cfgs.Definitions {
		if storedCfg.Name == cfg.Name {
			return true, api.ErrAPINameExists
		}

/*		if storedCfg.Proxy.ListenPath == cfg.Proxy.ListenPath {
			return true, api.ErrAPIListenPathExists
		}*/
	}

	return false, nil
}

func (c *APIHandler) findByName(name string) *api.Definition {
	for _, cfg := range c.Cfgs.Definitions {
		if cfg.Name == name {
			return cfg
		}
	}

	return nil
}

func (c *APIHandler) findByListenPath(listenPath string) *api.Definition {
	for _, cfg := range c.Cfgs.Definitions {
		if cfg.Proxy.ListenPath == listenPath {
			return cfg
		}
	}

	return nil
}
