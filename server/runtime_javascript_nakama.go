package server

import (
	"github.com/dop251/goja"
	"go.uber.org/zap"
)

type runtimeJavascriptNakamaModule struct {
	logger *zap.Logger
}

func NewRuntimeJavascriptNakamaModule(logger *zap.Logger) *runtimeJavascriptNakamaModule {
	return &runtimeJavascriptNakamaModule{
		logger: logger,
	}
}

func (n *runtimeJavascriptNakamaModule) Constructor(r *goja.Runtime) func(goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {
		for fnName, fn := range n.mappings() {
			call.This.Set(fnName, fn)
		}
		freeze(call.This)

		return nil
	}
}

func (n *runtimeJavascriptNakamaModule) mappings() map[string]func(goja.FunctionCall) goja.Value {
	return map[string]func(goja.FunctionCall) goja.Value {
		"matchGet": n.matchGet,
		"matchCreate": n.matchCreate,
	}
}

func (n *runtimeJavascriptNakamaModule) matchGet(f goja.FunctionCall) goja.Value {
	// TODO matchGet
	return goja.Null()
}

func (n *runtimeJavascriptNakamaModule) matchCreate(f goja.FunctionCall) goja.Value {
	// TODO matchCreate
	return goja.Null()
}
