package server

import (
	"database/sql"
	"github.com/dop251/goja"
	"go.uber.org/zap"
)

type RuntimeJavascriptNakamaModule struct {
	logger *zap.Logger
	db *sql.DB
}

func NewRuntimeJavascriptNakamaModule(logger *zap.Logger, db *sql.DB) *RuntimeJavascriptNakamaModule {
	return &RuntimeJavascriptNakamaModule{
		logger: logger,
		db: db,
	}
}

func (n *RuntimeJavascriptNakamaModule) Constructor() func(goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {
		for fnName, fn := range n.mappings() {
			call.This.Set(fnName, fn)
		}

		return nil // Returns the object itself
	}
}

func (n *RuntimeJavascriptNakamaModule) mappings() map[string]func(goja.FunctionCall) goja.Value {
	return map[string]func(goja.FunctionCall) goja.Value {
		"matchGet": n.matchGet,
		"matchCreate": n.matchCreate,
		"logInfo": n.logInfo,
		"logError": n.logError,
	}
}

func (n *RuntimeJavascriptNakamaModule) matchGet(f goja.FunctionCall) goja.Value {
	// TODO matchGet
	return goja.Null()
}

func (n *RuntimeJavascriptNakamaModule) logInfo(f goja.FunctionCall) goja.Value {
	// TODO how to handle errors?
	s, ok := f.Arguments[0].ToString().Export().(string)
	if !ok {
		panic("couldn't get string")
	}
	n.logger.Info(s)
	return goja.Null()
}

func (n *RuntimeJavascriptNakamaModule) logError(f goja.FunctionCall) goja.Value {
	s, ok := f.Arguments[0].ToString().Export().(string)
	if !ok {
		panic("couldn't get string")
	}
	n.logger.Error(s)
	return goja.Null()
}

func (n *RuntimeJavascriptNakamaModule) matchCreate(f goja.FunctionCall) goja.Value {
	// TODO matchCreate
	return goja.Null()
}
