package server

import (
	"context"
	"github.com/dop251/goja"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/heroiclabs/nakama-common/api"
	"go.uber.org/zap"
	"time"
)

type runtimeJavascriptNakamaModule struct {
	logger *zap.Logger
	eventFn RuntimeEventCustomFunction
}

func NewRuntimeJavascriptNakamaModule(logger *zap.Logger, eventFn RuntimeEventCustomFunction) *runtimeJavascriptNakamaModule {
	return &runtimeJavascriptNakamaModule{
		logger: logger,
		eventFn: eventFn,
	}
}

func (n *runtimeJavascriptNakamaModule) Constructor(r *goja.Runtime) func(goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {
		for fnName, fn := range n.mappings(r) {
			call.This.Set(fnName, fn)
		}
		freeze(call.This)

		return nil
	}
}

func (n *runtimeJavascriptNakamaModule) mappings(r *goja.Runtime) map[string]func(goja.FunctionCall) goja.Value {
	return map[string]func(goja.FunctionCall) goja.Value {
		"event": n.event(r),
	}
}

func (n *runtimeJavascriptNakamaModule) event(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		eventName := validateString(r, f.Argument(0))
		properties := validateStringMap(r, f.Argument(1))
		ts := &timestamp.Timestamp{}
		if f.Argument(2) != goja.Undefined() {
			int := validateInt(r, f.Argument(2))
			ts.Seconds = int64(int)
		} else {
			ts.Seconds = time.Now().Unix()
		}
		external := false
		if f.Argument(3) != goja.Undefined() {
			external = validateBool(r, f.Argument(3))
		}

		if n.eventFn != nil {
			n.eventFn(context.Background(), &api.Event{
				Name:                 eventName,
				Properties:           properties,
				Timestamp:            ts,
				External:             external,
			})
		}

		return nil
	}
}

func validateString(r *goja.Runtime, v goja.Value) string {
	s, ok := v.Export().(string)
	if !ok {
		panic(r.ToValue("Invalid argument - string expected."))
	}
	return s
}

func validateStringMap(r *goja.Runtime, v goja.Value) map[string]string {
	m, ok := v.Export().(map[string]interface{})
	if !ok {
		panic(r.ToValue("Invalid argument - object of string keys and values expected."))
	}

	res := make(map[string]string)
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			panic(r.ToValue("Invalid object value - string expected."))
		}
		res[k] = s
	}
	return res
}

func validateInt(r *goja.Runtime, v goja.Value) int {
	i, ok := v.Export().(int)
	if !ok {
		panic(r.ToValue("Invalid argument - int expected."))
	}
	return i
}

func validateBool(r *goja.Runtime, v goja.Value) bool {
	b, ok := v.Export().(bool)
	if !ok {
		panic(r.ToValue("Invalid argument - boolean expected."))
	}
	return b
}
