package server

import (
	"github.com/dop251/goja"
	"go.uber.org/zap"
	"strings"
)

const INIT_MODULE_FN_NAME = "InitModule"

type RuntimeJavascriptInitModule struct {
	Logger *zap.Logger
	Callbacks *RuntimeJavascriptCallbacks
	announceCallbackFn func(RuntimeExecutionMode, string)
}

func NewRuntimeJavascriptInitModule(logger *zap.Logger, announceCallbackFn func(RuntimeExecutionMode, string)) *RuntimeJavascriptInitModule {
	callbacks := &RuntimeJavascriptCallbacks{
		Rpc:    make(map[string]goja.Callable),
		Before: make(map[string]goja.Callable),
		After:  make(map[string]goja.Callable),
	}

	return &RuntimeJavascriptInitModule{
		Logger: logger,
		announceCallbackFn: announceCallbackFn,
		Callbacks: callbacks,
	}
}

func (im *RuntimeJavascriptInitModule) mappings(r *goja.Runtime) map[string]func(goja.FunctionCall) goja.Value {
	return map[string]func(goja.FunctionCall) goja.Value {
		"registerRpc": im.registerRpc(r),
		"registerReqBefore": im.registerReqBefore(r),
		"registerReqAfter": im.registerReqAfter(r),
		"registerRTBefore": im.registerRTBefore(r),
		"registerRTAfter": im.registerRTAfter(r),
	}
}

func (im *RuntimeJavascriptInitModule) Constructor(r *goja.Runtime) func(goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {
		for key, fn := range im.mappings(r) {
			call.This.Set(key, fn)
		}

		return nil
	}
}

func (im *RuntimeJavascriptInitModule) registerRpc(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		key, ok := f.Arguments[0].Export().(string)
		if !ok {
			panic(r.ToValue("Rpc function name must be a string."))
		}
		if key == "" {
			panic(r.ToValue("Rpc function name cannot be empty."))
		}

		fn, ok := goja.AssertFunction(f.Arguments[1])
		if !ok {
			panic(r.ToValue("Registering Rpc must be a javascript function."))
		}

		lKey := strings.ToLower(key)
		im.registerCallbackFn(RuntimeExecutionModeRPC, lKey, fn)
		im.announceCallbackFn(RuntimeExecutionModeRPC, lKey)

		return nil
	}
}

func (im *RuntimeJavascriptInitModule) registerReqBefore(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		key, ok := f.Arguments[0].Export().(string)
		if !ok {
			panic(r.ToValue("Request Before hook function name must be a string."))
		}
		if key == "" {
			panic(r.ToValue("Request Before hook function name cannot be empty."))
		}

		fn, ok := goja.AssertFunction(f.Arguments[1])
		if !ok {
			panic(r.ToValue("Registering request Before hook must be a javascript function."))
		}

		lKey := strings.ToLower(API_PREFIX + key)
		im.registerCallbackFn(RuntimeExecutionModeBefore, lKey, fn)
		im.announceCallbackFn(RuntimeExecutionModeBefore, lKey)

		return nil
	}
}

func (im *RuntimeJavascriptInitModule) registerReqAfter(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		key, ok := f.Arguments[0].Export().(string)
		if !ok {
			panic(r.ToValue("Request After hook function name must be a string."))
		}
		if key == "" {
			panic(r.ToValue("Request After hook function name cannot be empty."))
		}

		fn, ok := goja.AssertFunction(f.Arguments[1])
		if !ok {
			panic(r.ToValue("Registering request After hook must be a javascript function."))
		}

		lKey := strings.ToLower(API_PREFIX + key)
		im.registerCallbackFn(RuntimeExecutionModeAfter, lKey, fn)
		im.announceCallbackFn(RuntimeExecutionModeAfter, lKey)

		return nil
	}
}

func (im *RuntimeJavascriptInitModule) registerRTBefore(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		key, ok := f.Arguments[0].Export().(string)
		if !ok {
			panic(r.ToValue("Request realtime Before hook function name must be a string."))
		}
		if key == "" {
			panic(r.ToValue("Request realtime Before hook function name cannot be empty."))
		}

		fn, ok := goja.AssertFunction(f.Arguments[1])
		if !ok {
			panic(r.ToValue("Registering realtime Before hook must be a javascript function."))
		}

		lKey := strings.ToLower(RTAPI_PREFIX + key)
		im.registerCallbackFn(RuntimeExecutionModeBefore, lKey, fn)
		im.announceCallbackFn(RuntimeExecutionModeBefore, lKey)

		return nil
	}
}

func (im *RuntimeJavascriptInitModule) registerRTAfter(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		key, ok := f.Arguments[0].Export().(string)
		if !ok {
			panic(r.ToValue("Request realtime After hook function name must be a string."))
		}
		if key == "" {
			panic(r.ToValue("Request realtime After hook function name cannot be empty."))
		}

		fn, ok := goja.AssertFunction(f.Arguments[1])
		if !ok {
			panic(r.ToValue("Request realtime After hook must be a javascript function."))
		}

		lKey := strings.ToLower(RTAPI_PREFIX + key)
		im.registerCallbackFn(RuntimeExecutionModeAfter, lKey, fn)
		im.announceCallbackFn(RuntimeExecutionModeAfter, lKey)

		return nil
	}
}

func (im *RuntimeJavascriptInitModule) registerCallbackFn(mode RuntimeExecutionMode, key string, fn goja.Callable) {
	switch mode {
	case RuntimeExecutionModeRPC:
		im.Callbacks.Rpc[key] = fn
	case RuntimeExecutionModeBefore:
		im.Callbacks.Before[key] = fn
	case RuntimeExecutionModeAfter:
		im.Callbacks.After[key] = fn
		/*case RuntimeExecutionModeMatchmaker:
			im.Callbacks.Matchmaker = fn
		case RuntimeExecutionModeTournamentEnd:
			im.Callbacks.TournamentEnd = fn
		case RuntimeExecutionModeTournamentReset:
			im.Callbacks.TournamentReset = fn
		case RuntimeExecutionModeLeaderboardReset:
			im.Callbacks.LeaderboardReset = fn */
	}
}
