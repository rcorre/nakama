package server

import (
	"github.com/dop251/goja"
	"go.uber.org/zap"
	"strings"
)

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

func (im *RuntimeJavascriptInitModule) mappings() map[string]func(goja.FunctionCall) goja.Value {
	return map[string]func(goja.FunctionCall) goja.Value {
		"registerRpc": im.registerRpc,
	}
}

func (im *RuntimeJavascriptInitModule) Constructor() func(goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {
		for key, fn := range im.mappings() {
			call.This.Set(key, fn)
		}

		return nil
	}
}

func (im *RuntimeJavascriptInitModule) registerRpc(f goja.FunctionCall) goja.Value {
	key, ok := f.Arguments[0].Export().(string)
	if !ok {
		panic("invalid argument")
	}
	if key == "" {
		panic("RPC function name cannot be empty.")
	}

	fn, ok := goja.AssertFunction(f.Arguments[1])
	if !ok {
		panic("invalid argument")
	}

	lKey := strings.ToLower(key)
	im.registerCallbackFn(RuntimeExecutionModeRPC, lKey, fn)
	im.announceCallbackFn(RuntimeExecutionModeRPC, lKey)

	return nil
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
