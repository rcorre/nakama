// Copyright 2018 The Nakama Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/dop251/goja"
	"github.com/golang/protobuf/jsonpb"
	"github.com/heroiclabs/nakama/v2/social"
	"go.uber.org/atomic"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"io/ioutil"
	"path/filepath"
	"sort"
	"strings"
)

type RuntimeJS struct {
	logger    *zap.Logger
	jsLogger  *goja.Object
	nkModule  *goja.Object
	node      string
	vm        *goja.Runtime
	callbacks *RuntimeJavascriptCallbacks
}

func (r *RuntimeJS) GetCallback(e RuntimeExecutionMode, key string) goja.Callable {
	switch e {
	case RuntimeExecutionModeRPC:
		return r.callbacks.Rpc[key]
	case RuntimeExecutionModeBefore:
		return r.callbacks.Before[key]
	case RuntimeExecutionModeAfter:
		return r.callbacks.After[key]
	case RuntimeExecutionModeMatchmaker:
		// return r.callbacks.Matchmaker
	case RuntimeExecutionModeTournamentEnd:
		// return r.callbacks.TournamentEnd
	case RuntimeExecutionModeTournamentReset:
		// return r.callbacks.TournamentReset
	case RuntimeExecutionModeLeaderboardReset:
		// return r.callbacks.LeaderboardReset
	}

	return nil
}

type RuntimeJavascriptCallbacks struct {
	Rpc    map[string]goja.Callable
	Before map[string]goja.Callable
	After  map[string]goja.Callable
}

type RuntimeJSModule struct {
	Name    string
	Path    string
	Content []byte
}

type RuntimeJSModuleCache struct {
	Names   []string
	Modules map[string]*RuntimeJSModule
}

func (mc *RuntimeJSModuleCache) Add(m *RuntimeJSModule) {
	mc.Names = append(mc.Names, m.Name)
	mc.Modules[m.Name] = m

	// Ensure modules will be listed in ascending order of names.
	sort.Strings(mc.Names)
}

type RuntimeProviderJS struct {
	logger               *zap.Logger
	db                   *sql.DB
	jsonpbMarshaler      *jsonpb.Marshaler
	jsonpbUnmarshaler    *jsonpb.Unmarshaler
	config               Config
	socialClient         *social.Client
	leaderboardCache     LeaderboardCache
	leaderboardRankCache LeaderboardRankCache
	sessionRegistry      SessionRegistry
	matchRegistry        MatchRegistry

	stdLib              *goja.Object
	initializer         *RuntimeJavascriptInitModule

	poolCh       chan *RuntimeJS
	maxCount     uint32
	currentCount *atomic.Uint32
	newFn        func() *RuntimeJS
}

// TOOD why did I even add this here?
func (rp *RuntimeProviderJS) Rpc(ctx context.Context, id string, queryParams map[string][]string, userID, username string, vars map[string]string, expiry int64, sessionID, clientIP, clientPort, payload string) (string, error, codes.Code) {
	r, err := rp.Get(ctx)
	if err != nil {
		return "", err, codes.Internal
	}
	lf := r.GetCallback(RuntimeExecutionModeRPC, id)
	if lf == nil {
		rp.Put(r)
		return "", ErrRuntimeRPCNotFound, codes.NotFound
	}
	retValue, err, code := r.InvokeFunction(RuntimeExecutionModeRPC, lf, queryParams, userID, username, vars, expiry, sessionID, clientIP, clientPort, payload)
	ret := retValue.(string)

	return ret, err, code
}

func (r *RuntimeJS) InvokeFunction(execMode RuntimeExecutionMode, fn goja.Callable, queryParams map[string][]string, uid, username string, vars map[string]string, sessionExpiry int64, sid, clientIP, clientPort string, payloads ...interface{}) (interface{}, error, codes.Code) {
	ctx := r.vm.NewObject()
	args := []goja.Value{ctx, r.jsLogger, r.nkModule}
	jv := make([]goja.Value, 0, len(args)+len(payloads))
	jv = append(jv, args...)
	for _, payload := range payloads {
		jv = append(jv, r.vm.ToValue(payload))
	}

	retVal, err := fn(goja.Null(), jv...)
	if err != nil {
		return nil, err, codes.InvalidArgument
	}
	if retVal == goja.Undefined() || retVal == goja.Null() {
		return "", nil, 0
	}

	payload, ok := retVal.Export().(string)
	if !ok {
		return "", errors.New("Runtime function returned invalid data - only allowed one return value of type string."), codes.Internal
	}

	return payload, nil, 0
}

func (rp *RuntimeProviderJS) Get(ctx context.Context) (*RuntimeJS, error) {
	select {
	case <- ctx.Done():
		// Context cancelled
		return nil, ctx.Err()
	case r := <- rp.poolCh:
		return r, nil
	default:
		// If there was no idle runtime, see if we can allocate a new one.
		if rp.currentCount.Load() >= rp.maxCount {
			// No further runtime allocation allowed.
			break
		}
		currentCount := rp.currentCount.Inc()
		if currentCount > rp.maxCount {
			// When we've incremented see if we can still allocate or a concurrent operation has already done so up to the limit.
			// The current count value may go above max count value, but we will never over-allocate runtimes.
			// This discrepancy is allowed as it avoids a full mutex locking scenario.
			break
		}
		return rp.newFn(), nil
	}

	// If we reach here then we were unable to find an available idle runtime, and allocation was not allowed.
	// Wait as needed.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <- rp.poolCh:
		return r, nil
	}
}

func (rp *RuntimeProviderJS) Put(r *RuntimeJS) {
	select {
	case rp.poolCh <- r:
		// Runtime is successfully returned to the pool.
	default:
		// The pool is over capacity. Should never happen but guard anyway.
		// Safe to continue processing, the runtime is just discarded.
		rp.logger.Warn("Runtime pool full, discarding Lua runtime")
	}
}


func NewRuntimeProviderJS(logger, startupLogger *zap.Logger, db *sql.DB, jsonpbMarshaler *jsonpb.Marshaler, jsonpbUnmarshaler *jsonpb.Unmarshaler, config Config, socialClient *social.Client, leaderboardCache LeaderboardCache, leaderboardRankCache LeaderboardRankCache, leaderboardScheduler LeaderboardScheduler, sessionRegistry SessionRegistry, matchRegistry MatchRegistry, tracker Tracker, metrics *Metrics, streamManager StreamManager, router MessageRouter, goMatchCreateFn RuntimeMatchCreateFunction, eventFn RuntimeEventCustomFunction, rootPath string, paths []string) ([]string, map[string]RuntimeRpcFunction, map[string]RuntimeBeforeRtFunction, map[string]RuntimeAfterRtFunction, *RuntimeBeforeReqFunctions, *RuntimeAfterReqFunctions, RuntimeMatchmakerMatchedFunction, RuntimeMatchCreateFunction, RuntimeTournamentEndFunction, RuntimeTournamentResetFunction, RuntimeLeaderboardResetFunction, error) {
	startupLogger.Info("Initialising Javascript runtime provider", zap.String("path", rootPath))

	modCache, err := cacheJavascriptModules(startupLogger, rootPath, paths)
	if err != nil {
		panic(err)
	}

	runtimeProviderJS := &RuntimeProviderJS{
		logger:              	logger,
		stdLib:               nil, // TODO
		initializer:          nil, // TODO
		poolCh:               make(chan *RuntimeJS, config.GetRuntime().MaxCount),
		maxCount:             uint32(config.GetRuntime().MaxCount),
		currentCount:         atomic.NewUint32(uint32(config.GetRuntime().MinCount)),
	}

	rpcFunctions := make(map[string]RuntimeRpcFunction, 0)
	// beforeRtFunctions := make(map[string]RuntimeBeforeRtFunction, 0)
	// afterRtFunctions := make(map[string]RuntimeAfterRtFunction, 0)

	announceCallbackFn := func(mode RuntimeExecutionMode, key string) {
		switch mode {
		case RuntimeExecutionModeRPC:
			rpcFunctions[key] = func(ctx context.Context, queryParams map[string][]string, userID, username string, vars map[string]string, expiry int64, sessionID, clientIP, clientPort, payload string) (string, error, codes.Code) {
				return runtimeProviderJS.Rpc(ctx, key, queryParams, userID, username, vars, expiry, sessionID, clientIP, clientPort, payload)
			}
		}
	}

	// TODO see if it is possible to share the global state across vms
	initializer := NewRuntimeJavascriptInitModule(logger, announceCallbackFn)
	runtimeProviderJS.newFn = func () *RuntimeJS {
		r, err := newRuntimeJavascriptVM(logger, db, modCache, initializer, config)
		if err != nil {
			logger.Fatal("Failed to initialize Javascript runtime", zap.Error(err))
		}
		return r
	}

	startupLogger.Info("Javascript runtime modules loaded")

	// Warm up the pool.
	startupLogger.Info("Allocating minimum runtime pool", zap.Int("count", config.GetRuntime().MinCount))
	if len(modCache.Names) > 0 {
		// Only if there are runtime modules to load.
		for i := 0; i < config.GetRuntime().MinCount; i++ {
			runtimeProviderJS.poolCh <- runtimeProviderJS.newFn()
		}
		// TODO Gauge metrics
	}
	startupLogger.Info("Allocated minimum runtime pool")

	// return modulePaths, rpcFunctions, beforeRtFunctions, afterRtFunctions, beforeReqFunctions, afterReqFunctions, matchmakerMatchedFunction, allMatchCreateFn, tournamentEndFunction, tournamentResetFunction, leaderboardResetFunction, nil
	return modCache.Names, rpcFunctions, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil
}

func cacheJavascriptModules(logger *zap.Logger, rootPath string, paths []string) (*RuntimeJSModuleCache, error) {
	moduleCache := &RuntimeJSModuleCache{
		Names: make([]string, 0),
		Modules: make(map[string]*RuntimeJSModule),
	}

	for _, path := range paths {
		if strings.ToLower(filepath.Ext(path)) != ".js" {
			continue
		}

		var content []byte
		var err error
		if content, err = ioutil.ReadFile(path); err != nil {
			logger.Error("Could not read Javascript module", zap.String("path", path), zap.Error(err))
		}

		moduleCache.Add(&RuntimeJSModule{
			Name:    filepath.Base(path),
			Path:    path,
			Content: content,
		})
	}

	return moduleCache, nil
}

func newRuntimeJavascriptVM(logger *zap.Logger, db *sql.DB, modCache *RuntimeJSModuleCache, initializer *RuntimeJavascriptInitModule, config Config) (*RuntimeJS, error) {
	runtime := goja.New()

	nakamaModule := NewRuntimeJavascriptNakamaModule(logger, db)
	nk := runtime.ToValue(nakamaModule.Constructor())
	nkInst, err := runtime.New(nk)
	if err != nil {
		panic(err)
	}
	//runtime.Set("nk", nkInst)

	initializerValue := runtime.ToValue(initializer.Constructor())
	initializerInst, err := runtime.New(initializerValue)

	jsLogger := NewJsLogger(logger)
	jsLoggerValue := runtime.ToValue(jsLogger.Constructor())
	jsLoggerInst, err := runtime.New(jsLoggerValue)

	if err != nil {
		panic(err)
	}

	for _, modName := range modCache.Names {
		prg, err := goja.Compile(modName, string(modCache.Modules[modName].Content), true)
		if err != nil {
			panic(err)
		}

		_, err = runtime.RunProgram(prg)
		if err != nil {
			panic(err)
		}

		initMod := runtime.Get("InitModule")
		initModFn, ok := goja.AssertFunction(initMod)
		if !ok {
			panic("Couldn't get InitMod function")
		}

		_, err = initModFn(goja.Null(), goja.Null(), jsLoggerInst, nkInst, initializerInst)
		if err != nil {
			panic(err)
		}
	}

	// TODO freeze the global object using the writable property on the object definition if possible
	return &RuntimeJS{
		logger:    logger,
		jsLogger:  jsLoggerInst,
		nkModule:  nkInst,
		node:      config.GetName(),
		vm:        runtime,
		callbacks: initializer.Callbacks,
	}, nil
}


type jsLogger struct {
	logger *zap.Logger
}

func NewJsLogger(logger *zap.Logger) *jsLogger {
	return &jsLogger{logger: logger}
}

func (l *jsLogger) Constructor() func(goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {

		getArgs := func(values []goja.Value) (string, []interface{}, error) {
			format, ok := values[0].Export().(string)
			if !ok {
				return "", nil, errors.New("Invalid argument") // TODO
			}
			args := make([]interface{}, 0, len(values)-1)
			for _, v := range values[1:] {
				a, ok := v.Export().(string)
				if !ok {
					return "", nil, errors.New("Invalid argument") // TODO
				}
				args = append(args, a)
			}
			return format, args, nil
		}

		call.This.Set("info", func(f goja.FunctionCall) goja.Value {
			format, a, err := getArgs(f.Arguments)
			if err != nil {
				panic(errors.New("Invalid args in function call.")) // Should this raise an error ?
			}
			l.logger.Info(fmt.Sprintf(format, a...))
			return nil
		})
		call.This.Set("warn", func(f goja.FunctionCall) goja.Value {
			format, a, err := getArgs(f.Arguments)
			if err != nil {
				panic(errors.New("Invalid args in function call.")) // Should this raise an error ?
			}
			l.logger.Warn(fmt.Sprintf(format, a...))
			return nil
		})
		call.This.Set("error", func(f goja.FunctionCall) goja.Value {
			format, a, err := getArgs(f.Arguments)
			if err != nil {
				panic(errors.New("Invalid args in function call.")) // Should this raise an error ?
			}
			l.logger.Error(fmt.Sprintf(format, a...))
			return nil
		})
		call.This.Set("debug", func(f goja.FunctionCall) goja.Value {
			format, a, err := getArgs(f.Arguments)
			if err != nil {
				panic(errors.New("Invalid args in function call.")) // Should this raise an error ?
			}
			l.logger.Debug(fmt.Sprintf(format, a...))
			return nil
		})

		return nil
	}
}
