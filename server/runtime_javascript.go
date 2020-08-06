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
	logger       *zap.Logger
	node         string
	nkInst       goja.Value
	jsLoggerInst goja.Value
	env          goja.Value
	vm           *goja.Runtime
	callbacks    *RuntimeJavascriptCallbacks
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

type JsErrorType int

func(e JsErrorType) String() string {
	switch e {
	case JsErrorException:
		return "exception"
	default:
		return ""
	}
}

const (
	JsErrorException JsErrorType = iota
	JsErrorRuntime
)

type jsError struct {
	StackTrace string
	Type string
	Message string `json:",omitempty"`
	error error
}

func (e *jsError) Error() string {
	return e.error.Error()
}

type RuntimeJavascriptCallbacks struct {
	Rpc    map[string]goja.Callable
	Before map[string]goja.Callable
	After  map[string]goja.Callable
}

func newJsExceptionError(t JsErrorType, error, st string) *jsError {
	return &jsError{
		StackTrace: st,
		Type: t.String(),
		error: errors.New(error),
	}
}

func newJsError(t JsErrorType, err error) *jsError {
	return &jsError{
		Message: err.Error(),
		Type: t.String(),
		error: err,
	}
}

type RuntimeJSModule struct {
	Name    string
	Path    string
	Program *goja.Program
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

	poolCh       chan *RuntimeJS
	maxCount     uint32
	currentCount *atomic.Uint32
	newFn        func() *RuntimeJS
}

func (rp *RuntimeProviderJS) Rpc(ctx context.Context, id string, queryParams map[string][]string, userID, username string, vars map[string]string, expiry int64, sessionID, clientIP, clientPort, payload string) (string, error, codes.Code) {
	r, err := rp.Get(ctx)
	if err != nil {
		return "", err, codes.Internal
	}
	jsFn := r.GetCallback(RuntimeExecutionModeRPC, id)
	if jsFn == nil {
		rp.Put(r)
		return "", ErrRuntimeRPCNotFound, codes.NotFound
	}
	retValue, err, code := r.InvokeFunction(RuntimeExecutionModeRPC, id, jsFn, queryParams, userID, username, vars, expiry, sessionID, clientIP, clientPort, payload)
	if err != nil {
		return "", err, code
	}
	payload, ok := retValue.Export().(string)
	if !ok {
		msg := "Runtime function returned invalid data - only allowed one return value of type string."
		rp.logger.Error(msg, zap.String("mode", RuntimeExecutionModeRPC.String()), zap.String("id", id))
		return "", errors.New(msg), codes.Internal
	}

	return payload, nil, code
}

func (r *RuntimeJS) InvokeFunction(execMode RuntimeExecutionMode, id string, fn goja.Callable, queryParams map[string][]string, uid, username string, vars map[string]string, sessionExpiry int64, sid, clientIP, clientPort string, payloads ...interface{}) (goja.Value, error, codes.Code) {
	ctx := NewRuntimeJsContext(r.vm, r.node, r.env, execMode, queryParams, sessionExpiry, uid, username, vars, sid, clientIP, clientPort)
	args := []goja.Value{ctx, r.jsLoggerInst, r.nkInst}
	jv := make([]goja.Value, 0, len(args)+len(payloads))
	jv = append(jv, args...)
	for _, payload := range payloads {
		jv = append(jv, r.vm.ToValue(payload))
	}

	retVal, err := fn(goja.Null(), jv...)
	if err != nil {
		if exErr, ok := err.(*goja.Exception); ok {
			println(exErr)
			r.logger.Error("javascript runtime function raised an uncaught exception", zap.String("mode", execMode.String()), zap.String("id", id), zap.Error(err))
			return nil, newJsExceptionError(JsErrorException, exErr.Error(), exErr.String()), codes.Internal
		}
		r.logger.Error("javascript runtime function caused an error", zap.String("mode", execMode.String()), zap.String("id", id), zap.Error(err))
		return nil, newJsError(JsErrorRuntime, err), codes.Internal
	}
	if retVal == nil || retVal == goja.Undefined() || retVal == goja.Null() {
		return nil, nil, codes.OK
	}

	return retVal, nil, codes.OK
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
		logger:       logger,
		poolCh:       make(chan *RuntimeJS, config.GetRuntime().MaxCount),
		maxCount:     uint32(config.GetRuntime().MaxCount),
		currentCount: atomic.NewUint32(uint32(config.GetRuntime().MinCount)),
	}

	rpcFunctions := make(map[string]RuntimeRpcFunction, 0)
	// beforeRtFunctions := make(map[string]RuntimeBeforeRtFunction, 0)
	// afterRtFunctions := make(map[string]RuntimeAfterRtFunction, 0)

	callbacks, err := evalRuntimeModules(logger, modCache, config, func(mode RuntimeExecutionMode, key string) {
		switch mode {
		case RuntimeExecutionModeRPC:
			rpcFunctions[key] = func(ctx context.Context, queryParams map[string][]string, userID, username string, vars map[string]string, expiry int64, sessionID, clientIP, clientPort, payload string) (string, error, codes.Code) {
				return runtimeProviderJS.Rpc(ctx, key, queryParams, userID, username, vars, expiry, sessionID, clientIP, clientPort, payload)
			}
		}
	})
	if err != nil {
		logger.Error("Failed to eval Javascript modules.", zap.Error(err))
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, err
	}

	runtimeProviderJS.newFn = func () *RuntimeJS {
		runtime := goja.New()

		jsLogger := NewJsLogger(logger)
		jsLoggerValue := runtime.ToValue(jsLogger.Constructor(runtime))
		jsLoggerInst, err := runtime.New(jsLoggerValue)
		if err != nil {
			logger.Fatal("Failed to initialize Javascript runtime", zap.Error(err))
		}

		nakamaModule := NewRuntimeJavascriptNakamaModule(logger)
		nk := runtime.ToValue(nakamaModule.Constructor(runtime))
		nkInst, err := runtime.New(nk)
		if err != nil {
			logger.Fatal("Failed to initialize Javascript runtime", zap.Error(err))
		}

		return &RuntimeJS {
			logger:       logger,
			jsLoggerInst: jsLoggerInst,
			nkInst:       nkInst,
			node:         config.GetName(),
			vm:           runtime,
			env:          runtime.ToValue(config.GetRuntime().Environment),
			callbacks:    callbacks,
		}
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

func CheckRuntimeProviderJavascript(logger *zap.Logger, config Config, paths []string) error {
	modCache, err := cacheJavascriptModules(logger, config.GetRuntime().Path, paths)
	if err != nil {
		return err
	}
	_, err = evalRuntimeModules(logger, modCache, config, func(RuntimeExecutionMode, string){})
	return err
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
			return nil, err
		}

		modName := filepath.Base(path)
		prg, err := goja.Compile(modName, string(content), true)
		if err != nil {
			logger.Error("Could not compile Javascript module", zap.String("module", modName), zap.Error(err))
			return nil, err
		}

		moduleCache.Add(&RuntimeJSModule{
			Name:    modName,
			Path:    path,
			Program: prg,
		})
	}

	return moduleCache, nil
}

func evalRuntimeModules(logger *zap.Logger, modCache *RuntimeJSModuleCache, config Config, announceCallbackFn func(RuntimeExecutionMode, string)) (*RuntimeJavascriptCallbacks, error) {
	r := goja.New()

	initializer := NewRuntimeJavascriptInitModule(logger, announceCallbackFn)
	initializerValue := r.ToValue(initializer.Constructor())
	initializerInst, err := r.New(initializerValue)
	if err != nil {
		return nil, err
	}

	jsLogger := NewJsLogger(logger)
	jsLoggerValue := r.ToValue(jsLogger.Constructor(r))
	jsLoggerInst, err := r.New(jsLoggerValue)
	if err != nil {
		return nil, err
	}

	nakamaModule := NewRuntimeJavascriptNakamaModule(logger)
	nk := r.ToValue(nakamaModule.Constructor(r))
	nkInst, err := r.New(nk)
	if err != nil {
		return nil, err
	}

	for _, modName := range modCache.Names {
		_, err = r.RunProgram(modCache.Modules[modName].Program)
		if err != nil {
			return nil, err
		}

		initMod := r.Get(INIT_MODULE_FN_NAME)
		initModFn, ok := goja.AssertFunction(initMod)
		if !ok {
			logger.Error("InitModule function not found in module.", zap.String("module", modName))
			return nil, errors.New(INIT_MODULE_FN_NAME + " function not found.")
		}

		ctx := NewRuntimeJsInitContext(r, config.GetName(), config.GetRuntime().Environment)
		_, err = initModFn(goja.Null(), ctx, jsLoggerInst, nkInst, initializerInst)
		if err != nil {
			if exErr, ok := err.(*goja.Exception); ok {
				return nil, errors.New(exErr.String())
			}
			return nil, err
		}
	}

	return initializer.Callbacks, nil
}
