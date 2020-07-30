package server

import (
	"errors"
	"fmt"
	"github.com/dop251/goja"
	"go.uber.org/zap"
)

type jsLogger struct {
	logger *zap.Logger
}

func NewJsLogger(logger *zap.Logger) *jsLogger {
	return &jsLogger{logger: logger.WithOptions()}
}

func (l *jsLogger) Constructor(r *goja.Runtime) func(goja.ConstructorCall) *goja.Object {
	invalidArgErr := errors.New("invalid argument")
	getArgs := func(values []goja.Value) (string, []interface{}, error) {
		format, ok := values[0].Export().(string)
		if !ok {
			return "", nil, invalidArgErr
		}
		args := make([]interface{}, 0, len(values)-1)
		for _, v := range values[1:] {
			a, ok := v.Export().(string)
			if !ok {
				return "", nil, invalidArgErr
			}
			args = append(args, a)
		}
		return format, args, nil
	}

	toLoggerFields := func(m map[string]interface{}) []zap.Field {
		zFields := make([]zap.Field, 0, len(m))
		for k, v := range m {
			zFields = append(zFields, zap.Any(k, v))
		}
		return zFields
	}

	return func(call goja.ConstructorCall) *goja.Object {
		var argFields goja.Value
		if len(call.Arguments) > 0 {
			argFields = call.Arguments[0]
		} else {
			argFields = r.NewObject()
		}
		call.This.Set("fields", argFields)

		call.This.Set("info", func(f goja.FunctionCall) goja.Value {
			format, a, err := getArgs(f.Arguments)
			if err != nil {
				panic(err)
			}
			fields := call.This.Get("fields").Export().(map[string]interface{})
			l.logger.Info(fmt.Sprintf(format, a...), toLoggerFields(fields)...)
			return nil
		})
		call.This.Set("warn", func(f goja.FunctionCall) goja.Value {
			format, a, err := getArgs(f.Arguments)
			if err != nil {
				panic(err)
			}
			fields := call.This.Get("fields").Export().(map[string]interface{})
			l.logger.Warn(fmt.Sprintf(format, a...), toLoggerFields(fields)...)
			return nil
		})
		call.This.Set("error", func(f goja.FunctionCall) goja.Value {
			format, a, err := getArgs(f.Arguments)
			if err != nil {
				panic(err)
			}
			fields := call.This.Get("fields").Export().(map[string]interface{})
			l.logger.Error(fmt.Sprintf(format, a...), toLoggerFields(fields)...)
			return nil
		})
		call.This.Set("debug", func(f goja.FunctionCall) goja.Value {
			format, a, err := getArgs(f.Arguments)
			if err != nil {
				panic(err)
			}
			fields := call.This.Get("fields").Export().(map[string]interface{})
			l.logger.Debug(fmt.Sprintf(format, a...), toLoggerFields(fields)...)
			return nil
		})
		call.This.Set("withField", func(f goja.FunctionCall) goja.Value {
			key, ok := f.Arguments[0].Export().(string)
			if !ok {
				panic(invalidArgErr)
			}
			value, ok := f.Arguments[1].Export().(string)
			if !ok {
				panic(invalidArgErr)
			}

			fields := call.This.Get("fields").Export().(map[string]interface{})
			fields[key] = value

			c := r.ToValue(call.This.Get("constructor"))
			objInst, err := r.New(c, r.ToValue(fields))
			if err != nil {
				panic(err)
			}

			return objInst
		})
		call.This.Set("withFields", func(f goja.FunctionCall) goja.Value {
			argMap, ok := f.Arguments[0].Export().(map[string]interface{})
			if !ok {
				panic(invalidArgErr)
			}

			fields := call.This.Get("fields").Export().(map[string]interface{})
			for k, v := range argMap {
				fields[k] = v
			}

			c := r.ToValue(call.This.Get("constructor"))
			objInst, err := r.New(c, r.ToValue(fields))
			if err != nil {
				panic(err)
			}

			return objInst
		})
		call.This.Set("getFields", func(f goja.FunctionCall) goja.Value {
			return call.This.Get("fields")
		})

		return nil
	}
}

