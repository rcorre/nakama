package server

import (
	"context"
	"database/sql"
	"github.com/dop251/goja"
	"github.com/gofrs/uuid"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/heroiclabs/nakama-common/api"
	"go.uber.org/zap"
	"time"
)

type runtimeJavascriptNakamaModule struct {
	logger *zap.Logger
	db *sql.DB
	eventFn RuntimeEventCustomFunction
}

func NewRuntimeJavascriptNakamaModule(logger *zap.Logger, db *sql.DB, eventFn RuntimeEventCustomFunction) *runtimeJavascriptNakamaModule {
	return &runtimeJavascriptNakamaModule{
		logger: logger,
		db: db,
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
		"uuidv4": n.uuidV4(r),
		"sqlExec": n.sqlExec(r),
		"sqlQuery": n.sqlQuery(r),
		"httpRequest": n.httpRequest(r),
	}
}

func (n *runtimeJavascriptNakamaModule) event(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		eventName := getString(r, f.Argument(0))
		properties := getStringMap(r, f.Argument(1))
		ts := &timestamp.Timestamp{}
		if f.Argument(2) != goja.Undefined() {
			ts.Seconds = getInt(r, f.Argument(2))
		} else {
			ts.Seconds = time.Now().Unix()
		}
		external := false
		if f.Argument(3) != goja.Undefined() {
			external = getBool(r, f.Argument(3))
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

func (n *runtimeJavascriptNakamaModule) uuidV4(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		return r.ToValue(uuid.Must(uuid.NewV4()).String())
	}
}

func (n *runtimeJavascriptNakamaModule) sqlExec(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		query := getString(r, f.Argument(0))
		var args []interface{}
		if f.Argument(1) == goja.Undefined() {
			args = make([]interface{}, 0)
		} else {
			var ok bool
			args, ok = f.Argument(1).Export().([]interface{})
			if !ok {
				panic(r.ToValue("Invalid argument - query params must be an array."))
			}
		}

		// TODO figure out how to pass in context
		var res sql.Result
		var err error
		err = ExecuteRetryable(func() error {
			res, err = n.db.Exec(query, args...)
			return err
		})
		if err != nil {
			n.logger.Error("Failed to exec db query.", zap.String("query", query), zap.Any("args", args), zap.Error(err))
			panic(r.ToValue(err.Error()))
		}

		nRowsAffected, _ := res.RowsAffected()

		return r.ToValue(
			map[string]interface{}{
				"rows_affected": nRowsAffected,
			},
		)
	}
}

func (n *runtimeJavascriptNakamaModule) sqlQuery(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		query := getString(r, f.Argument(0))
		var args []interface{}
		if f.Argument(1) == goja.Undefined() {
			args = make([]interface{}, 0)
		} else {
			var ok bool
			args, ok = f.Argument(1).Export().([]interface{})
			if !ok {
				panic(r.ToValue("Invalid argument - query params must be an array."))
			}
		}

		var rows *sql.Rows
		var err error
		err = ExecuteRetryable(func() error {
			rows, err = n.db.Query(query, args...)
			return err
		})
		if err != nil {
			n.logger.Error("Failed to exec db query.", zap.String("query", query), zap.Any("args", args), zap.Error(err))
			panic(r.ToValue(err.Error()))
		}
		defer rows.Close()

		rowColumns, err := rows.Columns()
		if err != nil {
			n.logger.Error("Failed to get row columns.", zap.Error(err))
			panic(r.ToValue(err.Error()))
		}
		rowsColumnCount := len(rowColumns)
		resultRows := make([][]interface{}, 0)
		for rows.Next() {
			resultRowValues := make([]interface{}, rowsColumnCount)
			resultRowPointers := make([]interface{}, rowsColumnCount)
			for i := range resultRowValues {
				resultRowPointers[i] = &resultRowValues[i]
			}
			if err = rows.Scan(resultRowPointers...); err != nil {
				n.logger.Error("Failed to scan row results.", zap.Error(err))
				panic(r.ToValue(err.Error()))
			}
			resultRows = append(resultRows, resultRowValues)
		}
		if err = rows.Err(); err != nil {
			n.logger.Error("Failed scan rows.", zap.Error(err))
			panic(r.ToValue(err.Error()))
		}

		results := make([]map[string]interface{}, 0, len(resultRows))
		for _, row := range resultRows {
			resultRow := make(map[string]interface{}, rowsColumnCount)
			for i, col := range rowColumns {
				resultRow[col] = row[i]
			}
			results = append(results, resultRow)
		}

		return r.ToValue(results)
	}
}

func (n *runtimeJavascriptNakamaModule) httpRequest(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		// TODO http request
		return nil
	}
}

func getString(r *goja.Runtime, v goja.Value) string {
	s, ok := v.Export().(string)
	if !ok {
		panic(r.ToValue("Invalid argument - string expected."))
	}
	return s
}

func getStringMap(r *goja.Runtime, v goja.Value) map[string]string {
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

func getInt(r *goja.Runtime, v goja.Value) int64 {
	i, ok := v.Export().(int64)
	if !ok {
		panic(r.ToValue("Invalid argument - int expected."))
	}
	return i
}

func getBool(r *goja.Runtime, v goja.Value) bool {
	b, ok := v.Export().(bool)
	if !ok {
		panic(r.ToValue("Invalid argument - boolean expected."))
	}
	return b
}
