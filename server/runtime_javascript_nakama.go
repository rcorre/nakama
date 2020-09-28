package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/heroiclabs/nakama/v2/cronexpr"

	"github.com/heroiclabs/nakama-common/rtapi"

	"github.com/dgrijalva/jwt-go"
	"github.com/dop251/goja"
	"github.com/gofrs/uuid"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/heroiclabs/nakama-common/api"
	"github.com/heroiclabs/nakama/v2/social"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type runtimeJavascriptNakamaModule struct {
	logger               *zap.Logger
	config               Config
	db                   *sql.DB
	jsonpbMarshaler      *jsonpb.Marshaler
	jsonpbUnmarshaler    *jsonpb.Unmarshaler
	httpClient           *http.Client
	socialClient         *social.Client
	leaderboardCache     LeaderboardCache
	rankCache            LeaderboardRankCache
	leaderboardScheduler LeaderboardScheduler
	tracker              Tracker
	sessionRegistry      SessionRegistry
	matchRegistry        MatchRegistry
	streamManager        StreamManager
	router               MessageRouter

	node          string
	matchCreateFn RuntimeMatchCreateFunction
	eventFn       RuntimeEventCustomFunction
}

func NewRuntimeJavascriptNakamaModule(logger *zap.Logger, db *sql.DB, jsonpbMarshaler *jsonpb.Marshaler, jsonpbUnmarshaler *jsonpb.Unmarshaler, config Config, socialClient *social.Client, leaderboardCache LeaderboardCache, rankCache LeaderboardRankCache, leaderboardScheduler LeaderboardScheduler, sessionRegistry SessionRegistry, matchRegistry MatchRegistry, tracker Tracker, streamManager StreamManager, router MessageRouter, eventFn RuntimeEventCustomFunction, matchCreateFn RuntimeMatchCreateFunction) *runtimeJavascriptNakamaModule {
	return &runtimeJavascriptNakamaModule{
		logger:               logger,
		config:               config,
		db:                   db,
		jsonpbMarshaler:      jsonpbMarshaler,
		jsonpbUnmarshaler:    jsonpbUnmarshaler,
		streamManager:        streamManager,
		sessionRegistry:      sessionRegistry,
		matchRegistry:        matchRegistry,
		router:               router,
		tracker:              tracker,
		socialClient:         socialClient,
		leaderboardCache:     leaderboardCache,
		rankCache:            rankCache,
		leaderboardScheduler: leaderboardScheduler,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},

		node:          config.GetName(),
		eventFn:       eventFn,
		matchCreateFn: matchCreateFn,
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
	return map[string]func(goja.FunctionCall) goja.Value{
		"event":                           n.event(r),
		"uuidv4":                          n.uuidV4(r),
		"sqlExec":                         n.sqlExec(r),
		"sqlQuery":                        n.sqlQuery(r),
		"httpRequest":                     n.httpRequest(r),
		"base64UrlEncode":                 n.base64UrlEncode(r),
		"base64UrlDecode":                 n.base64UrlDecode(r),
		"jwtGenerate":                     n.jwtGenerate(r),
		"aes128Encrypt":                   n.aes128Encrypt(r),
		"aes128Decrypt":                   n.aes128Decrypt(r),
		"aes256Encrypt":                   n.aes256Encrypt(r),
		"aes256Decrypt":                   n.aes256Decrypt(r),
		"md5Hash":                         n.md5Hash(r),
		"sha256Hash":                      n.sha256Hash(r),
		"hmacSha256Hash":                  n.hmacSHA256Hash(r),
		"rsaSha256Hash":                   n.rsaSHA256Hash(r),
		"bcryptHash":                      n.bcryptHash(r),
		"bcryptCompare":                   n.bcryptCompare(r),
		"authenticateApple":               n.authenticateApple(r),
		"authenticateCustom":              n.authenticateCustom(r),
		"authenticateDevice":              n.authenticateDevice(r),
		"authenticateEmail":               n.authenticateEmail(r),
		"authenticateFacebook":            n.authenticateFacebook(r),
		"authenticateFacebookInstantGame": n.authenticateFacebookInstantGame(r),
		"authenticateGamecenter":          n.authenticateGameCenter(r),
		"authenticateGoogle":              n.authenticateGoogle(r),
		"authenticateSteam":               n.authenticateSteam(r),
		"authenticateTokenGenerate":       n.authenticateTokenGenerate(r),
		"accountGetId":                    n.accountGetId(r),
		"accountsGetId":                   n.accountsGetId(r),
		"accountUpdateId":                 n.accountUpdateId(r),
		"accountDeleteId":                 n.accountDeleteId(r),
		"accountExportId":                 n.accountExportId(r),
		"usersGetId":                      n.usersGetId(r),
		"usersGetUsername":                n.usersGetUsername(r),
		"usersBanId":                      n.usersBanId(r),
		"usersUnbanId":                    n.usersUnbanId(r),
		"linkApple":                       n.linkApple(r),
		"linkCustom":                      n.linkCustom(r),
		"linkDevice":                      n.linkDevice(r),
		"linkEmail":                       n.linkEmail(r),
		"linkFacebook":                    n.linkFacebook(r),
		"linkFacebookInstantGame":         n.linkFacebookInstantGame(r),
		"linkGameCenter":                  n.linkGameCenter(r),
		"linkGoogle":                      n.linkGoogle(r),
		"linkSteam":                       n.linkSteam(r),
		"unlinkApple":                     n.unlinkApple(r),
		"unlinkCustom":                    n.unlinkCustom(r),
		"unlinkDevice":                    n.unlinkDevice(r),
		"unlinkEmail":                     n.unlinkEmail(r),
		"unlinkFacebook":                  n.unlinkFacebook(r),
		"unlinkFacebookInstantGame":       n.unlinkFacebookInstantGame(r),
		"unlinkGameCenter":                n.unlinkGameCenter(r),
		"unlinkGoogle":                    n.unlinkGoogle(r),
		"unlinkSteam":                     n.unlinkSteam(r),
		"streamUserList":                  n.streamUserList(r),
		"streamUserGet":                   n.streamUserGet(r),
		"streamUserJoin":                  n.streamUserJoin(r),
		"streamUserUpdate":                n.streamUserUpdate(r),
		"streamUserLeave":                 n.streamUserLeave(r),
		"streamUserKick":                  n.streamUserKick(r),
		"streamCount":                     n.streamCount(r),
		"streamClose":                     n.streamClose(r),
		"streamSend":                      n.streamSend(r),
		"streamSendRaw":                   n.streamSendRaw(r),
		"sessionDisconnect":               n.sessionDisconnect(r),
		"matchCreate":                     n.matchCreate(r),
		"matchGet":                        n.matchGet(r),
		"matchList":                       n.matchList(r),
		"notificationSend":                n.notificationSend(r),
		"notificationsSend":               n.notificationsSend(r),
		"walletUpdate":                    n.walletUpdate(r),
		"walletsUpdate":                   n.walletsUpdate(r),
		"walletLedgerUpdate":              n.walletLedgerUpdate(r),
		"walletLedgerList":                n.walletLedgerList(r),
		"storageList":                     n.storageList(r),
		"storageRead":                     n.storageRead(r),
		"storageWrite":                    n.storageWrite(r),
		"storageDelete":                   n.storageDelete(r),
		"multiUpdate":                     n.multiUpdate(r),
		"leaderboardCreate":               n.leaderboardCreate(r),
		"leaderboardDelete":               n.leaderboardDelete(r),
		"leaderboardRecordsList":          n.leaderboardRecordsList(r),
		"leaderboardRecordWrite":          n.leaderboardRecordWrite(r),
		"leaderboardRecordDelete":         n.leaderboardRecordDelete(r),
		"tournament_create":               n.tournamentCreate(r),
		"tournament_delete":               n.tournamentDelete(r),
		"tournament_add_attempt":          n.tournamentAddAttempt(r),
		"tournament_join":                 n.tournamentJoin(r),
		"tournament_list":                 n.tournamentList(r),
		"tournaments_get_id":              n.tournamentsGetId(r),
		"tournament_record_write":         n.tournamentRecordWrite(r),
		"tournament_records_haystack":     n.tournamentRecordsHaystack(r),
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
				Name:       eventName,
				Properties: properties,
				Timestamp:  ts,
				External:   external,
			})
		}

		return goja.Undefined()
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
				panic(r.NewTypeError("Invalid argument - query params must be an array."))
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
				panic(r.NewTypeError("Invalid argument - query params must be an array."))
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
		url := getString(r, f.Argument(0))
		method := strings.ToUpper(getString(r, f.Argument(1)))
		headers := getStringMap(r, f.Argument(2))
		body := getString(r, f.Argument(3))
		timeoutArg := f.Argument(4)
		if timeoutArg != goja.Undefined() {
			n.httpClient.Timeout = time.Duration(timeoutArg.ToInteger()) * time.Millisecond
		}

		n.logger.Debug(fmt.Sprintf("Http Timeout: %v", n.httpClient.Timeout))

		if url == "" {
			panic(r.ToValue("URL string cannot be empty."))
		}

		if !(method == "GET" || method == "POST" || method == "PUT" || method == "PATCH") {
			panic(r.ToValue("Invalid method must be one of: 'get', 'post', 'put', 'patch'."))
		}

		var requestBody io.Reader
		if body != "" {
			requestBody = strings.NewReader(body)
		}

		req, err := http.NewRequest(method, url, requestBody)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("HTTP request is invalid: %v", err.Error())))
		}

		for h, v := range headers {
			// TODO accept multiple values
			req.Header.Add(h, v)
		}

		resp, err := n.httpClient.Do(req)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("HTTP request error: %v", err.Error())))
		}

		// Read the response body.
		responseBody, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("HTTP response body error: %v", err.Error())))
		}
		respHeaders := make(map[string][]string, len(resp.Header))
		for h, v := range resp.Header {
			respHeaders[h] = v
		}

		returnVal := map[string]interface{}{
			"code":    resp.StatusCode,
			"headers": respHeaders,
			"body":    string(responseBody),
		}

		return r.ToValue(returnVal)
	}
}

func (n *runtimeJavascriptNakamaModule) base64Encode(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		in := getString(r, f.Argument(0))
		padding := true
		if f.Argument(1) != goja.Undefined() {
			padding = getBool(r, f.Argument(1))
		}

		e := base64.URLEncoding
		if !padding {
			e = base64.RawURLEncoding
		}

		out := e.EncodeToString([]byte(in))
		return r.ToValue(out)
	}
}

func (n *runtimeJavascriptNakamaModule) base64Decode(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		in := getString(r, f.Argument(0))
		padding := true
		if f.Argument(1) != goja.Undefined() {
			padding = getBool(r, f.Argument(1))
		}

		if !padding {
			// Pad string up to length multiple of 4 if needed to effectively make padding optional.
			if maybePad := len(in) % 4; maybePad != 0 {
				in += strings.Repeat("=", 4-maybePad)
			}
		}

		out, err := base64.StdEncoding.DecodeString(in)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("Failed to decode string: %s", in)))
		}
		return r.ToValue(string(out))
	}
}

func (n *runtimeJavascriptNakamaModule) base64UrlEncode(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		in := getString(r, f.Argument(0))
		padding := true
		if f.Argument(1) != goja.Undefined() {
			padding = getBool(r, f.Argument(1))
		}

		e := base64.URLEncoding
		if !padding {
			e = base64.RawURLEncoding
		}

		out := e.EncodeToString([]byte(in))
		return r.ToValue(out)
	}
}

func (n *runtimeJavascriptNakamaModule) base64UrlDecode(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		in := getString(r, f.Argument(0))
		padding := true
		if f.Argument(1) != goja.Undefined() {
			padding = getBool(r, f.Argument(1))
		}

		if !padding {
			// Pad string up to length multiple of 4 if needed to effectively make padding optional.
			if maybePad := len(in) % 4; maybePad != 0 {
				in += strings.Repeat("=", 4-maybePad)
			}
		}

		out, err := base64.URLEncoding.DecodeString(in)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("Failed to decode string: %s", in)))
		}
		return r.ToValue(string(out))
	}
}

func (n *runtimeJavascriptNakamaModule) base16Encode(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		in := getString(r, f.Argument(0))

		out := hex.EncodeToString([]byte(in))
		return r.ToValue(out)
	}
}

func (n *runtimeJavascriptNakamaModule) base16Decode(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		in := getString(r, f.Argument(0))

		out, err := hex.DecodeString(in)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("Failed to decode string: %s", in)))
		}
		return r.ToValue(string(out))
	}
}

func (n *runtimeJavascriptNakamaModule) jwtGenerate(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		algoType := getString(r, f.Argument(0))

		var signingMethod jwt.SigningMethod
		switch algoType {
		case "HS256":
			signingMethod = jwt.SigningMethodHS256
		case "RS256":
			signingMethod = jwt.SigningMethodRS256
		default:
			panic(r.NewTypeError("unsupported algo type - only allowed 'HS256', 'RS256'."))
		}

		signingKey := getString(r, f.Argument(1))
		if signingKey == "" {
			panic(r.ToValue("signing key cannot be empty"))
		}

		if f.Argument(1) == goja.Undefined() {
			panic(r.ToValue("claims argument is required"))
		}

		claims, ok := f.Argument(2).Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("claims must be an object"))
		}
		jwtClaims := jwt.MapClaims{}
		for k, v := range claims {
			jwtClaims[k] = v
		}

		var pk interface{}
		switch signingMethod {
		case jwt.SigningMethodRS256:
			block, _ := pem.Decode([]byte(signingKey))
			if block == nil {
				panic(r.ToValue("could not parse private key: no valid blocks found"))
			}

			var err error
			pk, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				panic(r.ToValue(fmt.Sprintf("could not parse private key: %v", err.Error())))
			}
		case jwt.SigningMethodHS256:
			pk = []byte(signingKey)
		}

		token := jwt.NewWithClaims(signingMethod, jwtClaims)
		signedToken, err := token.SignedString(pk)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to sign token: %v", err.Error())))
		}

		return r.ToValue(signedToken)
	}
}

func (n *runtimeJavascriptNakamaModule) aes128Encrypt(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getString(r, f.Argument(0))
		key := getString(r, f.Argument(1))

		cipherText, err := n.aesEncrypt(16, input, key)
		if err != nil {
			panic(r.ToValue(err.Error()))
		}

		return r.ToValue(cipherText)
	}
}

func (n *runtimeJavascriptNakamaModule) aes128Decrypt(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getString(r, f.Argument(0))
		key := getString(r, f.Argument(1))

		clearText, err := n.aesDecrypt(16, input, key)
		if err != nil {
			panic(r.ToValue(err.Error()))
		}

		return r.ToValue(clearText)
	}
}

func (n *runtimeJavascriptNakamaModule) aes256Encrypt(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getString(r, f.Argument(0))
		key := getString(r, f.Argument(1))

		cipherText, err := n.aesEncrypt(32, input, key)
		if err != nil {
			panic(r.ToValue(err.Error()))
		}

		return r.ToValue(cipherText)
	}
}

func (n *runtimeJavascriptNakamaModule) aes256Decrypt(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getString(r, f.Argument(0))
		key := getString(r, f.Argument(1))

		clearText, err := n.aesDecrypt(32, input, key)
		if err != nil {
			panic(r.ToValue(err.Error()))
		}

		return r.ToValue(clearText)
	}
}

// Returns the cipher text base64 encoded
func (n *runtimeJavascriptNakamaModule) aesEncrypt(keySize int, input, key string) (string, error) {
	if len(key) != keySize {
		return "", errors.New(fmt.Sprintf("expects key %v bytes long", keySize))
	}

	// Pad string up to length multiple of 4 if needed.
	if maybePad := len(input) % 4; maybePad != 0 {
		input += strings.Repeat(" ", 4-maybePad)
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", errors.New(fmt.Sprintf("error creating cipher block: %v", err.Error()))
	}

	cipherText := make([]byte, aes.BlockSize+len(input))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", errors.New(fmt.Sprintf("error getting iv: %v", err.Error()))
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(input))

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Expect the input cipher text to be base64 encoded
func (n *runtimeJavascriptNakamaModule) aesDecrypt(keySize int, input, key string) (string, error) {
	if len(key) != keySize {
		return "", errors.New(fmt.Sprintf("expects key %v bytes long", keySize))
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", errors.New(fmt.Sprintf("error creating cipher block: %v", err.Error()))
	}

	decodedtText, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "", errors.New(fmt.Sprintf("error decoding cipher text: %v", err.Error()))
	}
	cipherText := decodedtText
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}

func (n *runtimeJavascriptNakamaModule) md5Hash(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getString(r, f.Argument(0))

		hash := fmt.Sprintf("%x", md5.Sum([]byte(input)))

		return r.ToValue(hash)
	}
}

func (n *runtimeJavascriptNakamaModule) sha256Hash(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getString(r, f.Argument(0))

		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(input)))

		return r.ToValue(hash)
	}
}

func (n *runtimeJavascriptNakamaModule) rsaSHA256Hash(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getString(r, f.Argument(0))
		key := getString(r, f.Argument(1))
		if key == "" {
			panic(r.NewTypeError("Invalid argument - cannot be empty string."))
		}

		block, _ := pem.Decode([]byte(key))
		if block == nil {
			panic(r.ToValue("could not parse private key: no valid blocks found"))
		}
		rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error parsing key: %v", err.Error())))
		}

		hashed := sha256.Sum256([]byte(input))
		signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, hashed[:])
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error signing input: %v", err.Error())))
		}

		return r.ToValue(string(signature))
	}
}

func (n *runtimeJavascriptNakamaModule) hmacSHA256Hash(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getString(r, f.Argument(0))
		key := getString(r, f.Argument(1))
		if key == "" {
			panic(r.NewTypeError("Invalid argument - cannot be empty string."))
		}

		mac := hmac.New(sha256.New, []byte(key))
		_, err := mac.Write([]byte(input))
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error creating hash: %v", err.Error())))
		}

		return r.ToValue(string(mac.Sum(nil)))
	}
}

func (n *runtimeJavascriptNakamaModule) bcryptHash(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getString(r, f.Argument(0))
		hash, err := bcrypt.GenerateFromPassword([]byte(input), bcrypt.DefaultCost)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error hashing input: %v", err.Error())))
		}

		return r.ToValue(string(hash))
	}
}

func (n *runtimeJavascriptNakamaModule) bcryptCompare(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		hash := getString(r, f.Argument(0))
		if hash == "" {
			panic(r.NewTypeError("Invalid argument - cannot be empty string."))
		}

		plaintext := getString(r, f.Argument(1))
		if plaintext == "" {
			panic(r.NewTypeError("Invalid argument - cannot be empty string."))
		}

		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
		if err == nil {
			return r.ToValue(true)
		} else if err == bcrypt.ErrHashTooShort || err == bcrypt.ErrMismatchedHashAndPassword {
			return r.ToValue(false)
		}

		panic(r.ToValue(fmt.Sprintf("error comparing hash and plaintext: %v", err.Error())))
	}
}

func (n *runtimeJavascriptNakamaModule) authenticateApple(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		if n.config.GetSocial().Apple.BundleId == "" {
			panic(r.ToValue("Apple authentication is not configured"))
		}

		token := getString(r, f.Argument(0))
		if token == "" {
			panic(r.NewTypeError("expects token string"))
		}

		username := ""
		if f.Argument(1) != goja.Undefined() {
			username = getString(r, f.Argument(1))
		}

		if username == "" {
			username = generateUsername()
		} else if invalidCharsRegex.MatchString(username) {
			panic(r.NewTypeError("expects username to be valid, no spaces or control characters allowed"))
		} else if len(username) > 128 {
			panic(r.NewTypeError("expects id to be valid, must be 1-128 bytes"))
		}

		create := true
		if f.Argument(2) != goja.Undefined() {
			create = getBool(r, f.Argument(2))
		}

		dbUserID, dbUsername, created, err := AuthenticateApple(context.Background(), n.logger, n.db, n.socialClient, n.config.GetSocial().Apple.BundleId, token, username, create)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error authenticating: %v", err.Error())))
		}

		return r.ToValue(map[string]interface{}{
			"user_id":  dbUserID,
			"username": dbUsername,
			"created":  created,
		})
	}
}

func (n *runtimeJavascriptNakamaModule) authenticateCustom(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		id := getString(r, f.Argument(0))
		if id == "" {
			panic(r.NewTypeError("expects id string"))
		} else if invalidCharsRegex.MatchString(id) {
			panic(r.NewTypeError("expects id to be valid, no spaces or control characters allowed"))
		} else if len(id) < 6 || len(id) > 128 {
			panic(r.NewTypeError("expects id to be valid, must be 6-128 bytes"))
		}

		username := ""
		if f.Argument(1) != goja.Undefined() {
			username = getString(r, f.Argument(1))
		}

		if username == "" {
			username = generateUsername()
		} else if invalidCharsRegex.MatchString(username) {
			panic(r.NewTypeError("expects username to be valid, no spaces or control characters allowed"))
		} else if len(username) > 128 {
			panic(r.NewTypeError("expects id to be valid, must be 1-128 bytes"))
		}

		create := true
		if f.Argument(3) != goja.Undefined() {
			create = getBool(r, f.Argument(3))
		}

		dbUserID, dbUsername, created, err := AuthenticateCustom(context.Background(), n.logger, n.db, id, username, create)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error authenticating: %v", err.Error())))
		}

		return r.ToValue(map[string]interface{}{
			"user_id":  dbUserID,
			"username": dbUsername,
			"created":  created,
		})
	}
}

func (n *runtimeJavascriptNakamaModule) authenticateDevice(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		id := getString(r, f.Argument(0))
		if id == "" {
			panic(r.NewTypeError("expects id string"))
		} else if invalidCharsRegex.MatchString(id) {
			panic(r.NewTypeError("expects id to be valid, no spaces or control characters allowed"))
		} else if len(id) < 10 || len(id) > 128 {
			panic(r.NewTypeError("expects id to be valid, must be 10-128 bytes"))
		}

		username := ""
		if f.Argument(1) != goja.Undefined() {
			username = getString(r, f.Argument(1))
		}

		if username == "" {
			username = generateUsername()
		} else if invalidCharsRegex.MatchString(username) {
			panic(r.NewTypeError("expects username to be valid, no spaces or control characters allowed"))
		} else if len(username) > 128 {
			panic(r.NewTypeError("expects id to be valid, must be 1-128 bytes"))
		}

		create := true
		if f.Argument(3) != goja.Undefined() {
			create = getBool(r, f.Argument(3))
		}

		dbUserID, dbUsername, created, err := AuthenticateDevice(context.Background(), n.logger, n.db, id, username, create)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error authenticating: %v", err.Error())))
		}

		return r.ToValue(map[string]interface{}{
			"user_id":  dbUserID,
			"username": dbUsername,
			"created":  created,
		})
	}
}

func (n *runtimeJavascriptNakamaModule) authenticateEmail(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		var attemptUsernameLogin bool
		// Parse email.
		email := getString(r, f.Argument(0))
		if email == "" {
			attemptUsernameLogin = true
		} else if invalidCharsRegex.MatchString(email) {
			panic(r.NewTypeError("expects email to be valid, no spaces or control characters allowed"))
		} else if !emailRegex.MatchString(email) {
			panic(r.NewTypeError("expects email to be valid, invalid email address format"))
		} else if len(email) < 10 || len(email) > 255 {
			panic(r.NewTypeError("expects email to be valid, must be 10-255 bytes"))
		}

		// Parse password.
		password := getString(r, f.Argument(1))
		if password == "" {
			panic(r.NewTypeError("expects password string"))
		} else if len(password) < 8 {
			panic(r.NewTypeError("expects password to be valid, must be longer than 8 characters"))
		}

		username := ""
		if f.Argument(2) != goja.Undefined() {
			username = getString(r, f.Argument(2))
		}

		if username == "" {
			if attemptUsernameLogin {
				panic(r.NewTypeError("expects username string when email is not supplied"))
			}

			username = generateUsername()
		} else if invalidCharsRegex.MatchString(username) {
			panic(r.NewTypeError("expects username to be valid, no spaces or control characters allowed"))
		} else if len(username) > 128 {
			panic(r.NewTypeError("expects id to be valid, must be 1-128 bytes"))
		}

		create := true
		if f.Argument(3) != goja.Undefined() {
			create = getBool(r, f.Argument(3))
		}

		var dbUserID string
		var created bool
		var err error

		if attemptUsernameLogin {
			dbUserID, err = AuthenticateUsername(context.Background(), n.logger, n.db, username, password)
		} else {
			cleanEmail := strings.ToLower(email)

			dbUserID, username, created, err = AuthenticateEmail(context.Background(), n.logger, n.db, cleanEmail, password, username, create)
		}
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error authenticating: %v", err.Error())))
		}

		return r.ToValue(map[string]interface{}{
			"user_id":  dbUserID,
			"username": username,
			"created":  created,
		})
	}
}

func (n *runtimeJavascriptNakamaModule) authenticateFacebook(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		token := getString(r, f.Argument(0))
		if token == "" {
			panic(r.NewTypeError("expects token string"))
		}

		importFriends := true
		if f.Argument(1) != goja.Undefined() {
			importFriends = getBool(r, f.Argument(1))
		}

		username := ""
		if f.Argument(2) != goja.Undefined() {
			username = getString(r, f.Argument(2))
		}

		if username == "" {
			username = generateUsername()
		} else if invalidCharsRegex.MatchString(username) {
			panic(r.NewTypeError("expects username to be valid, no spaces or control characters allowed"))
		} else if len(username) > 128 {
			panic(r.NewTypeError("expects id to be valid, must be 1-128 bytes"))
		}

		create := true
		if f.Argument(3) != goja.Undefined() {
			create = getBool(r, f.Argument(3))
		}

		dbUserID, dbUsername, created, err := AuthenticateFacebook(context.Background(), n.logger, n.db, n.socialClient, token, username, create)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error authenticating: %v", err.Error())))
		}

		if importFriends {
			// Errors are logged before this point and failure here does not invalidate the whole operation.
			_ = importFacebookFriends(context.Background(), n.logger, n.db, n.router, n.socialClient, uuid.FromStringOrNil(dbUserID), dbUsername, token, false)
		}

		return r.ToValue(map[string]interface{}{
			"user_id":  dbUserID,
			"username": username,
			"created":  created,
		})
	}
}

func (n *runtimeJavascriptNakamaModule) authenticateFacebookInstantGame(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		signedPlayerInfo := getString(r, f.Argument(0))
		if signedPlayerInfo == "" {
			panic(r.NewTypeError("expects signed player info"))
		}

		username := ""
		if f.Argument(1) != goja.Undefined() {
			username = getString(r, f.Argument(1))
		}

		if username == "" {
			username = generateUsername()
		} else if invalidCharsRegex.MatchString(username) {
			panic(r.NewTypeError("expects username to be valid, no spaces or control characters allowed"))
		} else if len(username) > 128 {
			panic(r.NewTypeError("expects id to be valid, must be 1-128 bytes"))
		}

		create := true
		if f.Argument(2) != goja.Undefined() {
			create = getBool(r, f.Argument(2))
		}

		dbUserID, dbUsername, created, err := AuthenticateFacebookInstantGame(context.Background(), n.logger, n.db, n.socialClient, n.config.GetSocial().FacebookInstantGame.AppSecret, signedPlayerInfo, username, create)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error authenticating: %v", err.Error())))
		}

		return r.ToValue(map[string]interface{}{
			"user_id":  dbUserID,
			"username": dbUsername,
			"created":  created,
		})
	}
}

func (n *runtimeJavascriptNakamaModule) authenticateGameCenter(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		playerID := getString(r, f.Argument(0))
		if playerID == "" {
			panic(r.NewTypeError("expects player ID string"))
		}
		bundleID := getString(r, f.Argument(1))
		if bundleID == "" {
			panic(r.NewTypeError("expects bundle ID string"))
		}
		ts := getInt(r, f.Argument(2))
		if ts == 0 {
			panic(r.NewTypeError("expects timestamp value"))
		}
		salt := getString(r, f.Argument(3))
		if salt == "" {
			panic(r.NewTypeError("expects salt string"))
		}
		signature := getString(r, f.Argument(4))
		if signature == "" {
			panic(r.NewTypeError("expects signature string"))
		}
		publicKeyURL := getString(r, f.Argument(5))
		if publicKeyURL == "" {
			panic(r.NewTypeError("expects public key URL string"))
		}

		username := ""
		if f.Argument(6) != goja.Undefined() {
			username = getString(r, f.Argument(6))
		}

		if username == "" {
			username = generateUsername()
		} else if invalidCharsRegex.MatchString(username) {
			panic(r.NewTypeError("expects username to be valid, no spaces or control characters allowed"))
		} else if len(username) > 128 {
			panic(r.NewTypeError("expects id to be valid, must be 1-128 bytes"))
		}

		create := true
		if f.Argument(7) != goja.Undefined() {
			create = getBool(r, f.Argument(7))
		}

		dbUserID, dbUsername, created, err := AuthenticateGameCenter(context.Background(), n.logger, n.db, n.socialClient, playerID, bundleID, ts, salt, signature, publicKeyURL, username, create)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error authenticating: %v", err.Error())))
		}

		return r.ToValue(map[string]interface{}{
			"user_id":  dbUserID,
			"username": dbUsername,
			"created":  created,
		})
	}
}

func (n *runtimeJavascriptNakamaModule) authenticateGoogle(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		token := getString(r, f.Argument(0))
		if token == "" {
			panic(r.NewTypeError("expects ID token string"))
		}

		username := ""
		if f.Argument(1) != goja.Undefined() {
			username = getString(r, f.Argument(1))
		}

		if username == "" {
			username = generateUsername()
		} else if invalidCharsRegex.MatchString(username) {
			panic(r.NewTypeError("expects username to be valid, no spaces or control characters allowed"))
		} else if len(username) > 128 {
			panic(r.NewTypeError("expects id to be valid, must be 1-128 bytes"))
		}

		create := true
		if f.Argument(1) != goja.Undefined() {
			create = getBool(r, f.Argument(1))
		}

		dbUserID, dbUsername, created, err := AuthenticateGoogle(context.Background(), n.logger, n.db, n.socialClient, token, username, create)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error authenticating: %v", err.Error())))
		}

		return r.ToValue(map[string]interface{}{
			"user_id":  dbUserID,
			"username": dbUsername,
			"created":  created,
		})
	}
}

func (n *runtimeJavascriptNakamaModule) authenticateSteam(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		if n.config.GetSocial().Steam.PublisherKey == "" || n.config.GetSocial().Steam.AppID == 0 {
			panic(r.ToValue("Steam authentication is not configured"))
		}

		token := getString(r, f.Argument(0))
		if token == "" {
			panic(r.NewTypeError("expects ID token string"))
		}

		username := ""
		if f.Argument(1) != goja.Undefined() {
			username = getString(r, f.Argument(1))
		}

		if username == "" {
			username = generateUsername()
		} else if invalidCharsRegex.MatchString(username) {
			panic(r.NewTypeError("expects username to be valid, no spaces or control characters allowed"))
		} else if len(username) > 128 {
			panic(r.NewTypeError("expects id to be valid, must be 1-128 bytes"))
		}

		create := true
		if f.Argument(1) != goja.Undefined() {
			create = getBool(r, f.Argument(1))
		}

		dbUserID, dbUsername, created, err := AuthenticateSteam(context.Background(), n.logger, n.db, n.socialClient, n.config.GetSocial().Steam.AppID, n.config.GetSocial().Steam.PublisherKey, token, username, create)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error authenticating: %v", err.Error())))
		}

		return r.ToValue(map[string]interface{}{
			"user_id":  dbUserID,
			"username": dbUsername,
			"created":  created,
		})
	}
}

func (n *runtimeJavascriptNakamaModule) authenticateTokenGenerate(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		// Parse input User ID.
		userIDString := getString(r, f.Argument(0))
		if userIDString == "" {
			panic(r.NewTypeError("expects user id"))
		}

		_, err := uuid.FromString(userIDString)
		if err != nil {
			panic(r.NewTypeError("expects valid user id"))
		}

		username := getString(r, f.Argument(1))
		if username == "" {
			panic(r.NewTypeError("expects username"))
		}

		exp := time.Now().UTC().Add(time.Duration(n.config.GetSession().TokenExpirySec) * time.Second).Unix()
		if f.Argument(2) != goja.Undefined() {
			exp = getInt(r, f.Argument(2))
		}

		vars := getStringMap(r, f.Argument(3))

		token, exp := generateTokenWithExpiry(n.config, userIDString, username, vars, exp)

		return r.ToValue(map[string]interface{}{
			"token": token,
			"exp":   exp,
		})
	}
}

func (n *runtimeJavascriptNakamaModule) accountGetId(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getString(r, f.Argument(0))
		if input == "" {
			panic(r.NewTypeError("expects user id"))
		}
		userID, err := uuid.FromString(input)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		account, err := GetAccount(context.Background(), n.logger, n.db, n.tracker, userID)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error getting account: %v", err.Error())))
		}

		accountData, err := getAccountData(account)
		if err != nil {
			panic(r.ToValue(err.Error()))
		}

		return r.ToValue(accountData)
	}
}

func (n *runtimeJavascriptNakamaModule) accountsGetId(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		var input []interface{}
		if f.Argument(0) == goja.Undefined() {
			panic(r.NewTypeError("expects list of user ids"))
		} else {
			var ok bool
			input, ok = f.Argument(0).Export().([]interface{})
			if !ok {
				panic(r.NewTypeError("Invalid argument - user ids must be an array."))
			}
		}

		userIDs := make([]string, 0, len(input))
		for _, userID := range input {
			id, ok := userID.(string)
			if !ok {
				panic(r.NewTypeError(fmt.Sprintf("invalid user id: %v - must be a string", userID)))
			}
			if _, err := uuid.FromString(id); err != nil {
				panic(r.NewTypeError(fmt.Sprintf("invalid user id: %v", userID)))
			}
			userIDs = append(userIDs, id)
		}

		accounts, err := GetAccounts(context.Background(), n.logger, n.db, n.tracker, userIDs)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to get accounts: %s", err.Error())))
		}

		accountsData := make([]map[string]interface{}, 0, len(accounts))
		for _, account := range accounts {
			accountData, err := getAccountData(account)
			if err != nil {
				panic(r.ToValue(err.Error()))
			}
			accountsData = append(accountsData, accountData)
		}

		return r.ToValue(accountsData)
	}
}

func (n *runtimeJavascriptNakamaModule) accountUpdateId(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID, err := uuid.FromString(getString(r, f.Argument(0)))
		if err != nil {
			panic(r.ToValue("expects a valid user id"))
		}

		data, ok := f.Argument(1).Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("expects an object"))
		}

		var username string
		if usernameIn, ok := data["username"]; ok {
			username, ok = usernameIn.(string)
			if !ok {
				panic(r.NewTypeError("expects a string"))
			}
		}

		var displayName *wrappers.StringValue
		if displayNameIn, ok := data["display_name"]; ok {
			displayNameStr, ok := displayNameIn.(string)
			if !ok {
				panic(r.NewTypeError("expects a string"))
			}
			displayName = &wrappers.StringValue{Value: displayNameStr}
		}

		var timezone *wrappers.StringValue
		if timezoneIn, ok := data["timezone"]; ok {
			timezoneStr, ok := timezoneIn.(string)
			if !ok {
				panic(r.NewTypeError("expects a string"))
			}
			timezone = &wrappers.StringValue{Value: timezoneStr}
		}

		var location *wrappers.StringValue
		if locationIn, ok := data["location"]; ok {
			locationStr, ok := locationIn.(string)
			if !ok {
				panic(r.NewTypeError("expects a string"))
			}
			location = &wrappers.StringValue{Value: locationStr}
		}

		var lang *wrappers.StringValue
		if langIn, ok := data["lang_tag"]; ok {
			langStr, ok := langIn.(string)
			if !ok {
				panic(r.NewTypeError("expects a string"))
			}
			lang = &wrappers.StringValue{Value: langStr}
		}

		var avatar *wrappers.StringValue
		if avatarIn, ok := data["avatar_url"]; ok {
			avatarStr, ok := avatarIn.(string)
			if !ok {
				panic(r.NewTypeError("expects a string"))
			}
			avatar = &wrappers.StringValue{Value: avatarStr}
		}

		var metadata *wrappers.StringValue
		if metadataIn, ok := data["metadata"]; ok {
			metadataMap, ok := metadataIn.(map[string]interface{})
			if !ok {
				panic(r.ToValue("expects metadata to be a key value object"))
			}
			metadataBytes, err := json.Marshal(metadataMap)
			if err != nil {
				panic(r.ToValue(fmt.Sprintf("failed to convert metadata: %s", err.Error())))
			}
			metadata = &wrappers.StringValue{Value: string(metadataBytes)}
		}

		if err = UpdateAccounts(context.Background(), n.logger, n.db, []*accountUpdate{{
			userID:      userID,
			username:    username,
			displayName: displayName,
			timezone:    timezone,
			location:    location,
			langTag:     lang,
			avatarURL:   avatar,
			metadata:    metadata,
		}}); err != nil {
			panic(r.ToValue(fmt.Sprintf("error while trying to update user: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) accountDeleteId(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID, err := uuid.FromString(getString(r, f.Argument(0)))
		if err != nil {
			panic("invalid user id")
		}

		recorded := getBool(r, f.Argument(1))

		if err := DeleteAccount(context.Background(), n.logger, n.db, userID, recorded); err != nil {
			panic(r.ToValue(fmt.Sprintf("error while trying to delete account: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) accountExportId(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID, err := uuid.FromString(getString(r, f.Argument(0)))
		if err != nil {
			panic("invalid user id")
		}

		export, err := ExportAccount(context.Background(), n.logger, n.db, userID)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error exporting account: %v", err.Error())))
		}

		exportString, err := n.jsonpbMarshaler.MarshalToString(export)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error encoding account export: %v", err.Error())))
		}

		return r.ToValue(exportString)
	}
}

func (n *runtimeJavascriptNakamaModule) usersGetId(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		var input []interface{}
		if f.Argument(0) == goja.Undefined() {
			panic(r.NewTypeError("expects list of user ids"))
		} else {
			var ok bool
			input, ok = f.Argument(0).Export().([]interface{})
			if !ok {
				panic(r.NewTypeError("Invalid argument - user ids must be an array."))
			}
		}

		userIDs := make([]string, 0, len(input))
		for _, userID := range input {
			id, ok := userID.(string)
			if !ok {
				panic(r.NewTypeError(fmt.Sprintf("invalid user id: %v - must be a string", userID)))
			} else if _, err := uuid.FromString(id); err != nil {
				panic(r.NewTypeError(fmt.Sprintf("invalid user id: %v", userID)))
			}
			userIDs = append(userIDs, id)
		}

		users, err := GetUsers(context.Background(), n.logger, n.db, n.tracker, userIDs, nil, nil)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to get users: %s", err.Error())))
		}

		usersData := make([]map[string]interface{}, 0, len(users.Users))
		for _, user := range users.Users {
			userData, err := getUserData(user)
			if err != nil {
				panic(r.ToValue(err.Error()))
			}
			usersData = append(usersData, userData)
		}

		return r.ToValue(usersData)
	}
}

func (n *runtimeJavascriptNakamaModule) usersGetUsername(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		var input []interface{}
		if f.Argument(0) == goja.Undefined() {
			panic(r.NewTypeError("expects list of usernames"))
		} else {
			var ok bool
			input, ok = f.Argument(0).Export().([]interface{})
			if !ok {
				panic(r.NewTypeError("Invalid argument - usernames must be an array."))
			}
		}

		usernames := make([]string, 0, len(input))
		for _, userID := range input {
			id, ok := userID.(string)
			if !ok {
				panic(r.NewTypeError(fmt.Sprintf("invalid username: %v - must be a string", userID)))
			}
			usernames = append(usernames, id)
		}

		users, err := GetUsers(context.Background(), n.logger, n.db, n.tracker, nil, usernames, nil)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to get users: %s", err.Error())))
		}

		usersData := make([]map[string]interface{}, 0, len(users.Users))
		for _, user := range users.Users {
			userData, err := getUserData(user)
			if err != nil {
				panic(r.ToValue(err.Error()))
			}
			usersData = append(usersData, userData)
		}

		return r.ToValue(usersData)
	}
}

func (n *runtimeJavascriptNakamaModule) usersBanId(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		var input []interface{}
		if f.Argument(0) == goja.Undefined() {
			panic(r.NewTypeError("expects list of user ids"))
		} else {
			var ok bool
			input, ok = f.Argument(0).Export().([]interface{})
			if !ok {
				panic(r.NewTypeError("Invalid argument - user ids must be an array."))
			}
		}

		userIDs := make([]string, 0, len(input))
		for _, userID := range input {
			id, ok := userID.(string)
			if !ok {
				panic(r.NewTypeError(fmt.Sprintf("invalid user id: %v - must be a string", userID)))
			} else if _, err := uuid.FromString(id); err != nil {
				panic(r.NewTypeError(fmt.Sprintf("invalid user id: %v", userID)))
			}
			userIDs = append(userIDs, id)
		}

		err := BanUsers(context.Background(), n.logger, n.db, userIDs)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to ban users: %s", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) usersUnbanId(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		var input []interface{}
		if f.Argument(0) == goja.Undefined() {
			panic(r.NewTypeError("expects list of user ids"))
		} else {
			var ok bool
			input, ok = f.Argument(0).Export().([]interface{})
			if !ok {
				panic(r.NewTypeError("Invalid argument - user ids must be an array."))
			}
		}

		userIDs := make([]string, 0, len(input))
		for _, userID := range input {
			id, ok := userID.(string)
			if !ok {
				panic(r.NewTypeError(fmt.Sprintf("invalid user id: %v - must be a string", userID)))
			} else if _, err := uuid.FromString(id); err != nil {
				panic(r.NewTypeError(fmt.Sprintf("invalid user id: %v", userID)))
			}
			userIDs = append(userIDs, id)
		}

		usernames := make([]string, 0, len(input))
		for _, userID := range input {
			id, ok := userID.(string)
			if !ok {
				panic(r.NewTypeError(fmt.Sprintf("invalid username: %v - must be a string", userID)))
			}
			usernames = append(usernames, id)
		}

		err := UnbanUsers(context.Background(), n.logger, n.db, userIDs)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to unban users: %s", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) linkApple(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		token := getString(r, f.Argument(1))
		if token == "" {
			panic(r.NewTypeError("expects token string"))
		}

		if err := LinkApple(context.Background(), n.logger, n.db, n.config, n.socialClient, id, token); err != nil {
			panic(r.ToValue(fmt.Sprintf("error linking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) linkCustom(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		customID := getString(r, f.Argument(1))
		if customID == "" {
			panic(r.NewTypeError("expects custom ID string"))
		}

		if err := LinkCustom(context.Background(), n.logger, n.db, id, customID); err != nil {
			panic(r.ToValue(fmt.Sprintf("error linking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) linkDevice(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		deviceID := getString(r, f.Argument(1))
		if deviceID == "" {
			panic(r.NewTypeError("expects device ID string"))
		}

		if err := LinkCustom(context.Background(), n.logger, n.db, id, deviceID); err != nil {
			panic(r.ToValue(fmt.Sprintf("error linking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) linkEmail(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		email := getString(r, f.Argument(1))
		if email == "" {
			panic(r.NewTypeError("expects email string"))
		}
		password := getString(r, f.Argument(2))
		if password == "" {
			panic(r.NewTypeError("expects password string"))
		}

		if err := LinkEmail(context.Background(), n.logger, n.db, id, email, password); err != nil {
			panic(r.ToValue(fmt.Sprintf("error linking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) linkFacebook(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		username := getString(r, f.Argument(1))
		if username == "" {
			panic(r.NewTypeError("expects username string"))
		}
		token := getString(r, f.Argument(2))
		if token == "" {
			panic(r.NewTypeError("expects token string"))
		}
		importFriends := true
		if f.Argument(3) != goja.Undefined() {
			importFriends = getBool(r, f.Argument(3))
		}

		if err := LinkFacebook(context.Background(), n.logger, n.db, n.socialClient, n.router, id, username, token, importFriends); err != nil {
			panic(r.ToValue(fmt.Sprintf("error linking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) linkFacebookInstantGame(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		signedPlayerInfo := getString(r, f.Argument(1))
		if signedPlayerInfo == "" {
			panic(r.NewTypeError("expects signed player info string"))
		}

		if err := LinkFacebookInstantGame(context.Background(), n.logger, n.db, n.config, n.socialClient, id, signedPlayerInfo); err != nil {
			panic(r.ToValue(fmt.Sprintf("error linking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) linkGameCenter(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		playerID := getString(r, f.Argument(1))
		if playerID == "" {
			panic(r.NewTypeError("expects player ID string"))
		}
		bundleID := getString(r, f.Argument(2))
		if bundleID == "" {
			panic(r.NewTypeError("expects bundle ID string"))
		}
		ts := getInt(r, f.Argument(3))
		if ts == 0 {
			panic(r.NewTypeError("expects timestamp value"))
		}
		salt := getString(r, f.Argument(4))
		if salt == "" {
			panic(r.NewTypeError("expects salt string"))
		}
		signature := getString(r, f.Argument(5))
		if signature == "" {
			panic(r.NewTypeError("expects signature string"))
		}
		publicKeyURL := getString(r, f.Argument(6))
		if publicKeyURL == "" {
			panic(r.NewTypeError("expects public key URL string"))
		}

		if err := LinkGameCenter(context.Background(), n.logger, n.db, n.socialClient, id, playerID, bundleID, ts, salt, signature, publicKeyURL); err != nil {
			panic(r.ToValue(fmt.Sprintf("error linking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) linkGoogle(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		token := getString(r, f.Argument(1))
		if token == "" {
			panic(r.NewTypeError("expects token string"))
		}

		if err := LinkGoogle(context.Background(), n.logger, n.db, n.socialClient, id, token); err != nil {
			panic(r.ToValue(fmt.Sprintf("error linking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) linkSteam(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		token := getString(r, f.Argument(1))
		if token == "" {
			panic(r.NewTypeError("expects token string"))
		}

		if err := LinkSteam(context.Background(), n.logger, n.db, n.config, n.socialClient, id, token); err != nil {
			panic(r.ToValue(fmt.Sprintf("error linking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) unlinkApple(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		token := getString(r, f.Argument(1))
		if token == "" {
			panic(r.NewTypeError("expects token string"))
		}

		if err := UnlinkApple(context.Background(), n.logger, n.db, n.config, n.socialClient, id, token); err != nil {
			panic(r.ToValue(fmt.Sprintf("error unlinking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) unlinkCustom(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		customID := getString(r, f.Argument(1))
		if customID == "" {
			panic(r.NewTypeError("expects custom ID string"))
		}

		if err := UnlinkCustom(context.Background(), n.logger, n.db, id, customID); err != nil {
			panic(r.ToValue(fmt.Sprintf("error unlinking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) unlinkDevice(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		deviceID := getString(r, f.Argument(1))
		if deviceID == "" {
			panic(r.NewTypeError("expects device ID string"))
		}

		if err := UnlinkDevice(context.Background(), n.logger, n.db, id, deviceID); err != nil {
			panic(r.ToValue(fmt.Sprintf("error unlinking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) unlinkEmail(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		email := getString(r, f.Argument(1))
		if email == "" {
			panic(r.NewTypeError("expects email string"))
		}

		if err := UnlinkEmail(context.Background(), n.logger, n.db, id, email); err != nil {
			panic(r.ToValue(fmt.Sprintf("error unlinking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) unlinkFacebook(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		token := getString(r, f.Argument(1))
		if token == "" {
			panic(r.NewTypeError("expects token string"))
		}

		if err := UnlinkFacebook(context.Background(), n.logger, n.db, n.socialClient, id, token); err != nil {
			panic(r.ToValue(fmt.Sprintf("error unlinking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) unlinkFacebookInstantGame(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		signedPlayerInfo := getString(r, f.Argument(1))
		if signedPlayerInfo == "" {
			panic(r.NewTypeError("expects signed player info string"))
		}

		if err := UnlinkFacebookInstantGame(context.Background(), n.logger, n.db, n.config, n.socialClient, id, signedPlayerInfo); err != nil {
			panic(r.ToValue(fmt.Sprintf("error unlinking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) unlinkGameCenter(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		playerID := getString(r, f.Argument(1))
		if playerID == "" {
			panic(r.NewTypeError("expects player ID string"))
		}
		bundleID := getString(r, f.Argument(2))
		if bundleID == "" {
			panic(r.NewTypeError("expects bundle ID string"))
		}
		ts := getInt(r, f.Argument(3))
		if ts == 0 {
			panic(r.NewTypeError("expects timestamp value"))
		}
		salt := getString(r, f.Argument(4))
		if salt == "" {
			panic(r.NewTypeError("expects salt string"))
		}
		signature := getString(r, f.Argument(5))
		if signature == "" {
			panic(r.NewTypeError("expects signature string"))
		}
		publicKeyURL := getString(r, f.Argument(6))
		if publicKeyURL == "" {
			panic(r.NewTypeError("expects public key URL string"))
		}

		if err := UnlinkGameCenter(context.Background(), n.logger, n.db, n.socialClient, id, playerID, bundleID, ts, salt, signature, publicKeyURL); err != nil {
			panic(r.ToValue(fmt.Sprintf("error unlinking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) unlinkGoogle(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		token := getString(r, f.Argument(1))
		if token == "" {
			panic(r.NewTypeError("expects token string"))
		}

		if err := UnlinkGoogle(context.Background(), n.logger, n.db, n.socialClient, id, token); err != nil {
			panic(r.ToValue(fmt.Sprintf("error unlinking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) unlinkSteam(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userID := getString(r, f.Argument(0))
		id, err := uuid.FromString(userID)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		token := getString(r, f.Argument(1))
		if token == "" {
			panic(r.NewTypeError("expects token string"))
		}

		if err := UnlinkSteam(context.Background(), n.logger, n.db, n.config, n.socialClient, id, token); err != nil {
			panic(r.ToValue(fmt.Sprintf("error unlinking: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) streamUserList(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		streamIn := f.Argument(0)
		if streamIn == goja.Undefined() {
			panic(r.NewTypeError("expects stream object"))
		}
		streamObj, ok := streamIn.Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("expects a stream object"))
		}
		includeHidden := true
		if f.Argument(1) != goja.Undefined() {
			includeHidden = getBool(r, f.Argument(1))
		}
		includeNotHidden := true
		if f.Argument(2) != goja.Undefined() {
			includeNotHidden = getBool(r, f.Argument(2))
		}

		stream := getStreamData(r, streamObj)
		presences := n.tracker.ListByStream(stream, includeHidden, includeNotHidden)

		presencesList := make([]map[string]interface{}, 0, len(presences))
		for _, p := range presences {
			presenceObj := make(map[string]interface{})
			presenceObj["user_id"] = p.UserID.String()
			presenceObj["session_id"] = p.ID.SessionID.String()
			presenceObj["node_id"] = p.ID.Node
			presenceObj["hidden"] = p.Meta.Hidden
			presenceObj["persistence"] = p.Meta.Persistence
			presenceObj["username"] = p.Meta.Username
			presenceObj["status"] = p.Meta.Status
		}

		return r.ToValue(presencesList)
	}
}

func (n *runtimeJavascriptNakamaModule) streamUserGet(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userIDString := getString(r, f.Argument(0))
		if userIDString == "" {
			panic(r.ToValue(r.NewTypeError("expects user id")))
		}
		userID, err := uuid.FromString(userIDString)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		sessionIDString := getString(r, f.Argument(1))
		if sessionIDString == "" {
			panic(r.NewTypeError("expects session id"))
		}
		sessionID, err := uuid.FromString(sessionIDString)
		if err != nil {
			panic(r.NewTypeError("invalid session id"))
		}

		streamIn := f.Argument(2)
		if streamIn == goja.Undefined() {
			panic(r.NewTypeError("expects stream object"))
		}
		streamObj, ok := streamIn.Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("expects a stream object"))
		}

		stream := getStreamData(r, streamObj)
		meta := n.tracker.GetLocalBySessionIDStreamUserID(sessionID, stream, userID)
		if meta == nil {
			return nil
		}

		return r.ToValue(map[string]interface{}{
			"hidden":      meta.Hidden,
			"persistence": meta.Persistence,
			"username":    meta.Username,
			"status":      meta.Status,
		})
	}
}

func (n *runtimeJavascriptNakamaModule) streamUserJoin(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userIDString := getString(r, f.Argument(0))
		if userIDString == "" {
			panic(r.ToValue(r.NewTypeError("expects user id")))
		}
		userID, err := uuid.FromString(userIDString)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		sessionIDString := getString(r, f.Argument(1))
		if sessionIDString == "" {
			panic(r.NewTypeError("expects session id"))
		}
		sessionID, err := uuid.FromString(sessionIDString)
		if err != nil {
			panic(r.NewTypeError("invalid session id"))
		}

		streamIn := f.Argument(2)
		if streamIn == goja.Undefined() {
			panic(r.NewTypeError("expects stream object"))
		}
		streamObj, ok := streamIn.Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("expects a stream object"))
		}

		// By default generate presence events.
		hidden := false
		if f.Argument(3) != goja.Undefined() {
			hidden = getBool(r, f.Argument(3))
		}
		// By default persistence is enabled, if the stream supports it.
		persistence := true
		if f.Argument(4) != goja.Undefined() {
			persistence = getBool(r, f.Argument(4))
		}
		// By default no status is set.
		status := ""
		if f.Argument(5) != goja.Undefined() {
			status = getString(r, f.Argument(5))
		}

		stream := getStreamData(r, streamObj)

		success, newlyTracked, err := n.streamManager.UserJoin(stream, userID, sessionID, hidden, persistence, status)
		if err != nil {
			if err == ErrSessionNotFound {
				panic(r.ToValue("session id does not exist"))
			}
			panic(r.ToValue(fmt.Sprintf("stream user join failed: %v", err.Error())))
		}
		if !success {
			panic(r.ToValue("tracker rejected new presence, session is closing"))
		}

		return r.ToValue(newlyTracked)
	}
}

func (n *runtimeJavascriptNakamaModule) streamUserUpdate(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userIDString := getString(r, f.Argument(0))
		if userIDString == "" {
			panic(r.ToValue(r.NewTypeError("expects user id")))
		}
		userID, err := uuid.FromString(userIDString)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		sessionIDString := getString(r, f.Argument(1))
		if sessionIDString == "" {
			panic(r.NewTypeError("expects session id"))
		}
		sessionID, err := uuid.FromString(sessionIDString)
		if err != nil {
			panic(r.NewTypeError("invalid session id"))
		}

		streamIn := f.Argument(2)
		if streamIn == goja.Undefined() {
			panic(r.NewTypeError("expects stream object"))
		}
		streamObj, ok := streamIn.Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("expects a stream object"))
		}

		// By default generate presence events.
		hidden := false
		if f.Argument(3) != goja.Undefined() {
			hidden = getBool(r, f.Argument(3))
		}
		// By default persistence is enabled, if the stream supports it.
		persistence := true
		if f.Argument(4) != goja.Undefined() {
			persistence = getBool(r, f.Argument(4))
		}
		// By default no status is set.
		status := ""
		if f.Argument(5) != goja.Undefined() {
			status = getString(r, f.Argument(5))
		}

		stream := getStreamData(r, streamObj)

		success, err := n.streamManager.UserUpdate(stream, userID, sessionID, hidden, persistence, status)
		if err != nil {
			if err == ErrSessionNotFound {
				panic(r.ToValue("session id does not exist"))
			}
			panic(r.ToValue(fmt.Sprintf("stream user update failed: %v", err.Error())))
		}
		if !success {
			panic(r.ToValue("tracker rejected updated presence, session is closing"))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) streamUserLeave(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userIDString := getString(r, f.Argument(0))
		if userIDString == "" {
			panic(r.ToValue(r.NewTypeError("expects user id")))
		}
		userID, err := uuid.FromString(userIDString)
		if err != nil {
			panic(r.NewTypeError("invalid user id"))
		}

		sessionIDString := getString(r, f.Argument(1))
		if sessionIDString == "" {
			panic(r.NewTypeError("expects session id"))
		}
		sessionID, err := uuid.FromString(sessionIDString)
		if err != nil {
			panic(r.NewTypeError("invalid session id"))
		}

		streamIn := f.Argument(2)
		if streamIn == goja.Undefined() {
			panic(r.NewTypeError("expects stream object"))
		}
		streamObj, ok := streamIn.Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("expects a stream object"))
		}

		stream := getStreamData(r, streamObj)

		if err := n.streamManager.UserLeave(stream, userID, sessionID); err != nil {
			panic(r.ToValue(fmt.Sprintf("stream user leave failed: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) streamUserKick(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		presenceIn := f.Argument(0)
		if presenceIn == goja.Undefined() {
			panic(r.NewTypeError("expects presence object"))
		}
		presence, ok := presenceIn.Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("expects a presence object"))
		}

		userID := uuid.Nil
		sessionID := uuid.Nil
		node := n.node

		userIDRaw, ok := presence["user_id"]
		if ok {
			userIDString, ok := userIDRaw.(string)
			if !ok {
				panic(r.ToValue("presence user_id must be a string"))
			}
			id, err := uuid.FromString(userIDString)
			if err != nil {
				panic(r.ToValue("invalid user_id"))
			}
			userID = id
		}

		sessionIdRaw, ok := presence["session_id"]
		if ok {
			sessionIDString, ok := sessionIdRaw.(string)
			if !ok {
				panic(r.ToValue("presence session_id must be a string"))
			}
			id, err := uuid.FromString(sessionIDString)
			if err != nil {
				panic(r.ToValue("invalid session_id"))
			}
			sessionID = id
		}

		nodeRaw, ok := presence["node"]
		if ok {
			nodeString, ok := nodeRaw.(string)
			if !ok {
				panic(r.ToValue("expects node to be a string"))
			}
			node = nodeString
		}

		if userID == uuid.Nil || sessionID == uuid.Nil || node == "" {
			panic(r.ToValue("expects each presence to have a valid user_id, session_id, and node"))
		}

		streamIn := f.Argument(1)
		if streamIn == goja.Undefined() {
			panic(r.NewTypeError("expects stream object"))
		}
		streamObj, ok := streamIn.Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("expects a stream object"))
		}

		stream := getStreamData(r, streamObj)

		if err := n.streamManager.UserLeave(stream, userID, sessionID); err != nil {
			panic(r.ToValue(fmt.Sprintf("stream user kick failed: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) streamCount(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		streamIn := f.Argument(0)
		if streamIn == goja.Undefined() {
			panic(r.NewTypeError("expects stream object"))
		}
		streamObj, ok := streamIn.Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("expects a stream object"))
		}

		stream := getStreamData(r, streamObj)

		count := n.tracker.CountByStream(stream)

		return r.ToValue(count)
	}
}

func (n *runtimeJavascriptNakamaModule) streamClose(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		streamIn := f.Argument(0)
		if streamIn == goja.Undefined() {
			panic(r.NewTypeError("expects stream object"))
		}
		streamObj, ok := streamIn.Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("expects a stream object"))
		}

		stream := getStreamData(r, streamObj)

		n.tracker.UntrackByStream(stream)

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) streamSend(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		streamIn := f.Argument(0)
		if streamIn == goja.Undefined() {
			panic(r.NewTypeError("expects stream object"))
		}
		streamObj, ok := streamIn.Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("expects a stream object"))
		}

		stream := getStreamData(r, streamObj)

		data := getString(r, f.Argument(1))

		presencesIn := f.Argument(2)
		var presences []interface{}
		if presencesIn == goja.Undefined() || presencesIn == goja.Null() {
			presences = make([]interface{}, 0)
		} else {
			presences, ok = presencesIn.Export().([]interface{})
			if !ok {
				panic(r.NewTypeError("expects a presences array"))
			}
		}

		presenceIDs := make([]*PresenceID, 0, len(presences))
		for _, presenceRaw := range presences {
			presence, ok := presenceRaw.(map[string]interface{})
			if !ok {
				panic(r.NewTypeError("expects a presence object"))
			}

			presenceID := &PresenceID{}
			sessionIdRaw, ok := presence["session_id"]
			if ok {
				sessionIDString, ok := sessionIdRaw.(string)
				if !ok {
					panic(r.ToValue("presence session_id must be a string"))
				}
				id, err := uuid.FromString(sessionIDString)
				if err != nil {
					panic(r.ToValue("invalid presence session_id"))
				}
				presenceID.SessionID = id
			}

			nodeIDRaw, ok := presence["node_id"]
			if ok {
				nodeString, ok := nodeIDRaw.(string)
				if !ok {
					panic(r.ToValue("expects node id to be a string"))
				}
				presenceID.Node = nodeString
			}

			presenceIDs = append(presenceIDs, presenceID)
		}

		reliable := true
		if f.Argument(3) != goja.Undefined() {
			reliable = getBool(r, f.Argument(3))
		}

		streamWire := &rtapi.Stream{
			Mode:  int32(stream.Mode),
			Label: stream.Label,
		}
		if stream.Subject != uuid.Nil {
			streamWire.Subject = stream.Subject.String()
		}
		if stream.Subcontext != uuid.Nil {
			streamWire.Subcontext = stream.Subcontext.String()
		}
		msg := &rtapi.Envelope{Message: &rtapi.Envelope_StreamData{StreamData: &rtapi.StreamData{
			Stream: streamWire,
			// No sender.
			Data:     data,
			Reliable: reliable,
		}}}

		if len(presenceIDs) == 0 {
			// Sending to whole stream.
			n.router.SendToStream(n.logger, stream, msg, reliable)
		} else {
			// Sending to a subset of stream users.
			n.router.SendToPresenceIDs(n.logger, presenceIDs, msg, reliable)
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) streamSendRaw(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		streamIn := f.Argument(0)
		if streamIn == goja.Undefined() {
			panic(r.NewTypeError("expects stream object"))
		}
		streamObj, ok := streamIn.Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("expects a stream object"))
		}

		stream := getStreamData(r, streamObj)

		envelopeMap, ok := f.Argument(1).Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("expects envelope object"))
		}
		envelopeBytes, err := json.Marshal(envelopeMap)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to convert envelope: %s", err.Error())))
		}

		msg := &rtapi.Envelope{}
		if err = n.jsonpbUnmarshaler.Unmarshal(bytes.NewReader(envelopeBytes), msg); err != nil {
			panic(r.ToValue(fmt.Sprintf("not a valid envelope: %s", err.Error())))
		}

		presencesIn := f.Argument(2)
		var presences []interface{}
		if presencesIn == goja.Undefined() || presencesIn == goja.Null() {
			presences = make([]interface{}, 0)
		} else {
			presences, ok = presencesIn.Export().([]interface{})
			if !ok {
				panic(r.NewTypeError("expects a presences array"))
			}
		}

		presenceIDs := make([]*PresenceID, 0, len(presences))
		for _, presenceRaw := range presences {
			presence, ok := presenceRaw.(map[string]interface{})
			if !ok {
				panic(r.NewTypeError("expects a presence object"))
			}

			presenceID := &PresenceID{}
			sessionIdRaw, ok := presence["session_id"]
			if ok {
				sessionIDString, ok := sessionIdRaw.(string)
				if !ok {
					panic(r.ToValue("presence session_id must be a string"))
				}
				id, err := uuid.FromString(sessionIDString)
				if err != nil {
					panic(r.ToValue("invalid presence session_id"))
				}
				presenceID.SessionID = id
			}

			nodeIDRaw, ok := presence["node_id"]
			if ok {
				nodeString, ok := nodeIDRaw.(string)
				if !ok {
					panic(r.ToValue("expects node id to be a string"))
				}
				presenceID.Node = nodeString
			}

			presenceIDs = append(presenceIDs, presenceID)
		}

		reliable := true
		if f.Argument(3) != goja.Undefined() {
			reliable = getBool(r, f.Argument(3))
		}

		if len(presenceIDs) == 0 {
			// Sending to whole stream.
			n.router.SendToStream(n.logger, stream, msg, reliable)
		} else {
			// Sending to a subset of stream users.
			n.router.SendToPresenceIDs(n.logger, presenceIDs, msg, reliable)
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) sessionDisconnect(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		sessionIDString := getString(r, f.Argument(0))
		if sessionIDString == "" {
			panic(r.NewTypeError("expects a session id"))
		}
		sessionID, err := uuid.FromString(sessionIDString)
		if err != nil {
			panic(r.NewTypeError("expects a valid session id"))
		}

		if err := n.sessionRegistry.Disconnect(context.Background(), sessionID); err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to disconnect: %s", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) matchCreate(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		module := getString(r, f.Argument(0))
		if module == "" {
			panic(r.ToValue("expects module name"))
		}

		params := f.Argument(1)
		var paramsMap map[string]interface{}
		if params == goja.Undefined() {
			paramsMap = make(map[string]interface{})
		} else {
			var ok bool
			paramsMap, ok = params.Export().(map[string]interface{})
			if !ok {
				panic(r.ToValue("expects params to be an object"))
			}
		}

		id, err := n.matchRegistry.CreateMatch(context.Background(), n.logger, n.matchCreateFn, module, paramsMap)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error creating match: %s", err.Error())))
		}

		return r.ToValue(id)
	}
}

func (n *runtimeJavascriptNakamaModule) matchGet(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		id := getString(r, f.Argument(0))

		result, err := n.matchRegistry.GetMatch(context.Background(), id)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to get match: %s", err.Error())))
		}

		matchData := map[string]interface{}{
			"match_id":      result.MatchId,
			"authoritative": result.Authoritative,
			"size":          result.Size,
		}
		if result.Label == nil {
			matchData["label"] = nil
		} else {
			matchData["label"] = result.Label.Value
		}

		return r.ToValue(matchData)
	}
}

func (n *runtimeJavascriptNakamaModule) matchList(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		limit := 1
		if f.Argument(0) != goja.Undefined() {
			limit = int(getInt(r, f.Argument(0)))
		}

		var authoritative *wrappers.BoolValue
		if f.Argument(1) != goja.Undefined() && f.Argument(1) != goja.Null() {
			authoritative = &wrappers.BoolValue{Value: getBool(r, f.Argument(1))}
		}

		var label *wrappers.StringValue
		if f.Argument(2) != goja.Undefined() && f.Argument(2) != goja.Null() {
			label = &wrappers.StringValue{Value: getString(r, f.Argument(2))}
		}

		var minSize *wrappers.Int32Value
		if f.Argument(3) != goja.Undefined() && f.Argument(3) != goja.Null() {
			minSize = &wrappers.Int32Value{Value: int32(getInt(r, f.Argument(3)))}
		}

		var maxSize *wrappers.Int32Value
		if f.Argument(4) != goja.Undefined() && f.Argument(4) != goja.Null() {
			maxSize = &wrappers.Int32Value{Value: int32(getInt(r, f.Argument(4)))}
		}

		var query *wrappers.StringValue
		if f.Argument(5) != goja.Undefined() && f.Argument(5) != goja.Null() {
			query = &wrappers.StringValue{Value: getString(r, f.Argument(5))}
		}

		results, err := n.matchRegistry.ListMatches(context.Background(), limit, authoritative, label, minSize, maxSize, query)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to list matches: %s", err.Error())))
		}

		matches := make([]map[string]interface{}, 0, len(results))
		for _, match := range results {
			matchData := map[string]interface{}{
				"match_id":      match.MatchId,
				"authoritative": match.Authoritative,
				"size":          match.Size,
			}
			if match.Label == nil {
				matchData["label"] = nil
			} else {
				matchData["label"] = match.Label.Value
			}

			matches = append(matches, matchData)
		}

		return r.ToValue(matches)
	}
}

func (n *runtimeJavascriptNakamaModule) notificationSend(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userIDString := getString(r, f.Argument(0))
		userID, err := uuid.FromString(userIDString)
		if err != nil {
			panic(r.NewTypeError("expects valid user id"))
		}

		subject := getString(r, f.Argument(1))
		if subject == "" {
			panic(r.NewTypeError("expects subject to be a non empty string"))
		}

		contentIn := f.Argument(2)
		if contentIn == goja.Undefined() {
			panic(r.NewTypeError("expects content"))
		}
		contentMap, ok := contentIn.Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("expects content to be an object"))
		}
		contentBytes, err := json.Marshal(contentMap)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to convert content: %s", err.Error())))
		}
		content := string(contentBytes)

		code := getInt(r, f.Argument(3))
		if code <= 0 {
			panic(r.ToValue("expects code number to be a positive integer"))
		}

		senderIdIn := f.Argument(4)
		senderID := uuid.Nil.String()
		if senderIdIn != goja.Undefined() && senderIdIn != goja.Null() {
			suid, err := uuid.FromString(getString(r, senderIdIn))
			if err != nil {
				panic(r.NewTypeError("expects sender_id to either be not set, empty string or a valid UUID"))
			}
			senderID = suid.String()
		}

		persistent := false
		if f.Argument(5) != goja.Undefined() {
			persistent = getBool(r, f.Argument(5))
		}

		nots := []*api.Notification{{
			Id:         uuid.Must(uuid.NewV4()).String(),
			Subject:    subject,
			Content:    content,
			Code:       int32(code),
			SenderId:   senderID,
			Persistent: persistent,
			CreateTime: &timestamp.Timestamp{Seconds: time.Now().UTC().Unix()},
		}}
		notifications := map[uuid.UUID][]*api.Notification{
			userID: nots,
		}

		if err := NotificationSend(context.Background(), n.logger, n.db, n.router, notifications); err != nil {
			panic(fmt.Sprintf("failed to send notifications: %s", err.Error()))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) notificationsSend(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		notificationsIn := f.Argument(0)
		if notificationsIn == goja.Undefined() {
			panic(r.NewTypeError("expects a valid set of notifications"))
		}

		notificationsSlice, ok := notificationsIn.Export().([]interface{})
		if !ok {
			panic(r.NewTypeError("expects notifications to be an array"))
		}

		notifications := make(map[uuid.UUID][]*api.Notification)
		for _, notificationRaw := range notificationsSlice {
			notificationObj, ok := notificationRaw.(map[string]interface{})
			if !ok {
				panic(r.NewTypeError("expects notification to be an object"))
			}

			notification := &api.Notification{}
			userID := uuid.Nil
			senderID := uuid.Nil

			var persistent bool
			if _, ok := notificationObj["persistent"]; ok {
				persistent, ok = notificationObj["persistent"].(bool)
				if !ok {
					panic(r.NewTypeError("expects 'persistent' value to be a boolean"))
				}
				notification.Persistent = persistent
			}

			if _, ok := notificationObj["subject"]; ok {
				subject, ok := notificationObj["subject"].(string)
				if !ok {
					panic(r.NewTypeError("expects 'subject' value to be a string"))
				}
				notification.Subject = subject
			}

			if _, ok := notificationObj["content"]; ok {
				content, ok := notificationObj["content"].(map[string]interface{})
				if !ok {
					panic(r.NewTypeError("expects 'content' value to be an object"))
				}
				contentBytes, err := json.Marshal(content)
				if err != nil {
					panic(r.ToValue(fmt.Sprintf("failed to convert content: %s", err.Error())))
				}
				notification.Content = string(contentBytes)
			}

			if _, ok := notificationObj["code"]; ok {
				code, ok := notificationObj["code"].(int32)
				if !ok {
					panic(r.NewTypeError("expects 'code' value to be a number"))
				}
				notification.Code = code
			}

			if _, ok := notificationObj["user_id"]; ok {
				userIDStr, ok := notificationObj["user_id"].(string)
				if !ok {
					panic(r.NewTypeError("expects 'user_id' value to be a string"))
				}
				uid, err := uuid.FromString(userIDStr)
				if err != nil {
					panic(r.NewTypeError("expects 'user_id' value to be a valid id"))
				}
				userID = uid
			}

			if _, ok := notificationObj["sender_id"]; ok {
				senderIDStr, ok := notificationObj["sender_id"].(string)
				if !ok {
					panic(r.NewTypeError("expects 'user_id' value to be a string"))
				}
				uid, err := uuid.FromString(senderIDStr)
				if err != nil {
					panic(r.NewTypeError("expects 'user_id' value to be a valid id"))
				}
				senderID = uid
			}

			if notification.Subject == "" {
				panic(r.NewTypeError("expects subject to be provided and to be non-empty"))
			} else if len(notification.Content) == 0 {
				panic(r.NewTypeError("expects content to be provided and be valid JSON"))
			} else if userID == uuid.Nil {
				panic(r.NewTypeError("expects user_id to be provided and be a valid UUID"))
			} else if notification.Code == 0 {
				panic(r.NewTypeError("expects code to be provided and be a number above 0"))
			}

			notification.Id = uuid.Must(uuid.NewV4()).String()
			notification.CreateTime = &timestamp.Timestamp{Seconds: time.Now().UTC().Unix()}
			notification.SenderId = senderID.String()

			no := notifications[userID]
			if no == nil {
				no = make([]*api.Notification, 0)
			}
			no = append(no, notification)
			notifications[userID] = no
		}

		if err := NotificationSend(context.Background(), n.logger, n.db, n.router, notifications); err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to send notifications: %s", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) walletUpdate(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		uid := getString(r, f.Argument(0))
		if uid == "" {
			panic(r.NewTypeError("expects a valid user id"))
		}
		userID, err := uuid.FromString(uid)
		if err != nil {
			panic(r.NewTypeError("expects a valid user id"))
		}

		changeSetMap, ok := f.Argument(1).Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("expects a changeset object"))
		}
		changeSet := make(map[string]int64)
		for k, v := range changeSetMap {
			i64, ok := v.(int64)
			if !ok {
				panic(r.NewTypeError("expects changeset values to be whole numbers"))
			}
			changeSet[k] = i64
		}

		metadataBytes := []byte("{}")
		metadataIn := f.Argument(2)
		if metadataIn != goja.Undefined() && metadataIn != goja.Null() {
			metadataMap, ok := metadataIn.Export().(map[string]interface{})
			if !ok {
				panic(r.ToValue("expects metadata to be a key value object"))
			}
			metadataBytes, err = json.Marshal(metadataMap)
			if err != nil {
				panic(r.ToValue(fmt.Sprintf("failed to convert metadata: %s", err.Error())))
			}
		}

		updateLedger := true
		if f.Argument(3) != goja.Undefined() {
			updateLedger = getBool(r, f.Argument(3))
		}

		results, err := UpdateWallets(context.Background(), n.logger, n.db, []*walletUpdate{{
			UserID:    userID,
			Changeset: changeSet,
			Metadata:  string(metadataBytes),
		}}, updateLedger)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to update user wallet: %s", err.Error())))
		}

		if len(results) == 0 {
			return goja.Null()
		}

		return r.ToValue(map[string]interface{}{
			"updated":  results[0].Updated,
			"previous": results[0].Previous,
		})
	}
}

func (n *runtimeJavascriptNakamaModule) walletsUpdate(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		updatesIn, ok := f.Argument(0).Export().([]interface{})
		if !ok {
			panic(r.ToValue("expects an array of wallet update objects"))
		}

		updates := make([]*walletUpdate, 0, len(updatesIn))
		for _, updateIn := range updatesIn {
			updateMap, ok := updateIn.(map[string]interface{})
			if !ok {
				panic(r.ToValue("expects an update to be a wallet update object"))
			}

			update := &walletUpdate{}

			uidRaw, ok := updateMap["user_id"]
			if !ok {
				panic(r.NewTypeError("expects a user id"))
			}
			uid, ok := uidRaw.(string)
			if !ok {
				panic(r.NewTypeError("expects a valid user id"))
			}
			userID, err := uuid.FromString(uid)
			if err != nil {
				panic(r.NewTypeError("expects a valid user id"))
			}
			update.UserID = userID

			changeSetRaw, ok := updateMap["changeset"]
			if !ok {
				panic(r.NewTypeError("expects changeset object"))
			}
			changeSetMap, ok := changeSetRaw.(map[string]interface{})
			if !ok {
				panic(r.NewTypeError("expects changeset object"))
			}
			changeSet := make(map[string]int64)
			for k, v := range changeSetMap {
				i64, ok := v.(int64)
				if !ok {
					panic(r.NewTypeError("expects changeset values to be whole numbers"))
				}
				changeSet[k] = i64
			}
			update.Changeset = changeSet

			metadataBytes := []byte("{}")
			metadataRaw, ok := updateMap["metadata"]
			if ok {
				metadataMap, ok := metadataRaw.(map[string]interface{})
				if !ok {
					panic(r.NewTypeError("expects metadata object"))
				}
				metadataBytes, err = json.Marshal(metadataMap)
				if err != nil {
					panic(r.ToValue(fmt.Sprintf("failed to convert metadata: %s", err.Error())))
				}
			}
			update.Metadata = string(metadataBytes)

			updates = append(updates, update)
		}

		updateLedger := false
		if f.Argument(1) != goja.Undefined() {
			updateLedger = getBool(r, f.Argument(1))
		}

		results, err := UpdateWallets(context.Background(), n.logger, n.db, updates, updateLedger)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to update user wallet: %s", err.Error())))
		}

		retResults := make([]map[string]interface{}, 0, len(results))
		for _, r := range results {
			retResults = append(retResults,
				map[string]interface{}{
					"updated":  r.Updated,
					"previous": r.Previous,
				},
			)
		}

		return r.ToValue(retResults)
	}
}

func (n *runtimeJavascriptNakamaModule) walletLedgerUpdate(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		// Parse ledger ID.
		id := getString(r, f.Argument(0))
		if id == "" {
			panic(r.NewTypeError("expects a valid id"))
		}
		itemID, err := uuid.FromString(id)
		if err != nil {
			panic(r.NewTypeError("expects a valid id"))
		}

		metadataBytes := []byte("{}")
		metadataMap, ok := f.Argument(1).Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("expects metadata object"))
		}
		metadataBytes, err = json.Marshal(metadataMap)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to convert metadata: %s", err.Error())))
		}
		item, err := UpdateWalletLedger(context.Background(), n.logger, n.db, itemID, string(metadataBytes))
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to update user wallet ledger: %s", err.Error())))
		}

		return r.ToValue(map[string]interface{}{
			"id":          id,
			"user_id":     item.UserID,
			"create_time": item.CreateTime,
			"update_time": item.UpdateTime,
			"changeset":   metadataMap,
			"metadata":    item.Metadata,
		})
	}
}

func (n *runtimeJavascriptNakamaModule) walletLedgerList(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		id := getString(r, f.Argument(0))
		if id == "" {
			panic(r.NewTypeError("expects a valid user id"))
		}
		userID, err := uuid.FromString(id)
		if err != nil {
			panic(r.NewTypeError("expects a valid user id"))
		}

		limit := 100
		if f.Argument(1) != goja.Undefined() {
			limit = int(getInt(r, f.Argument(1)))
		}

		cursor := ""
		if f.Argument(2) != goja.Undefined() {
			cursor = getString(r, f.Argument(2))
		}

		items, newCursor, err := ListWalletLedger(context.Background(), n.logger, n.db, userID, &limit, cursor)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to retrieve user wallet ledger: %s", err.Error())))
		}

		results := make([]interface{}, 0, len(items))
		for _, item := range items {
			results = append(results, map[string]interface{}{
				"id":          item.ID,
				"user_id":     id,
				"create_time": item.CreateTime,
				"update_time": item.UpdateTime,
				"changeset":   item.Changeset,
				"metadata":    item.Metadata,
			})
		}

		returnObj := map[string]interface{}{
			"items": results,
		}
		if newCursor == "" {
			returnObj["cursor"] = nil
		} else {
			returnObj["cursor"] = newCursor
		}

		return r.ToValue(returnObj)
	}
}

func (n *runtimeJavascriptNakamaModule) storageList(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		userIDString := ""
		if f.Argument(0) != goja.Undefined() {
			userIDString = getString(r, f.Argument(0))
		}
		uid, err := uuid.FromString(userIDString)
		if err != nil {
			panic(r.NewTypeError("expects empty or valid user id"))
		}

		collection := ""
		if f.Argument(1) != goja.Undefined() {
			collection = getString(r, f.Argument(1))
		}

		limit := 100
		if f.Argument(2) != goja.Undefined() {
			limit = int(getInt(r, f.Argument(2)))
		}

		cursor := ""
		if f.Argument(3) != goja.Undefined() {
			cursor = getString(r, f.Argument(3))
		}

		objectList, _, err := StorageListObjects(context.Background(), n.logger, n.db, uuid.Nil, &uid, collection, limit, cursor)

		objects := make([]interface{}, 0, len(objectList.Objects))
		for _, o := range objectList.Objects {
			objectMap := make(map[string]interface{})
			objectMap["key"] = o.Key
			objectMap["collection"] = o.Collection
			if o.UserId != "" {
				objectMap["user_id"] = o.UserId
			} else {
				objectMap["user_id"] = nil
			}
			objectMap["version"] = o.Version
			objectMap["permission_read"] = o.PermissionRead
			objectMap["permission_write"] = o.PermissionWrite
			objectMap["create_time"] = o.CreateTime.Seconds
			objectMap["update_time"] = o.UpdateTime.Seconds

			valueMap := make(map[string]interface{})
			err = json.Unmarshal([]byte(o.Value), &valueMap)
			if err != nil {
				panic(r.ToValue(fmt.Sprintf("failed to convert value to json: %s", err.Error())))
			}
			objectMap["value"] = valueMap

			objects = append(objects, objectMap)
		}

		returnObj := map[string]interface{}{
			"items": objects,
		}
		if cursor == "" {
			returnObj["cursor"] = nil
		} else {
			returnObj["cursor"] = cursor
		}

		return r.ToValue(returnObj)
	}
}

func (n *runtimeJavascriptNakamaModule) storageRead(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		keysIn := f.Argument(0)
		if keysIn == goja.Undefined() {
			panic(r.ToValue("expects an array ok keys"))
		}

		keysSlice, ok := keysIn.Export().([]interface{})
		if !ok {
			panic(r.ToValue("expects an array of keys"))
		}

		if len(keysSlice) == 0 {
			return r.ToValue([]interface{}{})
		}

		objectIDs := make([]*api.ReadStorageObjectId, 0, len(keysSlice))
		for _, obj := range keysSlice {
			objMap, ok := obj.(map[string]interface{})
			if !ok {
				panic(r.ToValue("expects an object"))
			}

			objectID := &api.ReadStorageObjectId{}

			if collectionIn, ok := objMap["collection"]; ok {
				collection, ok := collectionIn.(string)
				if !ok {
					panic(r.NewTypeError("expects 'collection' value to be a string"))
				}
				if collectionIn == "" {
					panic(r.NewTypeError("expects 'collection' value to be a non empty string"))
				}
				objectID.Collection = collection
			}

			if keyIn, ok := objMap["key"]; ok {
				key, ok := keyIn.(string)
				if !ok {
					panic(r.NewTypeError("expects 'key' value to be a string"))
				}
				objectID.Key = key
			}

			if userID, ok := objMap["user_id"]; ok {
				userIDStr, ok := userID.(string)
				if !ok {
					panic(r.NewTypeError("expects 'user_id' value to be a string"))
				}
				_, err := uuid.FromString(userIDStr)
				if err != nil {
					panic(r.NewTypeError("expects 'user_id' value to be a valid id"))
				}
				objectID.UserId = userIDStr
			}

			if objectID.UserId == "" {
				// Default to server-owned data if no owner is supplied.
				objectID.UserId = uuid.Nil.String()
			}

			objectIDs = append(objectIDs, objectID)
		}

		objects, err := StorageReadObjects(context.Background(), n.logger, n.db, uuid.Nil, objectIDs)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to read storage objects: %s", err.Error())))
		}

		results := make([]interface{}, 0, len(objects.Objects))
		for _, o := range objects.GetObjects() {
			oMap := make(map[string]interface{})

			oMap["key"] = o.Key
			oMap["collection"] = o.Collection
			if o.UserId != "" {
				oMap["user_id"] = o.UserId
			} else {
				oMap["user_id"] = nil
			}
			oMap["version"] = o.Version
			oMap["permission_read"] = o.PermissionRead
			oMap["permission_write"] = o.PermissionWrite
			oMap["create_time"] = o.CreateTime.Seconds
			oMap["update_time"] = o.UpdateTime.Seconds

			valueMap := make(map[string]interface{})
			err = json.Unmarshal([]byte(o.Value), &valueMap)
			if err != nil {
				panic(r.ToValue(fmt.Sprintf("failed to convert value to json: %s", err.Error())))
			}
			oMap["value"] = valueMap

			results = append(results, oMap)
		}

		return r.ToValue(results)
	}
}

func (n *runtimeJavascriptNakamaModule) storageWrite(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		data := f.Argument(0)
		if data == goja.Undefined() {
			panic(r.ToValue("expects a valid array of data"))
		}
		dataSlice, ok := data.Export().([]interface{})
		if !ok {
			panic(r.ToValue(r.NewTypeError("expects a valid array of data")))
		}

		ops := make(StorageOpWrites, 0, len(dataSlice))
		for _, data := range dataSlice {
			dataMap, ok := data.(map[string]interface{})
			if !ok {
				panic(r.NewTypeError("expects a data entry to be an object"))
			}

			var userID uuid.UUID
			writeOp := &api.WriteStorageObject{}

			if collectionIn, ok := dataMap["collectionIn"]; ok {
				collection, ok := collectionIn.(string)
				if !ok {
					panic(r.NewTypeError("expects 'collection' value to be a string"))
				}
				if collection == "" {
					panic(r.NewTypeError("expects 'collection' value to be non-empty"))
				}
				writeOp.Collection = collection
			}

			if keyIn, ok := dataMap["key"]; ok {
				key, ok := keyIn.(string)
				if !ok {
					panic(r.NewTypeError("expects 'key' value to be a string"))
				}
				if key == "" {
					panic(r.NewTypeError("expects 'key' value to be non-empty"))
				}
				writeOp.Key = key
			}

			if userID, ok := dataMap["user_id"]; ok {
				userIDStr, ok := userID.(string)
				if !ok {
					panic(r.NewTypeError("expects 'user_id' value to be a string"))
				}
				var err error
				userID, err = uuid.FromString(userIDStr)
				if err != nil {
					panic(r.NewTypeError("expects 'user_id' value to be a valid id"))
				}
			}

			if valueIn, ok := dataMap["value"]; ok {
				valueMap, ok := valueIn.(map[string]interface{})
				if !ok {
					panic(r.NewTypeError("expects 'value' value to be an object"))
				}
				valueBytes, err := json.Marshal(valueMap)
				if err != nil {
					panic(r.ToValue(fmt.Sprintf("failed to convert value: %s", err.Error())))
				}
				writeOp.Value = string(valueBytes)
			}

			if versionIn, ok := dataMap["version"]; ok {
				version, ok := versionIn.(string)
				if !ok {
					panic(r.NewTypeError("expects 'version' value to be a string"))
				}
				if version == "" {
					panic(r.NewTypeError("expects 'version' value to be a non-empty string"))
				}
				writeOp.Version = version
			}

			if permissionReadIn, ok := dataMap["permission_read"]; ok {
				permissionRead, ok := permissionReadIn.(int64)
				if !ok {
					panic(r.NewTypeError("expects 'permission_read' value to be a number"))
				}
				writeOp.PermissionRead = &wrappers.Int32Value{Value: int32(permissionRead)}
			} else {
				writeOp.PermissionRead = &wrappers.Int32Value{Value: 1}
			}

			if permissionWriteIn, ok := dataMap["permission_write"]; ok {
				permissionWrite, ok := permissionWriteIn.(int64)
				if !ok {
					panic(r.NewTypeError("expects 'permission_write' value to be a number"))
				}
				writeOp.PermissionWrite = &wrappers.Int32Value{Value: int32(permissionWrite)}
			} else {
				writeOp.PermissionWrite = &wrappers.Int32Value{Value: 1}
			}

			if writeOp.Collection == "" {
				panic(r.NewTypeError("expects collection to be supplied"))
			} else if writeOp.Key == "" {
				panic(r.NewTypeError("expects key to be supplied"))
			} else if writeOp.Value == "" {
				panic(r.NewTypeError("expects value to be supplied"))
			}

			ops = append(ops, &StorageOpWrite{
				OwnerID: userID.String(),
				Object:  writeOp,
			})
		}

		acks, _, err := StorageWriteObjects(context.Background(), n.logger, n.db, true, ops)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to write storage objects: %s", err.Error())))
		}

		results := make([]interface{}, 0, len(acks.Acks))
		for _, ack := range acks.Acks {
			result := make(map[string]interface{})
			result["key"] = ack.Key
			result["collection"] = ack.Collection
			if ack.UserId != "" {
				result["user_id"] = ack.UserId
			} else {
				result["user_id"] = nil
			}
			result["version"] = ack.Version

			results = append(results, result)
		}

		return r.ToValue(results)
	}
}

func (n *runtimeJavascriptNakamaModule) storageDelete(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		keysIn := f.Argument(0)
		if keysIn == goja.Undefined() {
			panic(r.ToValue("expects an array ok keys"))
		}
		keysSlice, ok := keysIn.Export().([]interface{})
		if !ok {
			panic(r.ToValue("expects an array of keys"))
		}

		ops := make(StorageOpDeletes, 0, len(keysSlice))
		for _, data := range keysSlice {
			dataMap, ok := data.(map[string]interface{})
			if !ok {
				panic(r.NewTypeError("expects a data entry to be an object"))
			}

			var userID uuid.UUID
			objectID := &api.DeleteStorageObjectId{}

			if collectionIn, ok := dataMap["collectionIn"]; ok {
				collection, ok := collectionIn.(string)
				if !ok {
					panic(r.NewTypeError("expects 'collection' value to be a string"))
				}
				if collection == "" {
					panic(r.NewTypeError("expects 'collection' value to be non-empty"))
				}
				objectID.Collection = collection
			}

			if keyIn, ok := dataMap["key"]; ok {
				key, ok := keyIn.(string)
				if !ok {
					panic(r.NewTypeError("expects 'key' value to be a string"))
				}
				if key == "" {
					panic(r.NewTypeError("expects 'key' value to be non-empty"))
				}
				objectID.Key = key
			}

			if userID, ok := dataMap["user_id"]; ok {
				userIDStr, ok := userID.(string)
				if !ok {
					panic(r.NewTypeError("expects 'user_id' value to be a string"))
				}
				var err error
				userID, err = uuid.FromString(userIDStr)
				if err != nil {
					panic(r.NewTypeError("expects 'user_id' value to be a valid id"))
				}
			}

			if versionIn, ok := dataMap["version"]; ok {
				version, ok := versionIn.(string)
				if !ok {
					panic(r.NewTypeError("expects 'version' value to be a string"))
				}
				if version == "" {
					panic(r.NewTypeError("expects 'version' value to be a non-empty string"))
				}
				objectID.Version = version
			}

			if objectID.Collection == "" {
				panic(r.NewTypeError("expects collection to be supplied"))
			} else if objectID.Key == "" {
				panic(r.NewTypeError("expects key to be supplied"))
			}

			ops = append(ops, &StorageOpDelete{
				OwnerID:  userID.String(),
				ObjectID: objectID,
			})
		}

		if _, err := StorageDeleteObjects(context.Background(), n.logger, n.db, true, ops); err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to remove storage: %s", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) multiUpdate(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		returnObj := make(map[string]interface{})

		// Process account update inputs.
		var accountUpdates []*accountUpdate
		if f.Argument(0) != goja.Undefined() && f.Argument(0) != goja.Null() {
			accountUpdatesSlice, ok := f.Argument(0).Export().([]interface{})
			if !ok {
				panic(r.ToValue("expects an array of account updates"))
			}

			accountUpdates = make([]*accountUpdate, 0, len(accountUpdatesSlice))
			for _, accUpdate := range accountUpdatesSlice {
				accUpdateObj, ok := accUpdate.(map[string]interface{})
				if !ok {
					panic(r.NewTypeError("expects an account update object"))
				}

				update := &accountUpdate{}
				if userIDIn, ok := accUpdateObj["user_id"]; ok {
					userIDStr, ok := userIDIn.(string)
					if !ok {
						panic(r.NewTypeError("expects 'user_id' value to be a string"))
					}
					uid, err := uuid.FromString(userIDStr)
					if err != nil {
						panic(r.NewTypeError("expects 'user_id' value to be a valid id"))
					}
					update.userID = uid
				}

				if usernameIn, ok := accUpdateObj["username"]; ok {
					username, ok := usernameIn.(string)
					if !ok {
						panic(r.NewTypeError("expects a string"))
					}
					update.username = username
				}

				if displayNameIn, ok := accUpdateObj["display_name"]; ok {
					displayNameStr, ok := displayNameIn.(string)
					if !ok {
						panic(r.NewTypeError("expects a string"))
					}
					update.displayName = &wrappers.StringValue{Value: displayNameStr}
				}

				if timezoneIn, ok := accUpdateObj["timezone"]; ok {
					timezoneStr, ok := timezoneIn.(string)
					if !ok {
						panic(r.NewTypeError("expects a string"))
					}
					update.timezone = &wrappers.StringValue{Value: timezoneStr}
				}

				if locationIn, ok := accUpdateObj["location"]; ok {
					locationStr, ok := locationIn.(string)
					if !ok {
						panic(r.NewTypeError("expects a string"))
					}
					update.location = &wrappers.StringValue{Value: locationStr}
				}

				if langIn, ok := accUpdateObj["lang_tag"]; ok {
					langStr, ok := langIn.(string)
					if !ok {
						panic(r.NewTypeError("expects a string"))
					}
					update.langTag = &wrappers.StringValue{Value: langStr}
				}

				if avatarIn, ok := accUpdateObj["avatar_url"]; ok {
					avatarStr, ok := avatarIn.(string)
					if !ok {
						panic(r.NewTypeError("expects a string"))
					}
					update.avatarURL = &wrappers.StringValue{Value: avatarStr}
				}

				if metadataIn, ok := accUpdateObj["metadata"]; ok {
					metadataMap, ok := metadataIn.(map[string]interface{})
					if !ok {
						panic(r.ToValue("expects metadata to be a key value object"))
					}
					metadataBytes, err := json.Marshal(metadataMap)
					if err != nil {
						panic(r.ToValue(fmt.Sprintf("failed to convert metadata: %s", err.Error())))
					}
					update.metadata = &wrappers.StringValue{Value: string(metadataBytes)}
				}

				accountUpdates = append(accountUpdates, update)
			}

			// Process storage update inputs.
			var storageWriteOps StorageOpWrites
			if f.Argument(1) != goja.Undefined() && f.Argument(1) != goja.Null() {
				data := f.Argument(1)
				dataSlice, ok := data.Export().([]interface{})
				if !ok {
					panic(r.ToValue(r.NewTypeError("expects a valid array of data")))
				}

				storageWriteOps = make(StorageOpWrites, 0, len(dataSlice))
				for _, data := range dataSlice {
					dataMap, ok := data.(map[string]interface{})
					if !ok {
						panic(r.NewTypeError("expects a data entry to be an object"))
					}

					var userID uuid.UUID
					writeOp := &api.WriteStorageObject{}

					if collectionIn, ok := dataMap["collectionIn"]; ok {
						collection, ok := collectionIn.(string)
						if !ok {
							panic(r.NewTypeError("expects 'collection' value to be a string"))
						}
						if collection == "" {
							panic(r.NewTypeError("expects 'collection' value to be non-empty"))
						}
						writeOp.Collection = collection
					}

					if keyIn, ok := dataMap["key"]; ok {
						key, ok := keyIn.(string)
						if !ok {
							panic(r.NewTypeError("expects 'key' value to be a string"))
						}
						if key == "" {
							panic(r.NewTypeError("expects 'key' value to be non-empty"))
						}
						writeOp.Key = key
					}

					if userID, ok := dataMap["user_id"]; ok {
						userIDStr, ok := userID.(string)
						if !ok {
							panic(r.NewTypeError("expects 'user_id' value to be a string"))
						}
						var err error
						userID, err = uuid.FromString(userIDStr)
						if err != nil {
							panic(r.NewTypeError("expects 'user_id' value to be a valid id"))
						}
					}

					if valueIn, ok := dataMap["value"]; ok {
						valueMap, ok := valueIn.(map[string]interface{})
						if !ok {
							panic(r.NewTypeError("expects 'value' value to be an object"))
						}
						valueBytes, err := json.Marshal(valueMap)
						if err != nil {
							panic(r.ToValue(fmt.Sprintf("failed to convert value: %s", err.Error())))
						}
						writeOp.Value = string(valueBytes)
					}

					if versionIn, ok := dataMap["version"]; ok {
						version, ok := versionIn.(string)
						if !ok {
							panic(r.NewTypeError("expects 'version' value to be a string"))
						}
						if version == "" {
							panic(r.NewTypeError("expects 'version' value to be a non-empty string"))
						}
						writeOp.Version = version
					}

					if permissionReadIn, ok := dataMap["permission_read"]; ok {
						permissionRead, ok := permissionReadIn.(int64)
						if !ok {
							panic(r.NewTypeError("expects 'permission_read' value to be a number"))
						}
						writeOp.PermissionRead = &wrappers.Int32Value{Value: int32(permissionRead)}
					} else {
						writeOp.PermissionRead = &wrappers.Int32Value{Value: 1}
					}

					if permissionWriteIn, ok := dataMap["permission_write"]; ok {
						permissionWrite, ok := permissionWriteIn.(int64)
						if !ok {
							panic(r.NewTypeError("expects 'permission_write' value to be a number"))
						}
						writeOp.PermissionWrite = &wrappers.Int32Value{Value: int32(permissionWrite)}
					} else {
						writeOp.PermissionWrite = &wrappers.Int32Value{Value: 1}
					}

					if writeOp.Collection == "" {
						panic(r.NewTypeError("expects collection to be supplied"))
					} else if writeOp.Key == "" {
						panic(r.NewTypeError("expects key to be supplied"))
					} else if writeOp.Value == "" {
						panic(r.NewTypeError("expects value to be supplied"))
					}

					storageWriteOps = append(storageWriteOps, &StorageOpWrite{
						OwnerID: userID.String(),
						Object:  writeOp,
					})
				}

				acks, _, err := StorageWriteObjects(context.Background(), n.logger, n.db, true, storageWriteOps)
				if err != nil {
					panic(r.ToValue(fmt.Sprintf("failed to write storage objects: %s", err.Error())))
				}

				storgeWritesResults := make([]interface{}, 0, len(acks.Acks))
				for _, ack := range acks.Acks {
					result := make(map[string]interface{})
					result["key"] = ack.Key
					result["collection"] = ack.Collection
					if ack.UserId != "" {
						result["user_id"] = ack.UserId
					} else {
						result["user_id"] = nil
					}
					result["version"] = ack.Version

					storgeWritesResults = append(storgeWritesResults, result)
				}

				returnObj["storage_write_acks"] = storgeWritesResults
			}

			// Process wallet update inputs.
			var walletUpdates []*walletUpdate
			if f.Argument(2) != goja.Undefined() && f.Argument(2) != goja.Null() {
				updatesIn, ok := f.Argument(0).Export().([]interface{})
				if !ok {
					panic(r.ToValue("expects an array of wallet update objects"))
				}

				walletUpdates = make([]*walletUpdate, 0, len(updatesIn))
				for _, updateIn := range updatesIn {
					updateMap, ok := updateIn.(map[string]interface{})
					if !ok {
						panic(r.ToValue("expects an update to be a wallet update object"))
					}

					update := &walletUpdate{}

					uidRaw, ok := updateMap["user_id"]
					if !ok {
						panic(r.NewTypeError("expects a user id"))
					}
					uid, ok := uidRaw.(string)
					if !ok {
						panic(r.NewTypeError("expects a valid user id"))
					}
					userID, err := uuid.FromString(uid)
					if err != nil {
						panic(r.NewTypeError("expects a valid user id"))
					}
					update.UserID = userID

					changeSetRaw, ok := updateMap["changeset"]
					if !ok {
						panic(r.NewTypeError("expects changeset object"))
					}
					changeSetMap, ok := changeSetRaw.(map[string]interface{})
					if !ok {
						panic(r.NewTypeError("expects changeset object"))
					}
					changeSet := make(map[string]int64)
					for k, v := range changeSetMap {
						i64, ok := v.(int64)
						if !ok {
							panic(r.NewTypeError("expects changeset values to be whole numbers"))
						}
						changeSet[k] = i64
					}
					update.Changeset = changeSet

					metadataBytes := []byte("{}")
					metadataRaw, ok := updateMap["metadata"]
					if ok {
						metadataMap, ok := metadataRaw.(map[string]interface{})
						if !ok {
							panic(r.NewTypeError("expects metadata object"))
						}
						metadataBytes, err = json.Marshal(metadataMap)
						if err != nil {
							panic(r.ToValue(fmt.Sprintf("failed to convert metadata: %s", err.Error())))
						}
					}
					update.Metadata = string(metadataBytes)

					walletUpdates = append(walletUpdates, update)
				}
			}

			updateLedger := false
			if f.Argument(3) == goja.Undefined() || f.Argument(3) == goja.Null() {
				updateLedger = getBool(r, f.Argument(3))
			}

			results, err := UpdateWallets(context.Background(), n.logger, n.db, walletUpdates, updateLedger)
			if err != nil {
				panic(r.ToValue(fmt.Sprintf("failed to update user wallet: %s", err.Error())))
			}

			updateWalletResults := make([]map[string]interface{}, 0, len(results))
			for _, r := range results {
				updateWalletResults = append(updateWalletResults,
					map[string]interface{}{
						"updated":  r.Updated,
						"previous": r.Previous,
					},
				)
			}
			returnObj["wallet_update_acks"] = updateWalletResults
		}

		return r.ToValue(returnObj)
	}
}

func (n *runtimeJavascriptNakamaModule) leaderboardCreate(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		id := getString(r, f.Argument(0))
		if id == "" {
			panic(r.NewTypeError("expects a leaderboard ID string"))
		}

		authoritative := false
		if f.Argument(1) != goja.Undefined() {
			authoritative = getBool(r, f.Argument(1))
		}

		sortOrder := "desc"
		if f.Argument(2) != goja.Undefined() {
			sortOrder = getString(r, f.Argument(2))
		}

		var sortOrderNumber int
		switch sortOrder {
		case "asc":
			sortOrderNumber = LeaderboardSortOrderAscending
		case "desc":
			sortOrderNumber = LeaderboardSortOrderDescending
		default:
			panic(r.NewTypeError("expects sort order to be 'asc' or 'desc'"))
		}

		operator := "best"
		if f.Argument(3) != goja.Undefined() {
			operator = getString(r, f.Argument(3))
		}
		var operatorNumber int
		switch operator {
		case "best":
			operatorNumber = LeaderboardOperatorBest
		case "set":
			operatorNumber = LeaderboardOperatorSet
		case "incr":
			operatorNumber = LeaderboardOperatorIncrement
		default:
			panic(r.NewTypeError("expects sort order to be 'best', 'set', or 'incr'"))
		}

		resetSchedule := ""
		if f.Argument(4) != goja.Undefined() && f.Argument(4) != goja.Null() {
			resetSchedule = getString(r, f.Argument(4))
		}
		if resetSchedule != "" {
			if _, err := cronexpr.Parse(resetSchedule); err != nil {
				panic(r.NewTypeError("expects reset schedule to be a valid CRON expression"))
			}
		}

		metadataStr := "{}"
		if f.Argument(5) != goja.Undefined() {
			metadataMap, ok := f.Argument(5).Export().(map[string]interface{})
			if !ok {
				panic(r.NewTypeError("expects metadata to be an object"))
			}
			metadataBytes, err := json.Marshal(metadataMap)
			if err != nil {
				panic(r.NewTypeError(fmt.Sprintf("error encoding metadata: %v", err.Error())))
			}
			metadataStr = string(metadataBytes)
		}

		if _, err := n.leaderboardCache.Create(context.Background(), id, authoritative, sortOrderNumber, operatorNumber, resetSchedule, metadataStr); err != nil {
			panic(r.ToValue(fmt.Sprintf("error creating leaderboard: %v", err.Error())))
		}

		n.leaderboardScheduler.Update()

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) leaderboardDelete(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		id := getString(r, f.Argument(0))
		if id == "" {
			panic(r.NewTypeError("expects a leaderboard ID string"))
		}

		if err := n.leaderboardCache.Delete(context.Background(), id); err != nil {
			panic(r.ToValue(fmt.Sprintf("error deleting leaderboard: %v", err.Error())))
		}

		n.leaderboardScheduler.Update()

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) leaderboardRecordsList(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		id := getString(r, f.Argument(0))
		if id == "" {
			panic(r.NewTypeError("expects a leaderboard ID string"))
		}

		var ownerIds []string
		owners := f.Argument(1)
		if owners != nil {
			if owners == goja.Undefined() {
				panic(r.NewTypeError("expects an array of owner ids or null"))
			}
			ownersSlice, ok := owners.Export().([]interface{})
			if !ok {
				panic(r.NewTypeError("expects an array of owner ids"))
			}
			ownerIds := make([]string, 0, len(ownersSlice))
			for _, owner := range ownersSlice {
				ownerStr, ok := owner.(string)
				if !ok {
					panic(r.NewTypeError("expects a valid owner string"))
				}
				ownerIds = append(ownerIds, ownerStr)
			}
		}

		limitNumber := 0
		if f.Argument(2) != goja.Undefined() {
			limitNumber = int(getInt(r, f.Argument(2)))
		}
		var limit *wrappers.Int32Value
		if limitNumber != 0 {
			limit = &wrappers.Int32Value{Value: int32(limitNumber)}
		}

		cursor := ""
		if f.Argument(3) != goja.Undefined() {
			cursor = getString(r, f.Argument(3))
		}

		overrideExpiry := int64(0)
		if f.Argument(4) != goja.Undefined() {
			overrideExpiry = getInt(r, f.Argument(4))
		}

		records, err := LeaderboardRecordsList(context.Background(), n.logger, n.db, n.leaderboardCache, n.rankCache, id, limit, cursor, ownerIds, overrideExpiry)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error listing leaderboard records: %v", err.Error())))
		}

		recordsSlice := make([]interface{}, 0, len(records.Records))
		for _, record := range records.Records {
			recordMap := make(map[string]interface{})
			recordMap["leaderboard_id"] = record.LeaderboardId
			recordMap["owner_id"] = record.OwnerId
			if record.Username != nil {
				recordMap["username"] = record.Username
			} else {
				recordMap["username"] = nil
			}
			recordMap["score"] = record.Score
			recordMap["subscore"] = record.Subscore
			recordMap["num_scoore"] = record.NumScore
			metadataMap := make(map[string]interface{})
			err = json.Unmarshal([]byte(record.Metadata), &metadataMap)
			if err != nil {
				panic(r.ToValue(fmt.Sprintf("failed to convert metadata to json: %s", err.Error())))
			}
			metadataMap["metadata"] = metadataMap
			metadataMap["create_time"] = record.CreateTime.Seconds
			metadataMap["update_time"] = record.UpdateTime.Seconds
			if record.ExpiryTime != nil {
				recordMap["expiry_time"] = record.ExpiryTime.Seconds
			} else {
				recordMap["expiry_time"] = nil
			}
			recordMap["rank"] = record.Rank

			recordsSlice = append(recordsSlice, recordMap)
		}

		ownerRecordsSlice := make([]interface{}, 0, len(records.OwnerRecords))
		for _, record := range records.OwnerRecords {
			recordMap := make(map[string]interface{})
			recordMap["leaderboard_id"] = record.LeaderboardId
			recordMap["owner_id"] = record.OwnerId
			if record.Username != nil {
				recordMap["username"] = record.Username
			} else {
				recordMap["username"] = nil
			}
			recordMap["score"] = record.Score
			recordMap["subscore"] = record.Subscore
			recordMap["num_scoore"] = record.NumScore
			metadataMap := make(map[string]interface{})
			err = json.Unmarshal([]byte(record.Metadata), &metadataMap)
			if err != nil {
				panic(r.ToValue(fmt.Sprintf("failed to convert metadata to json: %s", err.Error())))
			}
			metadataMap["metadata"] = metadataMap
			metadataMap["create_time"] = record.CreateTime.Seconds
			metadataMap["update_time"] = record.UpdateTime.Seconds
			if record.ExpiryTime != nil {
				recordMap["expiry_time"] = record.ExpiryTime.Seconds
			} else {
				recordMap["expiry_time"] = nil
			}
			recordMap["rank"] = record.Rank

			ownerRecordsSlice = append(ownerRecordsSlice, recordMap)
		}

		resultMap := make(map[string]interface{})

		resultMap["records"] = recordsSlice
		resultMap["owner_records"] = ownerRecordsSlice

		if records.NextCursor != "" {
			resultMap["next_cursor"] = records.NextCursor
		} else {
			resultMap["next_cursor"] = nil
		}

		if records.PrevCursor != "" {
			resultMap["prev_cursor"] = records.PrevCursor
		} else {
			resultMap["prev_cursor"] = nil
		}

		return r.ToValue(resultMap)
	}
}

func (n *runtimeJavascriptNakamaModule) leaderboardRecordWrite(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		id := getString(r, f.Argument(0))
		if id == "" {
			panic(r.NewTypeError("expects a leaderboard ID string"))
		}

		ownerID := getString(r, f.Argument(1))
		if _, err := uuid.FromString(ownerID); err != nil {
			panic(r.NewTypeError("expects owner ID to be a valid identifier"))
		}

		username := ""
		if f.Argument(2) != goja.Undefined() {
			username = getString(r, f.Argument(2))
		}

		var score int64
		if f.Argument(3) != goja.Undefined() {
			score = getInt(r, f.Argument(3))
		}

		var subscore int64
		if f.Argument(4) != goja.Undefined() {
			subscore = getInt(r, f.Argument(4))
		}

		metadata := f.Argument(5)
		metadataStr := ""
		if metadata != goja.Undefined() && metadata != goja.Null() {
			metadataMap, ok := f.Argument(4).Export().(map[string]interface{})
			if !ok {
				panic(r.NewTypeError("expects metadata to be an object"))
			}
			metadataBytes, err := json.Marshal(metadataMap)
			if err != nil {
				panic(r.ToValue(fmt.Sprintf("error encoding metadata: %v", err.Error())))
			}
			metadataStr = string(metadataBytes)
		}

		record, err := LeaderboardRecordWrite(context.Background(), n.logger, n.db, n.leaderboardCache, n.rankCache, uuid.Nil, id, ownerID, username, score, subscore, metadataStr)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error writing leaderboard record: %v", err.Error())))
		}

		resultMap := make(map[string]interface{})

		resultMap["leaderboard_id"] = record.LeaderboardId
		resultMap["owner_id"] = record.OwnerId
		if record.Username != nil {
			resultMap["username"] = record.Username
		} else {
			resultMap["username"] = nil
		}
		resultMap["score"] = record.Score
		resultMap["subscore"] = record.Subscore
		resultMap["num_scoore"] = record.NumScore
		metadataMap := make(map[string]interface{})
		err = json.Unmarshal([]byte(record.Metadata), &metadataMap)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to convert metadata to json: %s", err.Error())))
		}
		metadataMap["metadata"] = metadataMap
		metadataMap["create_time"] = record.CreateTime.Seconds
		metadataMap["update_time"] = record.UpdateTime.Seconds
		if record.ExpiryTime != nil {
			resultMap["expiry_time"] = record.ExpiryTime.Seconds
		} else {
			resultMap["expiry_time"] = nil
		}

		return r.ToValue(resultMap)
	}
}

func (n *runtimeJavascriptNakamaModule) leaderboardRecordDelete(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		id := getString(r, f.Argument(0))
		if id == "" {
			panic(r.NewTypeError("expects a leaderboard ID string"))
		}

		ownerID := getString(r, f.Argument(1))
		if _, err := uuid.FromString(ownerID); err != nil {
			panic(r.NewTypeError("expects owner ID to be a valid identifier"))
		}

		if err := LeaderboardRecordDelete(context.Background(), n.logger, n.db, n.leaderboardCache, n.rankCache, uuid.Nil, id, ownerID); err != nil {
			panic(r.ToValue(fmt.Sprintf("error deleting leaderboard record: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) tournamentCreate(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		id := getString(r, f.Argument(0))
		if id == "" {
			panic(r.NewTypeError("expects a tournament ID string"))
		}

		sortOrder := "desc"
		if f.Argument(1) != goja.Undefined() {
			sortOrder = getString(r, f.Argument(1))
		}
		var sortOrderNumber int
		switch sortOrder {
		case "asc":
			sortOrderNumber = LeaderboardSortOrderAscending
		case "desc":
			sortOrderNumber = LeaderboardSortOrderDescending
		default:
			panic(r.NewTypeError("expects sort order to be 'asc' or 'desc'"))
		}

		operator := "best"
		if f.Argument(2) != goja.Undefined() {
			operator = getString(r, f.Argument(2))
		}
		var operatorNumber int
		switch operator {
		case "best":
			operatorNumber = LeaderboardOperatorBest
		case "set":
			operatorNumber = LeaderboardOperatorSet
		case "incr":
			operatorNumber = LeaderboardOperatorIncrement
		default:
			panic(r.NewTypeError("expects sort order to be 'best', 'set', or 'incr'"))
		}

		var duration int
		if f.Argument(3) != goja.Undefined() && f.Argument(3) != goja.Null() {
			duration = int(getInt(r, f.Argument(3)))
		}
		if duration <= 0 {
			panic(r.NewTypeError("duration must be > 0"))
		}

		resetSchedule := ""
		if f.Argument(4) != goja.Undefined() && f.Argument(4) != goja.Null() {
			resetSchedule = getString(r, f.Argument(4))
		}
		if resetSchedule != "" {
			if _, err := cronexpr.Parse(resetSchedule); err != nil {
				panic(r.NewTypeError("expects reset schedule to be a valid CRON expression"))
			}
		}

		metadata := f.Argument(5)
		metadataStr := ""
		if metadata != goja.Undefined() && metadata != goja.Null() {
			metadataMap, ok := f.Argument(5).Export().(map[string]interface{})
			if !ok {
				panic(r.NewTypeError("expects metadata to be an object"))
			}
			metadataBytes, err := json.Marshal(metadataMap)
			if err != nil {
				panic(r.ToValue(fmt.Sprintf("error encoding metadata: %v", err.Error())))
			}
			metadataStr = string(metadataBytes)
		}

		title := ""
		if f.Argument(6) != goja.Undefined() && f.Argument(6) != goja.Null() {
			title = getString(r, f.Argument(6))
		}

		description := ""
		if f.Argument(7) != goja.Undefined() && f.Argument(7) != goja.Null() {
			description = getString(r, f.Argument(7))
		}

		var category int
		if f.Argument(8) != goja.Undefined() && f.Argument(8) != goja.Null() {
			category = int(getInt(r, f.Argument(8)))
			if category < 0 || category >= 128 {
				panic(r.NewTypeError("category must be 0-127"))
			}
		}

		var startTime int
		if f.Argument(9) != goja.Undefined() && f.Argument(9) != goja.Null() {
			startTime = int(getInt(r, f.Argument(9)))
			if startTime < 0 {
				panic(r.NewTypeError("startTime must be >= 0."))
			}
		}

		var endTime int
		if f.Argument(10) != goja.Undefined() && f.Argument(10) != goja.Null() {
			endTime = int(getInt(r, f.Argument(10)))
		}
		if endTime != 0 && endTime <= startTime {
			panic(r.NewTypeError("endTime must be > startTime. Use 0 to indicate a tournament that never ends."))
		}

		var maxSize int
		if f.Argument(11) != goja.Undefined() && f.Argument(10) != goja.Null() {
			maxSize = int(getInt(r, f.Argument(11)))
			if maxSize < 0 {
				panic(r.NewTypeError("maxSize must be >= 0"))
			}
		}


		var maxNumScore int
		if f.Argument(12) != goja.Undefined() && f.Argument(12) != goja.Null() {
			maxNumScore = int(getInt(r, f.Argument(12)))
			if maxNumScore < 0 {
				panic(r.NewTypeError("maxNumScore must be >= 0"))
			}
		}

		joinRequired := false
		if f.Argument(13) != goja.Undefined() && f.Argument(13) != goja.Null() {
			joinRequired = getBool(r, f.Argument(13))
		}

		if err := TournamentCreate(context.Background(), n.logger, n.leaderboardCache, n.leaderboardScheduler, id, sortOrderNumber, operatorNumber, resetSchedule, metadataStr, title, description, category, startTime, endTime, duration, maxSize, maxNumScore, joinRequired); err != nil {
			panic(r.ToValue(fmt.Sprintf("error creating tournament: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) tournamentDelete(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		id := getString(r, f.Argument(0))
		if id == "" {
			panic(r.NewTypeError("expects a tournament ID string"))
		}

		if err := TournamentDelete(context.Background(), n.leaderboardCache, n.rankCache, n.leaderboardScheduler, id); err != nil {
			panic(r.ToValue(fmt.Sprintf("error deleting tournament: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) tournamentAddAttempt(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		id := getString(r, f.Argument(0))
		if id == "" {
			panic(r.NewTypeError("expects a tournament ID string"))
		}

		owner := getString(r, f.Argument(1))
		if owner == "" {
			panic(r.NewTypeError("expects an owner ID string"))
		} else if _, err := uuid.FromString(owner); err != nil {
			panic(r.NewTypeError("expects owner ID to be a valid identifier"))
		}

		count := int(getInt(r, f.Argument(2)))
		if count == 0 {
			panic(r.NewTypeError("expects an attempt count number != 0"))
		}

		if err := TournamentAddAttempt(context.Background(), n.logger, n.db, n.leaderboardCache, id, owner, count); err != nil {
			panic(r.NewTypeError("error adding tournament attempts: %v", err.Error()))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) tournamentJoin(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		id := getString(r, f.Argument(0))
		if id == "" {
			panic(r.NewTypeError("expects a tournament ID string"))
		}

		userID := getString(r, f.Argument(1))
		if userID == "" {
			panic(r.NewTypeError("expects a user ID string"))
		} else if _, err := uuid.FromString(userID); err != nil {
			panic(r.NewTypeError("expects user ID to be a valid identifier"))
		}

		username := getString(r, f.Argument(2))
		if username == "" {
			panic(r.NewTypeError("expects a username string"))
		}

		if err := TournamentJoin(context.Background(), n.logger, n.db, n.leaderboardCache, userID, username, id); err != nil {
			panic(r.ToValue(fmt.Sprintf("error joining tournament: %v", err.Error())))
		}

		return goja.Undefined()
	}
}

func (n *runtimeJavascriptNakamaModule) tournamentsGetId(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		tournamentIdsIn := f.Argument(0)
		if tournamentIdsIn == goja.Undefined() || tournamentIdsIn == goja.Null() {
			panic(r.NewTypeError("expects an array of tournament ids"))
		}
		tournamentIdsSlice := tournamentIdsIn.Export().([]interface{})

		tournmentIDs := make([]string, 0, len(tournamentIdsSlice))
		for _, id := range tournamentIdsSlice {
			idString, ok := id.(string)
			if !ok {
				panic(r.NewTypeError("expects a tournament ID to be a string"))
			}
			tournmentIDs = append(tournmentIDs, idString)
		}

		list, err := TournamentsGet(context.Background(), n.logger, n.db, tournmentIDs)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to get tournaments: %s", err.Error())))
		}

		results := make([]interface{}, 0, len(list))
		for _, tournament := range list {
			tournamentMap := make(map[string]interface{})

			tournamentMap["id"] = tournament.Id
			tournamentMap["title"] = tournament.Title
			tournamentMap["description"] = tournament.Description
			tournamentMap["category"] = tournament.Category
			if tournament.SortOrder == LeaderboardSortOrderAscending {
				tournamentMap["sort_order"] = "asc"
			} else {
				tournamentMap["sort_order"] = "desc"
			}
			tournamentMap["size"] = tournament.Size
			tournamentMap["max_size"] = tournament.MaxSize
			tournamentMap["max_num_score"] = tournament.MaxNumScore
			tournamentMap["duration"] = tournament.Duration
			tournamentMap["start_active"] = tournament.StartActive
			tournamentMap["end_active"] = tournament.EndActive
			tournamentMap["can_enter"] = tournament.CanEnter
			tournamentMap["next_reset"] = tournament.NextReset
			metadataMap := make(map[string]interface{})
			err = json.Unmarshal([]byte(tournament.Metadata), &metadataMap)
			if err != nil {
				panic(r.ToValue(fmt.Sprintf("failed to convert metadata to json: %s", err.Error())))
			}
			metadataMap["metadata"] = metadataMap
			metadataMap["create_time"] = tournament.CreateTime.Seconds
			metadataMap["start_time"] = tournament.StartTime.Seconds
			if tournament.EndTime == nil {
				tournamentMap["end_time"] = nil
			} else {
				tournamentMap["end_time"] = tournament.EndTime.Seconds
			}

			results = append(results, tournamentMap)
		}

		return r.ToValue(results)
	}
}

func (n *runtimeJavascriptNakamaModule) tournamentList(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		var categoryStart int
		if f.Argument(0) != goja.Undefined() && f.Argument(0) != goja.Null() {
			categoryStart = int(getInt(r, f.Argument(0)))
			if categoryStart < 0 || categoryStart >= 128 {
				panic(r.NewTypeError("category start must be 0-127"))
			}
		}

		var categoryEnd int
		if f.Argument(1) != goja.Undefined() && f.Argument(1) != goja.Null() {
			categoryEnd = int(getInt(r, f.Argument(1)))
			if categoryEnd < 0 || categoryEnd >= 128 {
				panic(r.NewTypeError("category end must be 0-127"))
			}
		}

		if categoryStart > categoryEnd {
			panic(r.NewTypeError("category end must be >= category start"))
		}

		startTime := 0
		if f.Argument(2) != goja.Undefined() && f.Argument(2) != goja.Null() {
			startTime = int(getInt(r, f.Argument(2)))
			if startTime < 0 {
				panic(r.NewTypeError("start time must be >= 0"))
			}
		}

		endTime := 0
		if f.Argument(3) != goja.Undefined() && f.Argument(3) != goja.Null() {
			endTime = int(getInt(r, f.Argument(2)))
			if endTime < 0 {
				panic(r.NewTypeError("end time must be >= 0"))
			}
		}

		if startTime > endTime {
			panic(r.NewTypeError("end time must be >= start time"))
		}

		limit := 10
		if f.Argument(4) != goja.Undefined() && f.Argument(4) != goja.Null() {
			limit = int(getInt(r, f.Argument(4)))
			if limit < 1 || limit > 100 {
				panic(r.NewTypeError("limit must be 1-100"))
			}
		}

		var cursor *TournamentListCursor
		cursorStr := ""
		if f.Argument(5) != goja.Undefined() && f.Argument(5) != goja.Null() {
			cursorStr = getString(r, f.Argument(5))
			cb, err := base64.StdEncoding.DecodeString(cursorStr)
			if err != nil {
				panic(r.ToValue("expects cursor to be valid when provided"))
			}
			cursor = &TournamentListCursor{}
			if err := gob.NewDecoder(bytes.NewReader(cb)).Decode(cursor); err != nil {
				panic(r.ToValue("expects cursor to be valid when provided"))
			}
		}

		list, err := TournamentList(context.Background(), n.logger, n.db, n.leaderboardCache, categoryStart, categoryEnd, startTime, endTime, limit, cursor)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error listing tournaments: %v", err.Error())))
		}

		results := make([]interface{}, 0, len(list.Tournaments))
		for _, tournament := range list.Tournaments {
			tournamentMap := make(map[string]interface{})

			tournamentMap["id"] = tournament.Id
			tournamentMap["title"] = tournament.Title
			tournamentMap["description"] = tournament.Description
			tournamentMap["category"] = tournament.Category
			if tournament.SortOrder == LeaderboardSortOrderAscending {
				tournamentMap["sort_order"] = "asc"
			} else {
				tournamentMap["sort_order"] = "desc"
			}
			tournamentMap["size"] = tournament.Size
			tournamentMap["max_size"] = tournament.MaxSize
			tournamentMap["max_num_score"] = tournament.MaxNumScore
			tournamentMap["duration"] = tournament.Duration
			tournamentMap["start_active"] = tournament.StartActive
			tournamentMap["end_active"] = tournament.EndActive
			tournamentMap["can_enter"] = tournament.CanEnter
			tournamentMap["next_reset"] = tournament.NextReset
			metadataMap := make(map[string]interface{})
			err = json.Unmarshal([]byte(tournament.Metadata), &metadataMap)
			if err != nil {
				panic(r.ToValue(fmt.Sprintf("failed to convert metadata to json: %s", err.Error())))
			}
			metadataMap["metadata"] = metadataMap
			metadataMap["create_time"] = tournament.CreateTime.Seconds
			metadataMap["start_time"] = tournament.StartTime.Seconds
			if tournament.EndTime == nil {
				tournamentMap["end_time"] = nil
			} else {
				tournamentMap["end_time"] = tournament.EndTime.Seconds
			}

			results = append(results, tournamentMap)
		}

		resultMap := make(map[string]interface{})

		if list.Cursor == "" {
			resultMap["cursor"] = nil
		} else {
			resultMap["cursor"] = list.Cursor
		}

		resultMap["tournaments"] = results

		return r.ToValue(resultMap)
	}
}

func (n *runtimeJavascriptNakamaModule) tournamentRecordWrite(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		id := getString(r, f.Argument(0))
		if id == "" {
			panic(r.NewTypeError("expects a tournament ID string"))
		}

		userIDStr := getString(r, f.Argument(1))
		userID, err := uuid.FromString(userIDStr)
		if err != nil {
			panic(r.NewTypeError("expects user ID to be a valid identifier"))
		}

		username := ""
		if f.Argument(2) != goja.Undefined() && f.Argument(2) != goja.Null() {
			username = getString(r, f.Argument(2))
		}

		var score int64
		if f.Argument(3) != goja.Undefined() && f.Argument(3) != goja.Null() {
			score = getInt(r, f.Argument(3))
		}

		var subscore int64
		if f.Argument(4) != goja.Undefined() && f.Argument(4) != goja.Null() {
			subscore = getInt(r, f.Argument(4))
		}

		metadata := f.Argument(5)
		metadataStr := ""
		if metadata != goja.Undefined() && metadata != goja.Null() {
			metadataMap, ok := f.Argument(5).Export().(map[string]interface{})
			if !ok {
				panic(r.NewTypeError("expects metadata to be an object"))
			}
			metadataBytes, err := json.Marshal(metadataMap)
			if err != nil {
				panic(r.ToValue(fmt.Sprintf("error encoding metadata: %v", err.Error())))
			}
			metadataStr = string(metadataBytes)
		}

		record, err := TournamentRecordWrite(context.Background(), n.logger, n.db, n.leaderboardCache, n.rankCache, id, userID, username, score, subscore, metadataStr)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error writing tournament record: %v", err.Error())))
		}

		result := make(map[string]interface{})

		result["leaderboard_id"] = record.LeaderboardId
		result["owner_id"] = record.OwnerId
		if record.Username != nil {
			result["username"] = record.Username.Value
		} else {
			result["username"] = nil
		}
		result["score"] = record.Score
		result["subscore"] = record.Subscore
		result["num_score"] = record.NumScore

		metadataMap := make(map[string]interface{})
		err = json.Unmarshal([]byte(record.Metadata), &metadataMap)
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("failed to convert metadata to json: %s", err.Error())))
		}
		result["metadata"] = metadataMap

		result["create_time"] = record.CreateTime.Seconds
		result["update_time"] = record.UpdateTime.Seconds
		if record.ExpiryTime != nil {
			result["expiry_time"] = record.ExpiryTime.Seconds
		} else {
			result["expiry_time"] = nil
		}

		return r.ToValue(result)
	}
}

func (n *runtimeJavascriptNakamaModule) tournamentRecordsHaystack(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		id := getString(r, f.Argument(0))
		if id == "" {
			panic(r.NewTypeError("expects a tournament ID string"))
		}

		userIDStr := getString(r, f.Argument(1))
		userID, err := uuid.FromString(userIDStr)
		if err != nil {
			panic(r.NewTypeError("expects user ID to be a valid identifier"))
		}

		limit := 10
		if f.Argument(2) != goja.Undefined() && f.Argument(2) != goja.Null() {
			limit = int(getInt(r, f.Argument(2)))
			if limit < 1 || limit > 100 {
				panic(r.NewTypeError("limit must be 1-100"))
			}
		}

		var expiry int
		if f.Argument(3) != goja.Undefined() && f.Argument(3) != goja.Null() {
			expiry = int(getInt(r, f.Argument(3)))
			if expiry < 0 {
				panic(r.NewTypeError("expiry should be time since epoch in seconds and has to be a positive integer"))
			}
		}

		records, err := TournamentRecordsHaystack(context.Background(), n.logger, n.db, n.leaderboardCache, n.rankCache, id, userID, limit, int64(expiry))
		if err != nil {
			panic(r.ToValue(fmt.Sprintf("error listing tournament records haystack: %v", err.Error())))
		}

		results := make([]interface{}, 0, len(records))
		for _, record := range records {
			recordMap := make(map[string]interface{})

			recordMap["leaderboard_id"] = record.LeaderboardId
			recordMap["owner_id"] = record.OwnerId
			if record.Username != nil {
				recordMap["username"] = record.Username.Value
			} else {
				recordMap["username"] = nil
			}
			recordMap["score"] = record.Score
			recordMap["subscore"] = record.Subscore
			recordMap["num_score"] = record.NumScore

			metadataMap := make(map[string]interface{})
			err = json.Unmarshal([]byte(record.Metadata), &metadataMap)
			if err != nil {
				panic(r.ToValue(fmt.Sprintf("failed to convert metadata to json: %s", err.Error())))
			}
			recordMap["metadata"] = metadataMap
			recordMap["create_time"] = record.CreateTime.Seconds
			recordMap["update_time"] = record.UpdateTime.Seconds
			if record.ExpiryTime != nil {
				recordMap["expiry_time"] = record.ExpiryTime.Seconds
			} else {
				recordMap["expiry_time"] = nil
			}

			results = append(results, recordMap)
		}

		return r.ToValue(results)
	}
}

func getString(r *goja.Runtime, v goja.Value) string {
	s, ok := v.Export().(string)
	if !ok {
		panic(r.NewTypeError("Invalid argument - string expected."))
	}
	return s
}

func getStringMap(r *goja.Runtime, v goja.Value) map[string]string {
	m, ok := v.Export().(map[string]interface{})
	if !ok {
		panic(r.ToValue("Invalid argument - object with type string keys and values expected."))
	}

	res := make(map[string]string)
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			panic(r.NewTypeError("Invalid object value - string expected."))
		}
		res[k] = s
	}
	return res
}

func getInt(r *goja.Runtime, v goja.Value) int64 {
	i, ok := v.Export().(int64)
	if !ok {
		panic(r.NewTypeError("Invalid argument - int expected."))
	}
	return i
}

func getBool(r *goja.Runtime, v goja.Value) bool {
	b, ok := v.Export().(bool)
	if !ok {
		panic(r.NewTypeError("Invalid argument - boolean expected."))
	}
	return b
}

func getAccountData(account *api.Account) (map[string]interface{}, error) {
	accountData := make(map[string]interface{})
	accountData["user_id"] = account.User.Id
	accountData["username"] = account.User.Username
	accountData["display_name"] = account.User.DisplayName
	accountData["avatar_url"] = account.User.AvatarUrl
	accountData["lang_tag"] = account.User.LangTag
	accountData["location"] = account.User.Location
	accountData["timezone"] = account.User.Timezone
	if account.User.AppleId != "" {
		accountData["apple_id"] = account.User.AppleId
	}
	if account.User.FacebookId != "" {
		accountData["facebook_id"] = account.User.FacebookId
	}
	if account.User.FacebookInstantGameId != "" {
		accountData["facebook_instant_game_id"] = account.User.FacebookInstantGameId
	}
	if account.User.GoogleId != "" {
		accountData["google_id"] = account.User.GoogleId
	}
	if account.User.GamecenterId != "" {
		accountData["gamecenter_id"] = account.User.GamecenterId
	}
	if account.User.SteamId != "" {
		accountData["steam_id"] = account.User.SteamId
	}
	accountData["online"] = account.User.Online
	accountData["edge_count"] = account.User.EdgeCount
	accountData["create_time"] = account.User.CreateTime
	accountData["update_time"] = account.User.UpdateTime

	metadata := make(map[string]interface{})
	err := json.Unmarshal([]byte(account.User.Metadata), &metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to convert metadata to json: %s", err.Error())
	}
	accountData["metadata"] = metadata

	walletData := make(map[string]int64)
	err = json.Unmarshal([]byte(account.Wallet), &walletData)
	if err != nil {
		return nil, fmt.Errorf("failed to convert wallet to json: %s", err.Error())
	}
	accountData["wallet"] = walletData

	if account.Email != "" {
		accountData["email"] = account.Email
	}
	if len(account.Devices) != 0 {
		devices := make([]map[string]string, 0, len(account.Devices))
		for _, device := range account.Devices {
			deviceData := make(map[string]string)
			deviceData["id"] = device.Id
			devices = append(devices, deviceData)
		}
		accountData["devices"] = devices
	}

	if account.CustomId != "" {
		accountData["custom_id"] = account.CustomId
	}
	if account.VerifyTime != nil {
		accountData["verify_time"] = account.VerifyTime.Seconds
	}
	if account.DisableTime != nil {
		accountData["disable_time"] = account.DisableTime.Seconds
	}

	return accountData, nil
}

func getUserData(user *api.User) (map[string]interface{}, error) {
	userData := make(map[string]interface{})
	userData["user_id"] = user.Id
	userData["username"] = user.Username
	userData["display_name"] = user.DisplayName
	userData["avatar_url"] = user.AvatarUrl
	userData["lang_tag"] = user.LangTag
	userData["location"] = user.Location
	userData["timezone"] = user.Timezone
	if user.AppleId != "" {
		userData["apple_id"] = user.AppleId
	}
	if user.FacebookId != "" {
		userData["facebook_id"] = user.FacebookId
	}
	if user.FacebookInstantGameId != "" {
		userData["facebook_instant_game_id"] = user.FacebookInstantGameId
	}
	if user.GoogleId != "" {
		userData["google_id"] = user.GoogleId
	}
	if user.GamecenterId != "" {
		userData["gamecenter_id"] = user.GamecenterId
	}
	if user.SteamId != "" {
		userData["steam_id"] = user.SteamId
	}
	userData["online"] = user.Online
	userData["edge_count"] = user.EdgeCount
	userData["create_time"] = user.CreateTime
	userData["update_time"] = user.UpdateTime

	metadata := make(map[string]interface{})
	err := json.Unmarshal([]byte(user.Metadata), &metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to convert metadata to json: %s", err.Error())
	}
	userData["metadata"] = metadata

	return userData, nil
}

func getStreamData(r *goja.Runtime, streamObj map[string]interface{}) PresenceStream {
	stream := PresenceStream{}

	modeRaw, ok := streamObj["mode"]
	if ok {
		mode, ok := modeRaw.(int64)
		if !ok {
			panic(r.NewTypeError("stream mode must be a number"))
		}
		stream.Mode = uint8(mode)
	}

	subjectRaw, ok := streamObj["subject"]
	if ok {
		subject, ok := subjectRaw.(string)
		if !ok {
			panic(r.NewTypeError("stream subject must be a string"))
		}
		uuid, err := uuid.FromString(subject)
		if err != nil {
			panic(r.NewTypeError("stream subject must be a valid identifier"))
		}
		stream.Subject = uuid
	}

	subcontextRaw, ok := streamObj["subcontext"]
	if ok {
		subcontext, ok := subcontextRaw.(string)
		if !ok {
			panic(r.NewTypeError("stream subcontext must be a string"))
		}
		uuid, err := uuid.FromString(subcontext)
		if err != nil {
			panic(r.NewTypeError("stream subcontext must be a valid identifier"))
		}
		stream.Subcontext = uuid
	}

	labelRaw, ok := streamObj["label"]
	if ok {
		label, ok := labelRaw.(string)
		if !ok {
			panic(r.NewTypeError("stream label must be a string"))
		}
		stream.Label = label
	}

	return stream
}
