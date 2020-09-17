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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/heroiclabs/nakama-common/rtapi"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

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
	logger            *zap.Logger
	config            Config
	db                *sql.DB
	jsonpbMarshaler   *jsonpb.Marshaler
	jsonpbUnmarshaler *jsonpb.Unmarshaler
	httpClient        *http.Client
	socialClient      *social.Client
	tracker           Tracker
	sessionRegistry   SessionRegistry
	streamManager     StreamManager
	router            MessageRouter
	eventFn           RuntimeEventCustomFunction

	node string
}

func NewRuntimeJavascriptNakamaModule(logger *zap.Logger, db *sql.DB, jsonpbMarshaler *jsonpb.Marshaler, jsonpbUnmarshaler *jsonpb.Unmarshaler, config Config, socialClient *social.Client, sessionRegistry SessionRegistry, tracker Tracker, streamManager StreamManager, router MessageRouter, eventFn RuntimeEventCustomFunction) *runtimeJavascriptNakamaModule {
	return &runtimeJavascriptNakamaModule{
		logger:            logger,
		config:            config,
		db:                db,
		jsonpbMarshaler:   jsonpbMarshaler,
		jsonpbUnmarshaler: jsonpbUnmarshaler,
		streamManager:     streamManager,
		sessionRegistry:   sessionRegistry,
		router:            router,
		tracker:           tracker,
		socialClient:      socialClient,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		eventFn: eventFn,
		node: config.GetName(),
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
			panic(r.ToValue("invalid user id"))
		}

		data, ok := f.Argument(1).Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("invalid data - must be an object"))
		}

		var username string
		if _, ok := data["username"]; ok {
			username = data["username"].(string)
		}

		var displayName *wrappers.StringValue
		if _, ok := data["display_name"]; ok {
			displayName = &wrappers.StringValue{Value: data["display_name"].(string)}
		}

		var timezone *wrappers.StringValue
		if _, ok := data["timezone"]; ok {
			timezone = &wrappers.StringValue{Value: data["timezone"].(string)}
		}

		var location *wrappers.StringValue
		if _, ok := data["location"]; ok {
			location = &wrappers.StringValue{Value: data["location"].(string)}
		}

		var lang *wrappers.StringValue
		if _, ok := data["lang_tag"]; ok {
			lang = &wrappers.StringValue{Value: data["lang_tag"].(string)}
		}

		var avatar *wrappers.StringValue
		if _, ok := data["avatar_url"]; ok {
			avatar = &wrappers.StringValue{Value: data["avatar_url"].(string)}
		}

		var metadata *wrappers.StringValue
		if _, ok := data["metadata"]; ok {
			metadata = &wrappers.StringValue{Value: data["metadata"].(string)}
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
			"hidden": meta.Hidden,
			"persistence": meta.Persistence,
			"username": meta.Username,
			"status": meta.Status,
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
		persistence := false
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
		persistence := false
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
