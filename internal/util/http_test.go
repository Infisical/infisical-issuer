package util

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDescribeErrorResponse(t *testing.T) {
	respond := func(t *testing.T, contentType, body string) *resty.Response {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", contentType)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		res, err := resty.New().R().Get(srv.URL + "/api/v1/auth/tls-cert-auth/login")
		require.NoError(t, err)
		return res
	}

	t.Run("uses the Infisical message and drops the request id", func(t *testing.T) {
		got := DescribeErrorResponse(respond(t, "application/json", `{"reqId":"req-abc","statusCode":400,"message":"Certificate not allowed"}`))
		assert.Equal(t, "400 Bad Request: Certificate not allowed", got)
	})

	t.Run("joins the validation issues Infisical sends on 422", func(t *testing.T) {
		got := DescribeErrorResponse(respond(t, "application/json", `{"reqId":"req-abc","statusCode":422,"error":"ValidationFailure","message":[{"code":"invalid_string","message":"Invalid name","path":["name"]},{"code":"too_small","message":"Required","path":["attributes","ttl"]}]}`))
		assert.Equal(t, "400 Bad Request: name: Invalid name; attributes.ttl: Required", got)
		assert.NotContains(t, got, "not from the Infisical API")
	})

	t.Run("falls back to the error name when Infisical sends no message", func(t *testing.T) {
		got := DescribeErrorResponse(respond(t, "application/json", `{"reqId":"req-abc","statusCode":400,"error":"BadRequest"}`))
		assert.Equal(t, "400 Bad Request: BadRequest", got)
	})

	t.Run("summarizes a response that is not from Infisical", func(t *testing.T) {
		got := DescribeErrorResponse(respond(t, "text/html", "<html><body>400 The SSL certificate error</body></html>"))
		assert.Contains(t, got, "400 Bad Request from ")
		assert.Contains(t, got, "the response is not from the Infisical API")
		assert.NotContains(t, got, "<html>")
	})
}
