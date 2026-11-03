package util

import (
	"encoding/json"
	"fmt"

	"github.com/go-resty/resty/v2"
)

// Volatile fields such as Infisical's reqId are dropped so a repeated failure
// yields the same message and does not rewrite the resource status.
func DescribeErrorResponse(res *resty.Response) string {
	var body struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(res.Body(), &body); err == nil && body.Message != "" {
		return fmt.Sprintf("%s: %s", res.Status(), body.Message)
	}
	return fmt.Sprintf("%s from %s: the response is not from the Infisical API; check the issuer url and any proxy in front of Infisical", res.Status(), res.Request.URL)
}
