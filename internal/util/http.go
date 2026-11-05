package util

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-resty/resty/v2"
)

type infisicalErrorBody struct {
	Message    json.RawMessage `json:"message"`
	Error      string          `json:"error"`
	StatusCode int             `json:"statusCode"`
	ReqID      string          `json:"reqId"`
}

type validationIssue struct {
	Message string        `json:"message"`
	Path    []interface{} `json:"path"`
}

// Volatile fields such as Infisical's reqId are dropped so a repeated failure
// yields the same message and does not rewrite the resource status.
func DescribeErrorResponse(res *resty.Response) string {
	var body infisicalErrorBody
	if err := json.Unmarshal(res.Body(), &body); err == nil && (body.StatusCode != 0 || body.ReqID != "" || len(body.Message) > 0) {
		if msg := describeMessage(body.Message); msg != "" {
			return fmt.Sprintf("%s: %s", res.Status(), msg)
		}
		if body.Error != "" {
			return fmt.Sprintf("%s: %s", res.Status(), body.Error)
		}
		return res.Status()
	}
	return fmt.Sprintf("%s from %s: the response is not from the Infisical API; check the issuer url and any proxy in front of Infisical", res.Status(), res.Request.URL)
}

// Infisical sends message as a string, or as a list of validation issues on 422.
func describeMessage(raw json.RawMessage) string {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text
	}
	var issues []json.RawMessage
	if err := json.Unmarshal(raw, &issues); err != nil {
		return ""
	}
	parts := make([]string, 0, len(issues))
	for _, item := range issues {
		var s string
		if err := json.Unmarshal(item, &s); err == nil {
			parts = append(parts, s)
			continue
		}
		var issue validationIssue
		if err := json.Unmarshal(item, &issue); err != nil || issue.Message == "" {
			continue
		}
		if len(issue.Path) == 0 {
			parts = append(parts, issue.Message)
			continue
		}
		path := make([]string, len(issue.Path))
		for i, p := range issue.Path {
			path[i] = fmt.Sprint(p)
		}
		parts = append(parts, fmt.Sprintf("%s: %s", strings.Join(path, "."), issue.Message))
	}
	return strings.Join(parts, "; ")
}
