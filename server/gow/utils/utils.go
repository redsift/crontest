package utils

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/redsift/go-sandbox-rpc"
	rpc "github.com/redsift/go-sandbox-rpc/rpc"
)

func NewRPCComputeResponse(k string, status int, b []byte, isJSON bool) sandboxrpc.ComputeResponse {
	r := rpc.Response{
		StatusCode: status,
		Header:     map[string][]string{},
		Body:       b,
	}
	if isJSON {
		r.Header.Add("Content-Type", "application/json")
	}
	v, _ := json.Marshal(r)
	return sandboxrpc.NewComputeResponse("api_rpc", k, v, 0, 0)
}

func ErrorResponse(brand string, key string, title string, err error) sandboxrpc.ComputeResponse {
	et := err.Error()
	if len(title) > 0 {
		et = fmt.Sprintf("%s: %v\n", title, err)
	}

	r := rpc.Response{
		StatusCode: 500,
		Header:     map[string][]string{},
		Body:       []byte(et),
	}
	// r.Header.Add("On-Dmarc-Error-Code","")
	// r.Header.Add("On-Dmarc-Error-Id","")
	r.Header.Add(brand+"-Error-Title", title)
	r.Header.Add(brand+"-Error-Detail", err.Error())

	v, _ := json.Marshal(r)
	return sandboxrpc.NewComputeResponse("api_rpc", key, v, 0, 0)
}

func ParseAuthenticationResults(ar string) map[string]string {
	regexs := map[string]*regexp.Regexp{
		"authservId": regexp.MustCompile(`^(([a-zA-Z0-9]+\.)+[a-zA-Z0-9]+)`),
		"spf":        regexp.MustCompile(`(?U)spf=(.*)(\s+|$)`),
		"dkim":       regexp.MustCompile(`(?U)dkim=(.*)(\s+|$)`),
		"dkimDomain": regexp.MustCompile(`(?U)header\.d=(.*)(\s+|$)`),
		"senderIP":   regexp.MustCompile(`sender IP is ([a-fA-F0-9.:]+)\)?`),
	}

	res := map[string]string{}
	parts := strings.Split(ar, ";")
	if len(parts) == 0 {
		return res
	}

	for _, p := range parts {
		for k, re := range regexs {
			if v, ok := res[k]; ok && len(v) > 0 {
				continue
			}
			t := re.FindStringSubmatch(p)
			if len(t) > 1 && len(t[1]) > 0 {
				if k == "senderIP" && net.ParseIP(t[1]) == nil {
					continue
				}
				res[k] = t[1]
			}
		}
	}

	return res
}
