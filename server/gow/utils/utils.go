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
		"spf":        regexp.MustCompile(`spf=(.*)`),
		"dkim":       regexp.MustCompile(`dkim=(.*)`),
		"dkimDomain": regexp.MustCompile(`header\.d=(.*)`),
		"senderIP":   regexp.MustCompile(`([\d\.]+\.\d{1,3})|([[:xdigit:]]*:+[:[:xdigit:]]+)`),
	}
	parts := strings.Split(ar, ";")
	res := map[string]string{
		"authservId": parts[0],
	}

	for _, p := range parts {
		for k, re := range regexs {
			t := strings.TrimSpace(re.FindString(p))
			if len(t) > 0 {
				res[k] = t
			}
		}
	}

	if net.ParseIP(res["senderIP"]) == nil {
		delete(res, "senderIP")
	}

	return res
}
