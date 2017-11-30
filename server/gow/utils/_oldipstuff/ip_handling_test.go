package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"testing"

	"github.com/redsift/bleve"
)

var grandList = []string{
	"192.168.0.0",
	"192.168.2.15",
	"192.168.255.255",
	"2001:0DB8:0A0B:11D0:FFFF:FFFF:FFFF:FFFF",
	"2001:0DB8:0A0B:12F0:0000:0000:0000:0000",
	"2001:0DB8:0A0B:12F0::1",
	"2001:0DB8:0A0B:12F0:FFFF:FFFF:FFFF:FFFF",
	"::ffff:ffff:192.0.2.1",
}

var idx bleve.Index

func TestIPRanges(t *testing.T) {
	tests := []struct {
		cidr    string
		matches []string
	}{
		{"192.168.2.15/0", grandList[:3]},
		{"192.168.2.15/16", grandList[:3]},
		{"192.168.2.15/32", grandList[1:2]},
		{"2001:0DB8:0A0B:12F0::1/32", grandList[3:7]},
		{"2001:0DB8:0A0B:12F0::1/64", grandList[4:7]},
		{"2001:0DB8:0A0B:12F0:0000:0000:0000:0000/128", grandList[4:5]},
		{"::/0", grandList[3:]},
		{"0.0.0.0/0", grandList[:3]},
	}
	for _, test := range tests {
		_, ipNet, err := net.ParseCIDR(test.cidr)
		if err != nil {
			die("%s", err.Error())
		}
		for _, v := range test.matches {
			assert(t, ipNet.Contains(net.ParseIP(v)), "Go Contains method: case: %v does not contain %s", test.cidr, v)
		}
		bq := ToQueryFromCIDR(ipNet, false)
		sreq := bleve.NewSearchRequest(bq)
		sreq.Fields = []string{"ip"}
		sreq.Explain = true
		sres, err := idx.Search(sreq)
		if err != nil {
			die("%s", err.Error())
		}
		assert(t, verifyResults(sres, test.matches), "case: %v no match: \n %v \nvs\n %v", test.cidr, sres, test.matches)
	}
	fmt.Println("Number of tests:", len(tests))
}

func TestMain(m *testing.M) {
	os.Setenv("_LARGE_STORAGE_rocksdb_store", "/tmp/rocksdb")
	var err error
	idx, err = OpenIndex(false)
	if err != nil {
		die("%s", err.Error())
	}
	err = UpdateIndex(idx, 1000, loadBulkPayload())
	if err != nil {
		die("%s", err.Error())
	}
	v := m.Run()
	idx.Close()
	os.Exit(v)
}

func loadBulkPayload() []Datum {
	data := []Datum{}
	raw, err := ioutil.ReadFile(path.Join(os.Getenv("GOPATH"), "src/sift/testdata/testBulkPayload.json"))
	if err != nil {
		die("%s", err.Error())
	}
	err = json.Unmarshal(raw, &data)
	if err != nil {
		die("%s", err.Error())
	}
	return data
}

func verifyResults(sr *bleve.SearchResult, expected []string) bool {
	found := make([]int, len(expected))
	if len(sr.Hits) != len(expected) {
		return false
	}
	for _, hit := range sr.Hits {
		for fieldName, fieldValue := range hit.Fields {
			if _, ok := hit.Fragments[fieldName]; !ok {
				for i, v := range expected {
					if fieldValue == v {
						found[i] = 1
					}
				}
			}
		}
	}
	sum := 0
	for _, v := range found {
		sum += v
	}
	return len(expected) == sum
}

func assert(t *testing.T, a bool, format string, v ...interface{}) {
	if a {
		return
	}
	t.Fatal(fmt.Sprintf(format, v...))
}

func die(format string, v ...interface{}) {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, v...))
	os.Exit(1)
}
