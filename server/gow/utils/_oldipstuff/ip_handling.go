package utils

import (
  "encoding/binary"
  "fmt"
  "net"
  "strings"

  "github.com/redsift/bleve"
  "github.com/redsift/bleve/search/query"
)

func ToQueryFromCIDR(ipNet *net.IPNet, exactMatch bool) query.Query {
  bndrs := make([]struct {
    min uint32
    max uint32
  }, 4)
  isIPv4 := false
  if ipNet.IP.DefaultMask() != nil {
    isIPv4 = true
  }

  if ok4 := ipNet.IP.To4(); ok4 != nil {
    bndrs[2].min = 0x0000FFFF
    bndrs[2].max = 0x0000FFFF
    bndrs[3].min = binary.BigEndian.Uint32(ok4)

    a := make([]byte, 4)
    m := ipNet.Mask
    for i, b := range ok4 {
      // calculate broadcast address (end of range)
      a[i] = b | ^m[i]
    }
    bndrs[3].max = binary.BigEndian.Uint32(a)
  } else {
    // IPv6
    for i, _ := range bndrs {
      chunk := ipNet.IP[i*4 : (i+1)*4]
      bndrs[i].min = binary.BigEndian.Uint32(chunk)

      t := make([]byte, 4)
      mask := ipNet.Mask[i*4 : (i+1)*4]
      for k, b := range chunk {
        t[k] = b | ^mask[k]
      }
      bndrs[i].max = binary.BigEndian.Uint32(t)
    }

  }

  qs := make([]query.Query, 4)
  for i, bs := range bndrs {
    tq := newNumericRangeInclusiveQuery(bs.min, bs.max, true, true)
    tq.SetField(fmt.Sprintf("_IP%d", i+1))
    qs[i] = tq
  }

  cq := bleve.NewConjunctionQuery(qs...)
  if exactMatch {
    return cq
  }

  blq := bleve.NewBoolFieldQuery(isIPv4)
  blq.SetField("_isIPv4")

  cq.AddQuery(blq)
  return cq
}

func newNumericRangeInclusiveQuery(min, max uint32, minInclusive, maxInclusive bool) *query.NumericRangeQuery {
  m1 := float64(min)
  m2 := float64(max)
  return bleve.NewNumericRangeInclusiveQuery(&m1, &m2, &minInclusive, &maxInclusive)
}

func AugmentIPInfo(input map[string]interface{}, field string) map[string]interface{} {
  if len(input) == 0 {
    return input
  }

  iip, ok := input[field]
  if !ok {
    return input
  }

  ip := net.ParseIP(iip.(string))
  isIPv4 := false
  if ip.DefaultMask() != nil {
    // Only IPv4 addresses have default masks
    isIPv4 = true
  }
  input["_isIPv4"] = isIPv4
  input["_IP1"] = binary.BigEndian.Uint32(ip[0:4])
  input["_IP2"] = binary.BigEndian.Uint32(ip[4:8])
  input["_IP3"] = binary.BigEndian.Uint32(ip[8:12])
  input["_IP4"] = binary.BigEndian.Uint32(ip[12:16])

  return input
}