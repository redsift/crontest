package utils

import (
	"strings"
	"time"

	"github.com/redsift/bleve"
	"github.com/redsift/bleve/search/query"
)

// NOTES:
// - double quotes only for dates
// - single quotes for everything else
// - text matching for IPs need to be in single quotes
// - text matching for IPv6 need to escape `:` with `\:`
// - for multiple CIDRs in the same query only the last one will be taken into account
func ParseSearchQuery(hQ string) query.Query {
	uq := strings.TrimSpace(hQ)

	if uq == "_all" {
		return bleve.NewMatchAllQuery()
	}

	var qip query.FieldableQuery
	senderIPFlag := 0
	tq := []string{}
	for _, v := range strings.Split(uq, " ") {
		if !strings.Contains(v, ":") {
			tq = append(tq, v)
			continue
		}

		senderSplit := strings.SplitN(v, ":", 2)
		fieldName := senderSplit[0]
		sq := senderSplit[1]
		switch fN := strings.TrimLeft(fieldName, `+-=&|><!(){}[]^"~*?:\/`); fN {
		case "senderIP", "source_ip":
			// remove quotes so CIDR doesn't fail
			sq = strings.Replace(sq, `"`, ``, 2)
			sq = strings.Replace(sq, `'`, ``, 2)

			// last CIDR overrides previous ones
			qip = query.NewIPRangeQuery(sq)
			qip.SetField(fN)

			if strings.HasPrefix(fieldName, `-`) {
				senderIPFlag = -1
			} else if strings.HasPrefix(fieldName, `+`) {
				senderIPFlag = 1
			}
			continue
		}

		tq = append(tq, v)
	}

	if qip == nil && len(tq) == 0 {
		return bleve.NewMatchNoneQuery()
	}

	qsq := bleve.NewQueryStringQuery(strings.Join(tq, " "))
	if qip == nil {
		return qsq
	}

	boolq := bleve.NewBooleanQuery()
	if len(tq) > 0 {
		boolq.AddShould(qsq)
	}
	switch senderIPFlag {
	case -1:
		boolq.AddMustNot(qip)
	case 0:
		boolq.AddShould(qip)
	case 1:
		boolq.AddMust(qip)
	}
	return boolq

}

func OnlyIdsFromSearchResults(sr *bleve.SearchResult, indexName, domain string) []string {
	hl := []string{}
	for _, hit := range sr.Hits {
		rid := GetHitID(hit.Fields, hit.ID, indexName, domain)
		if len(rid) > 0 {
			hl = append(hl, rid)
		}
	}
	return hl
}

func BeforeLastTwoWeeksDateQuery(fieldName string) query.Query {
	aYearBeforeNow := time.Now().AddDate(-1, 0, 0)
	twoWeeksBeforeNow := time.Now().AddDate(0, 0, -14)
	query := bleve.NewDateRangeQuery(aYearBeforeNow, twoWeeksBeforeNow)
	query.SetField(fieldName)

	return query
}

func BeforeLastTwoWeeksNumberQuery(fieldName string) query.Query {
	aYearBeforeNow := time.Now().AddDate(-1, 0, 0).Seconds()
	twoWeeksBeforeNow := time.Now().AddDate(0, 0, -14).Seconds()
	query := bleve.NewDateRangeQuery(aYearBeforeNow, twoWeeksBeforeNow)
	query.SetField(fieldName)

	return query
}
