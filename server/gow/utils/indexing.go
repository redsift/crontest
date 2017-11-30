package utils

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jpillora/backoff"
	"github.com/redsift/bleve"
	"github.com/redsift/bleve/analysis/analyzer/web"
	"github.com/redsift/bleve/index/upsidedown"
	"github.com/redsift/bleve/mapping"
	"github.com/redsift/blevex/rocksdb"
)

type Datum struct {
	Id   string                 `json:"id"`
	Data map[string]interface{} `json:"data"`
}

func OpenIndex(name string, forSearch bool) (bleve.Index, error) {
	indexPath := os.Getenv("_LARGE_STORAGE_rocksdb_store_" + name)
	if len(indexPath) == 0 {
		return nil, errors.New("node has no large storage with name: " + name)
	}
	ll := os.Getenv("LOGLEVEL")
	isDebug := ll == "debug"

	var idx bleve.Index
	var err error
	if forSearch {
		cfg := map[string]interface{}{
			"read_only": true,
		}
		start := time.Now()
		idx, err = bleve.OpenUsing(indexPath, cfg)
		if isDebug {
			fmt.Printf("Index opened in %s (read)\n", time.Now().Sub(start))
		}
		if err != nil {
			return nil, err
		}
	} else {
		idx, err = openToWriteOrCreate(name, indexPath)
		if err != nil {
			if isDebug {
				fmt.Println("openToWriteOrCreate failed because", err.Error())
			}
			if strings.HasPrefix(err.Error(), "IO error: While lock file") {
				if isDebug {
					fmt.Println("started retries...")
				}
				b := backoff.Backoff{
					Min:    50 * time.Millisecond,
					Max:    2 * time.Second,
					Jitter: true,
				}
				for {
					d := b.Duration()
					if d >= b.Max {
						break
					}
					idx, err = openToWriteOrCreate(name, indexPath)
					if idx != nil {
						break
					}
					time.Sleep(d)
				}
				if err != nil {
					return nil, err
				}
			}
			return nil, err
		}
	}

	return idx, nil
}

func openToWriteOrCreate(name, indexPath string) (bleve.Index, error) {
	ll := os.Getenv("LOGLEVEL")
	isDebug := ll == "debug"
	if isDebug {
		fmt.Println("openToWriteOrCreate...")
	}
	start := time.Now()
	idx, err := bleve.Open(indexPath)
	if err != nil {
		if err != bleve.ErrorIndexMetaMissing {
			return nil, err
		}
		idx, err = createIndex(name, indexPath)
		if err != nil {
			return nil, err
		}
	} else {
		fmt.Printf("Index opened in %s (write)\n", time.Now().Sub(start))
	}
	return idx, nil
}

func createIndex(name, indexPath string) (bleve.Index, error) {
	fmt.Println("Creating new index!")

	stdJustIndexed := bleve.NewTextFieldMapping()
	stdJustIndexed.Store = false
	stdJustIndexed.IncludeInAll = false
	stdJustIndexed.IncludeTermVectors = false

	stdStoredAndIndexed := bleve.NewTextFieldMapping()
	stdStoredAndIndexed.Store = true
	stdStoredAndIndexed.IncludeInAll = true
	stdStoredAndIndexed.IncludeTermVectors = false

	webJustIndexed := bleve.NewTextFieldMapping()
	webJustIndexed.Analyzer = web.Name
	webJustIndexed.Store = false
	webJustIndexed.IncludeInAll = false
	webJustIndexed.IncludeTermVectors = false

	webStoredAndIndexed := bleve.NewTextFieldMapping()
	webStoredAndIndexed.Analyzer = web.Name
	webStoredAndIndexed.Store = true
	webStoredAndIndexed.IncludeInAll = true
	webStoredAndIndexed.IncludeTermVectors = false

	numIndexed := bleve.NewNumericFieldMapping()
	numIndexed.Store = false
	numIndexed.IncludeInAll = false

	boolIndexed := bleve.NewBooleanFieldMapping()
	boolIndexed.Store = false
	boolIndexed.IncludeInAll = false

	dateIndexed := bleve.NewDateTimeFieldMapping()
	dateIndexed.Store = false
	dateIndexed.IncludeInAll = false

	ipIndexed := mapping.NewIPFieldMapping()
	ipIndexed.Store = false
	ipIndexed.IncludeInAll = false

	lineMapping := bleve.NewDocumentStaticMapping()
	if name == "forensics" {
		lineMapping.AddFieldMappingsAt("from", webStoredAndIndexed)
		lineMapping.AddFieldMappingsAt("subject", stdStoredAndIndexed)
		lineMapping.AddFieldMappingsAt("authservId", webJustIndexed)
		lineMapping.AddFieldMappingsAt("spf", stdJustIndexed)
		lineMapping.AddFieldMappingsAt("dkim", stdJustIndexed)
		lineMapping.AddFieldMappingsAt("dkimDomain", webJustIndexed)
		lineMapping.AddFieldMappingsAt("senderIP", ipIndexed)
		lineMapping.AddFieldMappingsAt("date", dateIndexed)
	} else if name == "records" {
		lineMapping.AddFieldMappingsAt("key", stdStoredAndIndexed)

		rowMap := bleve.NewDocumentStaticMapping()
		rowMap.AddFieldMappingsAt("source_ip", ipIndexed)
		rowMap.AddFieldMappingsAt("recordDate", dateIndexed)

		policyMap := bleve.NewDocumentStaticMapping()
		policyMap.AddFieldMappingsAt("disposition", stdJustIndexed)
		policyMap.AddFieldMappingsAt("dkim", stdJustIndexed)
		policyMap.AddFieldMappingsAt("spf", stdJustIndexed)
		rowMap.AddSubDocumentMapping("policy_evaluated", policyMap)

		providerMap := bleve.NewDocumentStaticMapping()
		providerMap.AddFieldMappingsAt("id", stdJustIndexed)
		rowMap.AddSubDocumentMapping("provider", providerMap)

		lineMapping.AddSubDocumentMapping("row", rowMap)

		pdMap := bleve.NewDocumentStaticMapping()
		pdMap.AddFieldMappingsAt("d", stdJustIndexed)
		pdMap.AddFieldMappingsAt("sd", stdJustIndexed)
		pdMap.AddFieldMappingsAt("t", stdJustIndexed)

		providerMap.AddSubDocumentMapping("pd", pdMap)

		identifiersMap := bleve.NewDocumentStaticMapping()
		identifiersMap.AddFieldMappingsAt("header_from", webJustIndexed)

		lineMapping.AddSubDocumentMapping("identifiers", identifiersMap)

		authMap := bleve.NewDocumentStaticMapping()
		dkimMap := bleve.NewDocumentStaticMapping()
		dkimMap.AddFieldMappingsAt("domain", webJustIndexed)
		dkimMap.AddFieldMappingsAt("result", stdJustIndexed)
		dkimMap.AddFieldMappingsAt("selector", stdJustIndexed)

		authMap.AddSubDocumentMapping("dkim", dkimMap)

		spfMap := bleve.NewDocumentStaticMapping()
		spfMap.AddFieldMappingsAt("domain", webJustIndexed)
		spfMap.AddFieldMappingsAt("result", stdJustIndexed)

		authMap.AddSubDocumentMapping("spf", spfMap)

		lineMapping.AddSubDocumentMapping("auth_results", authMap)
	}

	mapping := bleve.NewIndexMapping()
	mapping.DefaultMapping = lineMapping
	mapping.DefaultAnalyzer = "standard"
	idx, err := bleve.NewUsing(indexPath, mapping, upsidedown.Name, rocksdb.Name, nil)
	if err != nil {
		return nil, err
	}

	return idx, nil
}

func UpdateIndex(idx bleve.Index, batchSize int, lines []Datum) error {
	ll := os.Getenv("LOGLEVEL")
	isDebug := ll == "debug"
	start := time.Now()

	var batch *bleve.Batch

	for i, s := range lines {
		if batch == nil {
			batch = idx.NewBatch()
		}
		if err := batch.Index(strings.TrimSpace(s.Id), s.Data); err != nil {
			return err
		}

		if batch.Size() == batchSize {
			if err := idx.Batch(batch); err != nil {
				return err
			}
			batch = nil
		}

		if isDebug {
			if i%100 == 0 {
				fmt.Println("Indexed...", i)
			}
		}
	}

	if batch != nil {
		if err := idx.Batch(batch); err != nil {
			return err
		}
		batch = nil
	}

	fmt.Printf("Indexed %d lines in %0.3fs\n", len(lines), time.Now().Sub(start).Seconds())
	return nil
}
