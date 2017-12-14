package emailload

import (
	"encoding/json"
	"fmt"
	"os"
	"server/gow/utils"

	"github.com/redsift/go-sandbox-rpc"
)

// Indexing the following fields: from, to, subject, headers.authentication-results
func Compute(req sandboxrpc.ComputeRequest) ([]sandboxrpc.ComputeResponse, error) {
	mm := os.Getenv("MIGRATION_MODE")
	isMM := mm == "true"
	ll := os.Getenv("LOGLEVEL")
	isDebug := ll == "debug"
	indexPath := os.Getenv("_LARGE_STORAGE_rocksdb_store_forensics")
	if len(indexPath) == 0 && isMM {
		fmt.Println("no op")
		return nil, nil
	}
	inData := req.In.Data
	if len(inData) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	idx, err := utils.OpenIndex("forensics", false, isMM)
	if err != nil {
		return nil, fmt.Errorf("error creating index: %s", err.Error())
	}
	if idx == nil {
		return nil, fmt.Errorf("error creating index, retries failed")
	}

	defer idx.Close()

	var datums []utils.Datum
	for _, v := range inData {
		if v.Data.Value == nil {
			continue
		}

		var entry map[string]interface{}
		err = json.Unmarshal(v.Data.Value, &entry)
		if err != nil {
			return nil, fmt.Errorf("Unmarshal the entry to index failed: %s", err.Error())
		}

		entryToIndex := map[string]interface{}{
			"from":    entry["from"],
			"subject": entry["subject"],
			"date":    entry["date"],
		}

		headers, ok := entry["headers"].(map[string]interface{})
		if ok {
			authenticationResults, ok := headers["authentication-results"].(string)
			if ok {
				ar := utils.ParseAuthenticationResults(authenticationResults)
				for k, v := range ar {
					entryToIndex[k] = v
				}
			}
		}

		datums = append(datums, utils.Datum{
			Id:   v.Data.Key,
			Data: entryToIndex,
		})
	}

	err = utils.UpdateIndex(idx, 250, datums)
	if err != nil {
		return nil, fmt.Errorf("error updating index: %s", err.Error())
	}

	if isMM {
		err = utils.Compact(idx)
		if err != nil{
			return nil, fmt.Errorf("error in advanced: %s", err.Error())
		}
	}

	return nil, nil
}
