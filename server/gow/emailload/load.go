package emailload

import (
	"encoding/json"
	"fmt"
	"server/gow/utils"

	"github.com/redsift/go-sandbox-rpc"
)

// Indexing the following fields: from, to, subject, headers.authentication-results
func Compute(req sandboxrpc.ComputeRequest) ([]sandboxrpc.ComputeResponse, error) {
	inData := req.In.Data
	if len(inData) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	idx, err := utils.OpenIndex("forensics", false)
	if err != nil {
		return nil, fmt.Errorf("error creating index: %s", err.Error())
	}
	defer idx.Close()

	batch := 1000
	var datums []utils.Datum
	for _, v := range inData {
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

		headers := entry["headers"].(map[string]interface{})
		headers["authentication-results"] = nil
		ar := utils.ParseAuthenticationResults(headers["authentication-results"].(string))
		for k, v := range ar {
			entryToIndex[k] = v
		}

		datums = append(datums, utils.Datum{
			Id:   v.Data.Key,
			Data: entryToIndex,
		})
	}

	err = utils.UpdateIndex(idx, batch, datums)
	if err != nil {
		return nil, err
	}

	return nil, nil
}
