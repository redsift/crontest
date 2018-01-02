package deleteentries

import (
	"encoding/json"
	"fmt"
	"os"
	"server/gow/utils"

	"github.com/redsift/bleve"
	"github.com/redsift/go-sandbox-rpc"
)

func Compute(got sandboxrpc.ComputeRequest) ([]sandboxrpc.ComputeResponse, error) {
	var resp []sandboxrpc.ComputeResponse
	ll := os.Getenv("LOGLEVEL")
	isDebug := ll == "debug"

	indexName := "forensics"

	idx, err := utils.OpenIndex(indexName, true, false)
	if err != nil {
		return nil, fmt.Errorf("error opening index: %s", err.Error())
	}
	defer idx.Close()

	bq := utils.BeforeLastTwoWeeksDateQuery("date")
	// bq := utils.BeforeLastTwoWeeksNumericQuery("date")

	searchRequest := bleve.NewSearchRequest(bq)
	searchRequest.Fields = []string{"*"}
	searchRequest.Size = 10000

	searchResult, err := idx.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("error while searching: %s", err.Error())
	}
	if isDebug {
		b, _ := json.MarshalIndent(searchResult, "", "  ")
		fmt.Println("searchResults: ", string(b[:]))
	}

	rids := utils.OnlyIdsFromSearchResults(searchResult, indexName, "")
	fmt.Println("onlyids", rids)
	// err = utils.DeleteFromIndex(idx, 200, rids)
	// if err != nil {
	// 	return nil, fmt.Errorf("error while deleting: %s", err.Error())
	// }

	return nil, nil
}
