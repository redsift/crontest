package counter

import (
  "fmt"
  "server/gow/utils"

  "github.com/redsift/go-sandbox-rpc"
)

func Compute(req sandboxrpc.ComputeRequest) ([]sandboxrpc.ComputeResponse, error) {
  idx, err := utils.OpenIndex("forensics", true)
  if err != nil {
    return nil, fmt.Errorf("error opening index: %s", err.Error())
  }
  defer idx.Close()

  count, err := idx.DocCount()
  if err != nil {
    return nil, err
  }

  txt := fmt.Sprintf("The DB contains %d documents", count)
  fmt.Println(txt)

  utils.Compact(idx)
  getData := req.Get
  reqID := string(getData[0].Data[0].Value[:])

  return []sandboxrpc.ComputeResponse{utils.NewRPCComputeResponse(reqID, 200, []byte(txt), false)}, nil
}
