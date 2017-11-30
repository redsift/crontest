package utils

import (
  "os"
  "fmt"
  "testing"
  "time"
)

func TestOpenIndexLocking(t *testing.T) {
  os.Setenv("_LARGE_STORAGE_rocksdb_store_forensics", "/run/sandbox/sift/sdk_tmp/large-storage/sdk@redsift.io/sift/rocksdb_store_forensics")
  idx, err := OpenIndex("forensics", false)
  if err != nil {
    fmt.Println(err)
  }
  time.Sleep(5 * time.Minute)
  // time.Sleep(1 * time.Second)
  idx.Close()
}
