'use strict';

let nodes =  [{
  "#": "RPC trigger",
  "input":{
    "bucket": "trigger"
  },
  "implementation": {
    "javascript": "server/rpc.js"
  },
  "outputs":{
    "trigger-st": {},
    "api_rpc": {}
  }
},
{
  "#": "Cron trigger",
  "implementation":{
    "javascript": "server/cron.js",
    "when":{
      "interval": 180
    }
  },
  "outputs":{
    "trigger-st": {}
  }
},
{
  "#": "Emit Node",
  "input": {
    "bucket": "trigger-st"
  },
  "implementation": {
    "javascript": "server/node1.js"
  },
  "outputs": {
    "forensics-st":{}
  }
}];

const NUMBER_OF_GO_NODES = 20

for (let i=0; i<NUMBER_OF_GO_NODES; i++){
  nodes.push({
    "#": `Update Forensics Index ${i}`,
    "input": {
      "bucket": "forensics-st",
      "select": "/"
    },
    "implementation": {
      "go": "server/gow/emailload/load.go",
      "sandbox": "quay.io/redsift/sandbox-go-rocksdb:v5.8",
      "qos": {
        "large-storage": [
          `rocksdb_store_forensics_${i}:rw`
        ]
      }
    }
  })
}

console.log(JSON.stringify(nodes, null, 2))
