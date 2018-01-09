/**
 * Crontest Sift. DAG's 'Node1' node implementation
 */
'use strict';

// Entry point for DAG node
// got ={
//   in: ... // contains the key/value pairs that match the given query
//   with: ... // key/value pairs selected based on the with selection
//   lookup: ... // an array with result of lookup for a specific key
//   query: ... // an array containing the key hierarchy
// }
// for more info have a look at:
// http://docs.redsift.com/docs/server-code-implementation
var crypto = require("crypto");
var moment = require("moment");

function randomDate(start, end) {
  return moment(start.valueOf() + Math.random() * (end.valueOf() - start.valueOf()));
}

module.exports = function(got) {
  var id = crypto.randomBytes(10).toString('hex');
  var numForensics = parseInt(process.env.NUM_OF_STUBS) || 100
  var res = [];
  for (var i = 0; i < numForensics; i++) {
    var NUM_OF_DATES_TO_KEEP = 14
    var date = randomDate(moment().subtract(NUM_OF_DATES_TO_KEEP + 2, 'days'), moment().subtract(NUM_OF_DATES_TO_KEEP - 2, 'days')).toISOString()
    res.push({
      name: 'forensics-st',
      key: `redsift.com/${id}-${i}`,
      value: {
        "date":date,"timestamp":1509497567,"from":"Google Platform <carrkees@redsift.com>","subject":"Your Apple ID was used to sign in to FaceTime on an iPhone 7",
        "forensicId":"PDEyMzQ1NjczMnAtbGcHBsZS5jb20-" + i, "headers":{"authentication-results":"hotmail.com; spf=softfail (sender IP is 192.168.0.64; identity alignment result); dkim=none header.d=redsift.com"}
      }
    });
  }
  console.log("done with generating data")
  return res
};
