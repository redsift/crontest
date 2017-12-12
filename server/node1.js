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
module.exports = function (got) {
  var id = crypto.randomBytes(15).toString('hex');
  var numForensics = process.env.NUM_OF_STUBS || 100
  var res = [];
  for (var i = 0; i < numForensics; i++) {
    res.push({
      name: 'forensics-st',
      key: `redsift.com/${id}-${i}`,
      value: {
        "date":"2017-11-01T00:52:47.000Z",
        "timestamp":1509497567,
        "urls":["http://luckybestservice.ru", "http://www.apple.com/privacy/"],
        "html":"Message body redacted by OnDMARC in accordance with https://tools.ietf.org/html/rfc7489#section-7.3. Original body length: 3567.",
        "attachments":[],
        "from":"Google Platform <carrkees@redsift.com>",
        "to":"REDACTED <postmaster@outlook.com>",
        "subject":"Your Apple ID was used to sign in to FaceTime on an iPhone 7",
        "messageId":"<1234567333989.79297938859175595418.JavaMail.roverp@nwk-roverp-lap12.corp.apple.com>",
        "forensicId":"PDEyMzQ1NjczMzM5ODkuNzkyOTc5Mzg4NTkxNzU1OTU0MTguSmF2YU1haWwucm92ZXJwQG53ay1yb3ZlcnAtbGcHBsZS5jb20-" + i,
        "headers":{
          "authentication-results":"hotmail.com; spf=softfail (sender IP is 192.168.0.64; identity alignment result is pass and alignment mode is relaxed) smtp.mailfrom=carrkees@redsift.com; dkim=none (identity alignment result is pass and alignment mode is relaxed) header.d=redsift.com; x-hmca=fail header.id=carrkees@redsift.com",
        "x-envelope-sender":"carrkees@redsift.com",
        "x-sid-pra":"carrkees@redsift.com",
        "x-auth-result":"FAIL",
        "x-sid-result":"FAIL",
        "received":"from localhost ([192.168.0.64]) by SNT004-MC5F19.hotmail.com with Microsoft SMTPSVC(7.5.7601.23143); Mon, 1 Nov 2017 00:52:47 -0700",
        "message-id":"<1234567333989.79297938859175595418.JavaMail.roverp@nwk-roverp-lap12.corp.apple.com>","mime-version":"1.0","x-emailtype-id":"784633","x-sent-to":"babygirl_636@hotmail.com","x-business-group":"iCloud","content-type":{"value":"text/html","params":{"charset":"UTF-8"}},"content-transfer-encoding":"7BIT","return-path":"carrkees@redsift.com","x-originalarrivaltime":"1 Nov 2017 07:52:47.0641 (UTC) FILETIME=[CE738090:01D29BCE]"}}
    });
  }
  return res
};
