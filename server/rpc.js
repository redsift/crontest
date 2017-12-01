'use strict';

module.exports = function (got) {
  const inData = got.in;
  var res = [];
  console.log("rpc triggered!")
  for (var d of inData.data) {
    res.push({
      name: 'api_rpc',
      key: d.key,
      value: {
        status_code: 200,
        body: 'ok'
      }
    })
  }
  res.push({
    name: 'trigger-st',
    key: 'rpc-trigger',
    value: { 'who': 'rpc'}
  })

  return res;
}
