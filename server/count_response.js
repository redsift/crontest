'use strict';

module.exports = function (got) {
  const inData = got.in;
  console.log("count_response triggered!")
  return {
    name: 'api_rpc',
    key: got.get[0].data[0].value.toString(),
    value: {
      status_code: 200,
      body: Buffer.from('forensic-st=' + inData.data.length).toString('base64')
    }
  }
}
