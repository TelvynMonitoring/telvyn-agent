'use strict';
// Small application for verifying installation and source links without customer data.
const http = require('node:http');
let retained = [];

function calculate() {
  let value = 0;
  for (let i = 0; i < 1000000; i++) value += Math.sqrt(i);
  return value;
}

function retainObjects() {
  retained = Array.from({length: 50000}, (_, index) => ({index, values: new Array(20).fill(index)}));
  return retained.length;
}

http.createServer((request, response) => {
  response.setHeader('content-type', 'application/json');
  if (request.url === '/calculate') response.end(JSON.stringify({value: calculate()}));
  else if (request.url === '/retain') response.end(JSON.stringify({objects: retainObjects()}));
  else if (request.url === '/release') { retained = []; response.end('{"released":true}'); }
  else { response.statusCode = 404; response.end('{"error":"not found"}'); }
}).listen(Number(process.env.PORT || 3000), '127.0.0.1');
