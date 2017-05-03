var https = require('https')
var fs = require('fs')
var express = require('express')
var app = express()

const port = 4433;

app.get('/:index', function(req, res) {
    var index = req.params.index;
    var result = index + "Name\n" + index + "Phone\n";
    res.send(result);
})

var options = {
    key: fs.readFileSync('./keys/server-key.pem'),
    ca: [fs.readFileSync('./keys/ca-cert.pem')],
    cert: fs.readFileSync('./keys/server-cert.pem')
};

https.createServer({
    key: options.key,
    ca: options.ca,
    cert: options.cert
}, app).listen(port);

console.log('Server listening at ' + port);