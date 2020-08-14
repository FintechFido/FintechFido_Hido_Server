var http = require('http');
var https = require('https');
var fs = require('fs');
var express = require("express"); // npm install express

var key = fs.readFileSync('./keys/hidoTest/hidopr.pem', 'utf-8');
var certificate =  fs.readFileSync('./keys/hidoTest/hido_server.crt', 'utf-8');
var credentials = {key: key, cert: certificate};

var app = express();

app.use(express.json());

app.get("/get_test", function(req,res){
    console.log("get");
    res.writeHead(200);
    res.end("GET Success");
})

app.post("/post_test", function(req,res){
    console.log(req.body);
    res.send("Post Success");
})

var httpsServer = https.createServer(credentials, app);
httpsServer.listen(3002);
console.log('Server running');