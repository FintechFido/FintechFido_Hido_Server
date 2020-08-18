var http = require('http');
var https = require('https');
var fs = require('fs');
var express = require("express"); // npm install express
const request = require("request");


process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; //crt의 self-signed 문제 해결

var key = fs.readFileSync('./keys/hidopr.pem', 'utf-8');
var certificate =  fs.readFileSync('./keys/hido_server.crt', 'utf-8');
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

request.defaults({ //rejectUnauthorized를 false값으로 두어야 https 서버통신 가능
    strictSSL: false, // allow us to use our self-signed cert for testing
    rejectUnauthorized: false
});

/*
request('https://127.0.0.1:3000/get_test', //localhost
    function (error, response, body) {
        console.error('error:', error); // Print the error if one occurred
        console.log('statusCode:', response && response.statusCode); // Print the response status code if a response was received
        console.log('body:', body); // Print the HTML for the Google homepage.
    }); //Web_Server.js에서 보낸 값을 받아옴
// fs.createReadStream('file.json').pipe(request.put('http://mysite.com/obj.json'))
*/

request('https://127.0.0.1:3000/registration/fingerprint', 
    function (error, response, body) {
        console.error('error:', error); // Print the error if one occurred
        console.log('statusCode:', response && response.statusCode); // Print the response status code if a response was received
        console.log('body:', body); // Print the HTML for the Google homepage.
    }); 

/* read json file _비동기 방식
fs.readFile('./todos.json', 'utf8', (error, jsonFile) => {
    if (error) return console.log(error);
    console.log(jsonFile);

    const jsonData = JSON.parse(jsonFile);
    console.log(jsonFile);

    const todos = jsonData.todos;
    todos.forEach(todo => {
        console.log(todo);
    });
});
*/
var httpsServer = https.createServer(credentials, app);
httpsServer.listen(3002);
console.log('Server running');