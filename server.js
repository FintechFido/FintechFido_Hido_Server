var http = require('http');
var https = require('https');
var fs = require('fs');
var express = require("express"); // npm install express
const request = require("request");
var bodyParser = require('body-parser');
var crypto = require('crypto');
var mysql = require("mysql");

var connection = mysql.createConnection({//local DB에 연결(TEST)
    host: "localhost",
    user: "root",
    password: "8603",
    database: "hido",
    port: "3306"
});

connection.connect();

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; //crt의 self-signed 문제 해결

var key = fs.readFileSync('./keys/hido/hidopr.pem', 'utf-8');
var certificate =  fs.readFileSync('./keys/hido/hido_server.crt', 'utf-8');
var credentials = {key: key, cert: certificate};

var app = express();

app.use(express.json());


request.defaults({ //rejectUnauthorized를 false값으로 두어야 https 서버통신 가능
    strictSSL: false, // allow us to use our self-signed cert for testing
    rejectUnauthorized: false
});

request('https://127.0.0.1:3000/login', //localhost
    function (error, response, body) {
        console.error('error:', error); // Print the error if one occurred
        console.log('statusCode:', response && response.statusCode); // Print the response status code if a response was received
        console.log('body:', body); // Print the HTML for the Google homepage.
    }
);

app.post("/registration/fingerprint", function(req, res){
    //유저가 HIDO 서버에 생체정보 등록 요청
    //1. IMEI와 구동 은행 앱 코드에 해당되는 데이터 있으면 FALSE, 없으면 sessionKey를 전달

    var sessionKey=req.body.sessionKey;//세션키
    var curBankCode=req.body.curBankCode;//현재 구동중인 은행 앱 코드
    var IMEI = req.body.IMEI;

    if(sessionKey!=null)
    {
        var sql="SELECT * FROM key WHERE IMEI=? AND bankcode = ?";
        connection.query(
            sql,[IMEI, curBankCode], function(error, results){
                if(error)   throw error;
                else{
                    var dbIMEI = results[0].IMEI;
                    var dbBankCode=results[0].bankcode;

                    if(dbIMEI==IMEI && dbBankCode==curBankCode){
                        console.log("False");
                        var jsonData={"sessionKey":null, "bankcode":null};
                        res.send(jsonData);
                    }else{
                        console.log("진행");
                        var jsonData={"sessionKey":sessionKey, "bankcode":curBankCode};
                        res.send(jsonData);
                    }
                }
            });
    }else{
        console.log("key를 받아오지 못했음. False");
        var jsonData={"sessionKey":null, "bankcode":null};
        res.send(jsonData);
    }
});

// request('https://127.0.0.1:3000/get_test', //localhost
//     function (error, response, body) {
//         console.error('error:', error); // Print the error if one occurred
//         console.log('statusCode:', response && response.statusCode); // Print the response status code if a response was received
//         console.log('body:', body); // Print the HTML for the Google homepage.
//     });

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
console.log('HIDO_Server running');