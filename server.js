var http = require('http');
var https = require('https');
var fs = require('fs');
var express = require("express"); // npm install express
const request = require("request");
var bodyParser = require('body-parser');
var crypto = require('crypto');
var mysql = require("mysql");
const { isNull } = require('util');
const { response } = require('express');

var connection = mysql.createConnection({//local DB에 연결(TEST)
    host: "localhost",
    user: "root",
    password: "8603",
    database: "hido",
    port: "3306"
});

connection.connect();

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; //crt의 self-signed 문제 해결

var key = fs.readFileSync('./keys/hido/hidopr.pem', 'utf-8');
var certificate =  fs.readFileSync('./keys/hido/hido_server.crt', 'utf-8');
var credentials = {key: key, cert: certificate};

var app = express();

app.use(express.json());


request.defaults({ //rejectUnauthorized를 false값으로 두어야 https 서버통신 가능
    strictSSL: false, // allow us to use our self-signed cert for testing
    rejectUnauthorized: false
});

//2. IMEI와 구동 은행 앱 코드에 해당되는 데이터 있으면 FALSE, 없으면 진행 -> sessionKey 전달
app.post("/registration/fingerprint", function(req, res){
    //유저가 HIDO 서버에 생체정보 등록 요청

    //임시로 넣어둠.
    var sessionKey='d4nu/BE1tZenlaXDS8jjWe9NdF/g0N5MhIbni+ang+pXO/tGQHDEF1QG8Qt+i9Oc3G/Xe0aj1/1a1irAslS4Xw==';
    var curBankCode='001';//현재 구동중인 은행 앱 코드
    var IMEI = '1234';

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
                        console.log(jsonData);
                    }
                }
            });
    }else{
        console.log("key를 받아오지 못했음. False");
        var jsonData={"sessionKey":null, "bankcode":null};
        res.send(jsonData);
    }
});

//3.bankapp 서버에 SessionKey 전달해서 CI 값 받아오기
request('https://127.0.0.1:3000/registration/fingerprint', function (error, response, body) {
        //console.error('error:', error);
        //console.log('statusCode:', response && response.statusCode); 
        console.log('body:', body);

        if (!error && response.statusCode ==200){
            var data = JSON.parse(body);
            console.log(data);

            var sessionKey = data.sessionKey;
            var CI = data.CI;
            var bankcode=data.bankcode;
        
            //5. DB 데이터 수정, sessionKey로 검색해서 CI 값 추가.
            app.post("/registration/fingerprint", function(req, res){
                var sql = "UPDATE fingerprint SET CI = ? WHERE sessionKey = ?";
                connection.query(
                    sql,[CI, sessionKey],function(error, results){
                        if(error)   throw error;
                        else{
                            console.log("update ci fingerprint table");
                            var dbSessionKey=results[0].sessionKey;
                            var dbBankCode=results[0].bankcode;
    
                            console.log(dbSessionKey, dbBankCode);
    
                            if(dbSessionKey==sessionKey&&dbBankCode==bankcode){
                                console.log("fingerprint table에 CI값 등록");
                                res.send(1);
                            }
                            else{
                                console.log("false");
                            }
                        }
                });
            });
        }
}); 

app.post("regi")

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