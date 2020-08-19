const path = require("path");
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

app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

app.use(express.static(path.join(__dirname, "public"))); //to use static asset

request.defaults({ //rejectUnauthorized를 false값으로 두어야 https 서버통신 가능
    strictSSL: false, // allow us to use our self-signed cert for testing
    rejectUnauthorized: false
});

//2. IMEI와 구동 은행 앱 코드에 해당되는 데이터 있으면 FALSE, 없으면 진행 -> sessionKey 전달
app.get("/registration/fingerprint", function(req, res){
    //유저가 HIDO 서버에 생체정보 등록 요청

    //임시로 넣어둠.
    var testSession = 'test';
    var testIMEI = '1234';
    var hash_sessionKey=(crypto.createHash('sha512').update(String(testSession)).digest('base64'));
    var curBankCode='001';//현재 구동중인 은행 앱 코드
    var hash_IMEI = (crypto.createHash('sha512').update(String(testIMEI)).digest('base64'));
    //var hash_IMEI = testIMEI;//test값 -> db에 존재함.

    console.log('hash_IMEI', hash_IMEI);

    //key table에서 IMEI가 있는지 먼저 검사, 없으면 fingerprint table에 은행코드랑 sessionKey 등록
    var sql = "SELECT * FROM hido.key WHERE IMEI = ?";
    connection.query(
        sql,[hash_IMEI, curBankCode], function(error, results){
            if(error)   throw error;
            else{
                if(results.length == 0){
                    console.log("등록이 안된 IEMI -> fingertable에 등록");

                    var sql2 = "INSERT INTO fingerprint (`curBankCode`, `sessionKey`) VALUES (?,?)";
                        connection.query(
                            sql2,[curBankCode, hash_sessionKey], function(err, results){
                                if(err) throw err;
                                else{
                                    console.log("fingerprint table에 등록 완료");
                                    var jsonData={"sessionKey":hash_sessionKey, "bankcode":curBankCode};
                                    res.send(jsonData);
                                }
                            }
                        )
                }
                else{
                    console.log("이미 등록된거");
                    var dbIMEI = results[0].IMEI;
                    var dbBankCode=results[0].curBankCode;

                    if(dbIMEI==hash_IMEI && dbBankCode==curBankCode){
                        //3번 프로세스 -> bankapp서버에서 ci값 반환
                        var jsonData={"sessionKey":hash_sessionKey, "bankcode":curBankCode};
                        res.send(jsonData);
                    }
                }

                //3.bankapp 서버에 SessionKey 전달해서 CI 값 받아오기
                console.log("3번 프로세스...");
                request('https://127.0.0.1:3000/registration/fingerprint', function (error, response, body) {
                    //console.error('error:', error);
                    //console.log('statusCode:', response && response.statusCode); 
                    console.log('body:', body);

                    if (!error && response.statusCode == 200){
                        var data = JSON.parse(body);
                        console.log(data);

                        //이미 다 hash된 값이 넘어옴.
                        var CI = data.CI;
                        var sessionKey=data.sessionKey;
                        var bankcode=data.bankcode;
                    
                        console.log("5번 프로세스...");
                        //5. DB 데이터(fingertable) 수정, sessionKey로 검색해서 CI 값 추가.                 
                        var sql = "UPDATE fingerprint SET CI = ? WHERE sessionKey = ?";
                        connection.query(
                            sql,[CI, sessionKey],function(error, results){
                                if(error)   throw error;
                                else{
                                    console.log("update ci fingerprint table");
                                }
                        });
                        
                    }
                });
            }
        });  
});

// =============================== get/post test ====================================
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