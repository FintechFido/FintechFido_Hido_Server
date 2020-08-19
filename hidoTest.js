const path = require("path");
var http = require('http');
var https = require('https');
var fs = require('fs');
var express = require("express"); // npm install express
const request = require("request");
var mysql = require("mysql");
var crypto = require('crypto');
//promise, pm2, async 사용법

var app = express();
app.use(express.json());

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; //crt의 self-signed 문제 해결

var key = fs.readFileSync('./keys/hido/hidopr.pem', 'utf-8');
var certificate = fs.readFileSync('./keys/hido/hido_server.crt', 'utf-8');
var credentials = { key: key, cert: certificate };

//원래는 hidoDB가 아니라 key/certification/fingerprint DB 3개로 나눠줘야함.
//우선 hidoDB내에 table3개로 구성
var connection = mysql.createConnection({//local db
    host: "127.0.0.1", //localhost
    user: "root",
    password: "8603",
    database: "hido",
    port: "3306"
    // multipleStatements: true  // 다중쿼리용 설정
});
connection.connect();
// connection.release();

app.get("/get_test", function (req, res) {
    console.log("get");
    res.writeHead(200);
    res.end("GET Success");
})

app.post("/post_test", function (req, res) {
    console.log(req.body);
    res.send("Post Success");
})

request.defaults({ //rejectUnauthorized를 false값으로 두어야 https 서버통신 가능
    strictSSL: false, // allow us to use our self-signed cert for testing
    rejectUnauthorized: false
});

/* request 예시
request('https://127.0.0.1:3000/get_test', //localhost
    function (error, response, body) {
        console.error('error:', error); // Print the error if one occurred
        console.log('statusCode:', response && response.statusCode); // Print the response status code if a response was received
        console.log('body:', body); // Print the HTML for the Google homepage.
    }); //bankapp 서버에서 보낸 값을 받아옴
// fs.createReadStream('file.json').pipe(request.put('http://mysite.com/obj.json'))
*/

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


//8.client에서 받은 publicKey 분할 ->추후에 client에서 받아오는 request문 작성해줘야함
app.post("/registration/key", function (req, res) {
    global.publicKey = 'a1b2c3d4'; //publickey는 client을 거쳐서 넘어옴(우선 임의로 지정)

    if (publicKey != null) {
        var a = (publicKey.length) / 2;
        global.publicKeyA = publicKey.substr(0, a); //A는 hidoDB에 저장
        global.publicKeyB = publicKey.substr(a,); //B는 fidoDB에 저장
        
        } else {
        console.log("publickey 없음");
    }

    /*9.db 데이터 추가&삭제
    fingerprint table에서 은행코드, Session Key로 검색해서 CI 값 얻기
    CI와 연결된 PublicKeyA key table에 추가(update)*/

    if (sessionKey != null && bankcode != null && CI != null) {
        var sqls = "SELECT * FROM fingerprint WHERE sessionKey = ? AND bankcode = ?;"
                    +"UPDATE key SET publicKeyA = ? WHERE CI = ?;";
        connection.query(
            sqls, [sessionKey, bankcode, publicKeyA, CI], function (error, results) {
                if (error) throw error;
                else {
                    console.log(results);
                    var sessionKey = results[0].sessionKey;
                    var dbBankCode = results[0].bankcode;
                    var dbCI = results[0].CI;
                    
                    var jsonDataTofido = {"publicKeyB": publicKeyB, "CI": dbCI};
                    res.send(jsonDataTofido); //fido에 CI, publicKeyB를 넘겨줘야함
                }
            });
    } else {
        console.log("error");
    }
});

/*========================= 지문 인증 프로세스 ======================================*/

//3. DB에 IMEI가 있는지 확인 -> 있으면 bankapp 서버에서 CI값 가져오기
app.get("/auth", function(req, res){
    //client로부터 받은 IMEI, H(sessionKey)임시로 넣어둠.
    //인자 : H(Session Key), IMEI, 구동 중인 앱의 은행코드, 정보가 저장된 은행코드
    var testSession = 'test';
    var testIMEI = '1234';
    var hash_sessionKey=(crypto.createHash('sha512').update(String(testSession)).digest('base64'));
    var hash_IMEI = (crypto.createHash('sha512').update(String(testIMEI)).digest('base64'));
    var curBankCode = '001';
    var saveBankCode = '002';

    var sql = "SELECT * FROM hido.key WHERE IMEI = ? AND bankcode = ?";
    connection.query(
        sql,[hash_IMEI, curBankCode],function(error, results){
            if(error)   throw error;
            else{
                var CI = results[0].CI;
                var randomNum = Math.floor(Math.random()*1000)+1;//랜덤으로 챌린지 넘버 생성 
                var challengeNum=(crypto.createHash('sha512').update(String(randomNum)).digest('base64'));//암호화

                console.log(CI, curBankCode, saveBankCode, hash_sessionKey, challengeNum);

                //4. DB 데이터 추가하고 5.challengeNum 반환
                sql2 = "INSERT INTO certification (`CI`,`useBankCode`,`saveBankCode`, `sessionKey`,`challengeNum`) VALUE (?,?,?,?,?);"
                connection.query(
                    sql2,[CI, curBankCode, saveBankCode, hash_sessionKey, challengeNum], function(error, results){
                        if(error)   throw error;
                        else{
                            console.log("db certification에 데이터 넣었음");
                            var jsonData={"challengeNum":challengeNum};
                            res.send(jsonData);
                        }
                    });
            }
    });
});

var httpsServer = https.createServer(credentials, app);
httpsServer.listen(3002);
console.log('Server running');