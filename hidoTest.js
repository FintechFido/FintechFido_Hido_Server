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

app.use(express.urlencoded({ extended: false }));//form에서 데이터를 받아오자!

app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

app.use(express.static(path.join(__dirname, "public"))); //to use static asset

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

request.defaults({ //rejectUnauthorized를 false값으로 두어야 https 서버통신 가능
    strictSSL: false, // allow us to use our self-signed cert for testing
    rejectUnauthorized: false
});

//1. 서버 상태 확인.
app.get("/", function(req,res){
    console.log("server - get Test");
    var output = {
        "mode":"access",
        "result":"true"
    };
    console.log(output);
    res.send(output);
});

// app.get("/registration/fingerprint",function(req,res){
//     console.log("fingerprint page");
//     var input = {
//         "sessionKey":"test",
//         "running":"007",
//         "imei" :"1234567"
//     }
//     res.send(input);
// });

//4-1. 지문등록 유무 확인 요청
app.get("/registration/fingerprint", function(req, res){
    // var sessionKey = req.body.sessionKey;
    // var running = req.body.running;
    // var hash_imei = req.body.imei;

    //임시 값.(이미 등록된 지문)
    var sessionKey = 'test';
    var running = '007';
    var hash_imei = '1234567';

    //임시 값(등록되지 않은 지문)
    // var sessionKey = '112233';
    // var running = '005';
    // var hash_imei = '987654321';

    //4-2. 지문등록 유무확인
    var sql = "SELECT * FROM hido.key WHERE IMEI = ?";
    connection.query(
        sql,[hash_imei], function(error, results){
            if(error)   throw error;
            else{
                if(results.length==0)
                {
                    console.log("등록되지 않은 지문입니다.");

                    var output={
                        "mode":"register_check",
                        "result":"true"
                    }
                    
                    console.log(output);
                    res.set(output);

                    //지문등록 하기
                    var toBankServer = {
                        "sessionKey":sessionKey
                    };
                    res.send(toBankServer);

                    //4. 세션키로 A Bank Server에 CI요청
                    request('https://127.0.0.1:3000/registration/fingerprint', function (error, response, body) {
                        console.error('error:', error);
                        console.log('statusCode:', response && response.statusCode); 
                        console.log('body:', body);
                        
                        if (!error && response.statusCode == 200){
                            var data = JSON.parse(body);
                            var CI = data.CI;
                        
                            //6. 지문등록 DB에 등록                 
                            var sql2 = "INSERT INTO fingerprint (`CI`, `curBankCode`, `sessionKey`) VALUES (?,?,?)";
                            connection.query(
                                sql2,[CI, running, sessionKey],function(error, results){
                                    if(error)   throw error;
                                    else{
                                        console.log("fingerprint DB insert");
                                        //key db 에도 등록
                                        var sql3 = "INSERT INTO hido.key (`CI`, `bankcode`, `IMEI`) VALUES (?,?,?)";
                                        connection.query(
                                            sql3,[CI, running, hash_imei],function(error, results){
                                                if(error)   throw error;
                                                else{
                                                    console.log("key DB insert");
                                                    console.log("지문등록 완료");

                                                    var output={
                                                        "mode":"register_check",
                                                        "result":"false"
                                                    }
                                                    
                                                    console.log(output);
                                                    res.send(output);   
                                                }
                                            });                          
                                    }
                                });                       
                        }
                    });
                }
                else{
                    var dbimei = results[0].IMEI;
                    var dbBankCode = results[0].bankcode;

                    if(dbimei == hash_imei && dbBankCode == running){
                        console.log("등록된 지문입니다.");

                        var output={
                            "mode":"register_check",
                            "result":"false"
                        }
                        
                        console.log(output);
                        res.set(output);
                    }            
                }
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


//6. 사용자 인증
app.get("/fingerprint/valid", function(req,res){
    
    // var sessionKey = req.body.sessionKey;
    // var imei = req.body.imei;
    // var running = req.body.running;
    // var saved = req.body.saved;

    //임시값
    var sessionKey = 'test';
    var hash_imei = '1234567';
    var running = '007';//구동 은행
    var saved = '001';//생체 정보가 저장된 은행

    //1.지문등록 유무 확인
    sql = "SELECT * FROM hido.key WHERE IMEI = ? AND bankcode = ? ";
    connection.query(
        sql,[hash_imei, running],function(error, results){
            if(error)   throw error;
            else{
                //2.지문정보 확인
                var dbimei = results[0].IMEI;
                var dbBankCode = results[0].bankcode;
                if(dbimei==hash_imei && dbBankCode==running)
                {
                    console.log("지문 등록 되어있음.");

                    //3.지문 등록 확인 결과 및 챌린지 넘버 전송
                    var CI = results[0].CI;
                    var randomNum = Math.floor(Math.random()*1000)+1;//랜덤으로 챌린지 넘버 생성 
                    console.log(randomNum);
                    var challengeNum=(crypto.createHash('sha512').update(String(randomNum)).digest('base64'));//암호화

                    //certification DB 데이터 추가 
                    sql2 = "INSERT INTO certification (`CI`,`useBankCode`,`saveBankCode`, `sessionKey`,`challengeNum`) VALUE (?,?,?,?,?);"
                    connection.query(
                        sql2,[CI, running, saved, sessionKey, challengeNum], function(error, results){
                            if(error)   throw error;
                            else{
                                console.log("db certification에 데이터 넣었음");
                                var output={
                                    "mode":"fingerprint_valid",
                                    "result":"true",
                                    "challengeNum":challengeNum
                                };
                                res.send(output);
                            }
                        });
                }
                else{
                    console.log("지문등록이 되어 있지 않음.");
                    var output={
                        "mode":"fingerprint_valid",
                        "result":"false",
                        "challengeNum":null
                    };
                    res.send(output);
                }
            }
    });

});

//11. 사용자 검증 : H(SessionKey)와 구동중인 은행 앱 코드로 인증 DBMS에서
//H(CI)와 public B가져옴
app.get("/auth", function(req, res){
    // 유저가 HIDO 서버에 지문 인식 요청
    // input : session_key, imei, running, saved, challenge_number

    //임시값.
    var sessionKey = 'test';
    var hash_imei = '1234567';
    var running = '007';
    var saved = '001';
    var challenge_number = 'fVRF7lVZZFvXLbI3oLRIvsZMM8cL4hTpdNp60PUjJ4y7DHfEppD/dRtowxhDfs4q726ylRikHF7IA3IY7W+/DQ==';//243

    var publicKeyB = 'DHfEppD/dRtowxhDfs4q726ylRikHF7IA3IY7W+/DQ==';//임시값

    // 인증 DB에서 [구동 앱 은행 코드 , 세션키] 로 CI 획득해서 7번 먼저 처리
    sql = "SELECT * FROM certification WHERE useBankCode = ? AND sessionKey = ?";
    connection.query(
        sql,[running, sessionKey], function(error, results){
            if(error)   throw error;
            else{
                console.log("검증...");

                var dbUseBankCode = results[0].useBankCode;
                var dbsessionKey=results[0].sessionKey;
                var dbchallenge_number = results[0].challengeNum;

                if(dbUseBankCode == running && dbsessionKey == sessionKey){
                    //CI값 가져오기
                    var dbCI = results[0].CI;

                    //key db에서 [CI, 생체정보가 저장된 은행 코드] 로 key A 획득 후 키 조합하여 복호화 및 비교
                    sql2 = "SELECT * FROM hido.key WHERE CI = ? AND bankcode = ?";
                    connection.query(
                        sql2, [dbCI, running], function(error, results2){
                            if(error)   throw error;
                            else{
                                var publicKeyA  = results2[0].publicKeyA;
                                
                                var publicKey = publicKeyA+publicKeyB;
                                console.log("publicKey ",publicKey);
                                // 복호화
                                // var decipher = crypto.createDecipher('aes192', publicKey); // Decipher 객체 생성
                                // decipher.update(dbchallenge_number, 'base64', 'utf8');   // 인코딩 방식에 따라 복호화
                                // var decipheredOutput = decipher.final('utf8');       // 복호화된 결과 값
                                // console.log(decipheredOutput);

                                //검사는 나중에...ㅠㅠ
                            }
                        }); 
                }
                else{
                    console.log("인증 자체가 되지 않았음.");
                    var output ={
                        "mode" : "auth" , 
                        "result" : "false"
                    };
                        
                    console.log(output);
                }
            }

        });

});

var httpsServer = https.createServer(credentials, app);
httpsServer.listen(3002);
console.log('Server running');