var http = require('http');
var https = require('https');
var fs = require('fs');
var express = require("express"); // npm install express
const request = require("request");
var mysql = require("mysql");
const aes256 = require('aes256');
var crypto = require('crypto');

//promise, pm2, async 사용법

var app = express();
app.use(express.json());

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; //crt의 self-signed 문제 해결

var key = fs.readFileSync('./keys/hidopr.pem', 'utf-8');
var certificate = fs.readFileSync('./keys/hido_server.crt', 'utf-8');
var credentials = { key: key, cert: certificate };

//원래는 hidoDB가 아니라 key/certification/fingerprint DB 3개로 나눠줘야함.
//우선 hidoDB내에 table3개로 구성
var connection = mysql.createConnection({//local db
    host: "127.0.0.1", //localhost
    user: "root",
    password: "1234",
    database: "hido",
    port: "3306"
    // multipleStatements: true  // 다중쿼리용 설정(지금안됨ㅠ)
});
connection.connect();
// connection.release();


request.defaults({ //rejectUnauthorized를 false값으로 두어야 https 서버통신 가능
    strictSSL: false, // allow us to use our self-signed cert for testing
    rejectUnauthorized: false
});

/*========================= 지문 인증 프로세스 ======================================*/

//3. DB에 IMEI가 있는지 확인 -> 있으면 bankapp 서버에서 CI값 가져오기
app.get("/auth", function (req, res) {
    //client로부터 받은 IMEI, H(sessionKey)임시로 넣어둠.
    //인자 : H(Session Key), IMEI, 구동 중인 앱의 은행코드, 정보가 저장된 은행코드
    var testSession = 'test';
    var testIMEI = '1234';
    var hash_sessionKey = (crypto.createHash('sha512').update(String(testSession)).digest('base64'));
    var hash_IMEI = (crypto.createHash('sha512').update(String(testIMEI)).digest('base64'));
    var curBankCode = '001';
    var saveBankCode = '002';

    var sql = "SELECT * FROM hido.key WHERE IMEI = ? AND bankcode = ?";
    connection.query(
        sql, [hash_IMEI, curBankCode], function (error, results) {
            if (error) throw error;
            else {
                var CI = results[0].CI;
                var randomNum = Math.floor(Math.random() * 1000) + 1;//랜덤으로 챌린지 넘버 생성
                var pr = './keys/hidopr.pem'                         
                var enChallengeNum = crypto.privateEncrypt(pr, Buffer.from(randomNum, 'utf-8')).toString('base64'); // 개인키로 암호화

                console.log(CI, curBankCode, saveBankCode, hash_sessionKey, enchallengeNum);

                //4&5. DB 데이터 추가하고 challengeNum 반환
                sql2 = "INSERT INTO certification (`CI`,`useBankCode`,`saveBankCode`, `sessionKey`,`challengeNum`) VALUE (?,?,?,?,?);"
                connection.query(
                    sql2, [CI, curBankCode, saveBankCode, hash_sessionKey, enchallengeNum], function (error, results) {
                        if (error) throw error;
                        else {
                            console.log("db certification에 데이터 넣었음");
                            var jsonData = { "challengeNum": enchallengeNum };
                            res.send(jsonData);
                        }
                    });
            }
        });
});

//6&8.fido서버에 CI 보내고 publicKeyB 요청 + 11.사용자 검증
request('https://127.0.0.1:3001/auth', function (error, response, body) {
    //console.error('error:', error);
    //console.log('statusCode:', response && response.statusCode); 
    console.log('body:', body);

    if (!error && response.statusCode == 200) {
        var data = JSON.parse(body);
        console.log(data);
        //이미 다 hash된 값이 넘어옴.
        var CI = data.CI;
        var publicKeyB = data.publicKeyB;

        if (publicKeyB != null) {//publickeyB를 certDB에 저장(인증후 삭제)
            var sql = "UPDATE certification SET publicKeyB = ? WHERE CI = ?";
            connection.query(sql, [publicKeyB, CI], function (error, results) {
                if (error) throw error;
                else {
                    console.log("update cert table");
                }
            })
        } else {
            console.log("CI 없음");
        }
    }

    //Q.certificationDB에서 useBankCode, sessionKey 검색해서 CI획득<이미 CI값이 넘어오는데?
    var useBankCode = '001';
    if (CI != null) {//KeyDB에서 CI,useBankCode로 KeyA 획득
        var sql = "SELECT * FROM key WHERE CI = ? AND useBankCode = ?";
        connection.query(sql, [CI, useBankCode], function (error, results) {
            if (error) throw error;
            else {
                var publicKeyA = results[0].publicKeyA;
                var publicKey = publicKeyA + publicKeyB//KeyA+keyB로 완벽한 publicKey 획득
                console.log(publicKey);
            }
        })
    } else {
        console.log("CI 없음");
    }

    /*챌린지넘버 복호화 후, 해시시켜서 certDB에 저장된 챌린지넘버와 비교
     HIDO 서버가 bankapp서버에 인증 결과 전송 */
    var pu = './keys/hidopu.pem'    
    //var enChallengeNum = ??
    var deChallengeNum = crypto.publicDecrypt(pu, Buffer.from(enChallengeNum, 'base64')); // 공개키로 복호화
    console.log("deChallengeNum : " + deChallengeNum.toString() + "\n");
    var hashChallengeNum = (crypto.createHash('sha512').update(String(deChallengeNum)).digest('base64')); //해시

    var sql = "SELECT * FROM certification WHERE CI = ?";
    connection.query(sql, [CI], function (error, results) {
        if (error) throw error;
        else {
            var challengeNum = results[0].challengeNum;
            if (hashChallengeNum == challengeNum) {
                console.log("AUTHENTICATION & TRANSFER: " + "Session Key [" + req.body.session_key + "]  Running App Code [" + req.body.running + "]  IMEI [" + req.body.imei + "]  Saved Bank code [" + req.body.saved + "]  Challenge number [" + req.body.challengeNum + "]");

            } else {
                console.log("AUTHENTICATION - FAIL");
            }
        }
    })
});


var httpsServer = https.createServer(credentials, app);
httpsServer.listen(3002);
console.log('Server running');