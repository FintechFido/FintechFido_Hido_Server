const crypto = require('crypto');
const aes256 = require('aes256');
 
var key= 'test';      // 암호화, 복호화를 위한 키
var input = 'node.js';  // 암호화할 대상

//일방향 해시
var hash_testKey = (crypto.createHash('sha512').update(key).digest('base64'));
console.log("Hash Result : ", hash_testKey);
 
// 암호화
var cipher = crypto.createCipher('aes192', key);    // Cipher 객체 생성
cipher.update(input, 'utf8', 'base64');             // 인코딩 방식에 따라 암호화
var cipheredOutput = cipher.final('base64');        // 암호화된 결과 값
 
// 복호화
var decipher = crypto.createDecipher('aes192', key); // Decipher 객체 생성
decipher.update(cipheredOutput, 'base64', 'utf8');   // 인코딩 방식에 따라 복호화
var decipheredOutput = decipher.final('utf8');       // 복호화된 결과 값
 
// 출력
console.log('기존 문자열: ' + input);
console.log('암호화된 문자열: ' + cipheredOutput);
console.log('복호화된 문자열: ' + decipheredOutput);