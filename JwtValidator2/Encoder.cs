﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace JwtValidator2
{

    class Encoder
    {

        private const string PRIVATE_KEY = @"-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,2E65118E6C7B5207

7cYUTW4ZBdmVZ4ILB08hcTdm5ib0E0zcy+I7pHpNQfJHtI7BJ4omys5S19ufJPBJ
IzYjeO7oTVqI37F6EUmjZqG4WVE2UQbQDkosZbZN82O4Ipu1lFAPEbwjqePMKufz
snSQHKfnbyyDPEVNlJbs19NXC8v6g+pQay5rH/I6N2iBxgsTmuemZ54EhNQMZyEN
R/CiheArWEH9H8/4hd2gc9Tb2s0MwGHILL4kbbNm5tp3xw4ik7OYWNrj3m+nG6Xb
vKXh2xEanAZAyMXTqDJTHdn7/CEqusQPJjZGV+Mf1kjKu7p4qcXFnIXP5ILnTW7b
lHoWC4eweDzKOMRzXmbABEVSUvx2SmPl4TcoC5L1SCAHEmZaKbaY7S5l53u6gl0f
ULuQbt7Hr3THznlNFKkGT1/yVNt2QOm1emZd55LaNe8E7XsNSlhl0grYQ+Ue8Jba
x85OapltVjxM9wVCwbgFyi04ihdKHo9e+uYKeTGKv0hU5O7HEH1ev6t/s2u/UG6h
TqEsYrVp0CMHpt5uAF6nZyK6GZ/CHTxh/rz1hADMofem59+e6tVtjnPGA3EjnJT8
BMOw/D2QIDxjxj2GUzz+YJp50ENhWrL9oSDkG2nzv4NVL77QIy+T/2/f4PgokUDO
QJjIfxPWE40cHGHpnQtZvEPoxP0H3T0YhmEVwuJxX3uaWOY/8Fa1c7Ln0SwWdfV5
gYvJV8o6c3sumcq1O3agPDlHC5O4IxG7AZQ8CHRDyASogzfkY6P579ZOGYaO4al7
WA1YIpsHs3/1f4SByMuWe0NVkFfvXckjpqGrBQpTmqQzk6baa0VQ0cwU3XlkwHac
WB/fQ4jylwFzZDcp5JAo53n6aU72zgNvDlGTNKwdXXZI5U3JPocH0AiZgFFWYJLd
63PJLDnjyE3i6XMVlxifXKkXVv0RYSz+ByS7Oz9aCgnQhNU8ycv+UxtfkPQih5zE
/0Y2EEFknajmFJpNXczzF8OEzaswmR0AOjcCiklZKRf61rf5faJxJhhqKEEBJuL6
oodDVRk3OGU1yQSBazT8nK3V+e6FMo3tWkra2BXFCD+pKxTy014Cp59S1w6F1Fjt
WX7eMWSLWfQ56j2kLMBHq5gb2arqlqH3fsYOTD3TNjCYF3Sgx309kVPuOK5vw61P
pnL/LN3iGY42WR+9lfAyNN2qj9zvwKwscyYs5+DPQoPmcPcVGc3v/u66bLcOGbEU
OlGa/6gdD4GCp5E4fP/7GbnEY/PW2abquFhGB+pVdl3/4+1U/8kItlfWNZoG4FhE
gjMd7glmrdFiNJFFpf5ks1lVXGqJ4mZxqtEZrxUEwciZjm4V27a+E2KyV9NnksZ6
xF4tGPKIPsvNTV5o8ZqjiacxgbYmr2ywqDXKCgpU/RWSh1sLapqSQqbH/w0MquUj
VhVX0RMYH/foKtjagZf/KO1/mnCITl86treIdachGgR4wr/qqMjrpPUaPLCRY3JQ
00XUP1Mu6YPE0SnMYAVxZheqKHly3a1pg4Xp7YWlM671oUORs3+VENfnbIxgr+2D
TiJT9PxwpfK53Oh7RBSWHJZRuAdLUXE8DG+bl0N/QkJM6pFUxTI1AQ==
-----END RSA PRIVATE KEY-----
";
        public static string Encode()
        {

          
            RSAParameters rsaParams;
            using (var tr = new StringReader(PRIVATE_KEY))
            {
                var pemReader = new PemReader(tr, new PasswordFinder("passwd"));
                var keyPair = pemReader.ReadObject() as AsymmetricCipherKeyPair;
                if (keyPair == null)
                {
                    throw new Exception("Could not read RSA private key");
                }
                var privateRsaParams = keyPair.Private as RsaPrivateCrtKeyParameters;
                rsaParams = DotNetUtilities.ToRSAParameters(privateRsaParams);
            }
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                // Dictionary<string, object> payload = claims.ToDictionary(k => k.Type, v => (object)v.Value);
                var utc0 = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
                var issueTime = DateTime.Now;

                var iat = (int)issueTime.Subtract(utc0).TotalSeconds;
                var exp = (int)issueTime.AddMinutes(55).Subtract(utc0).TotalSeconds; // Expiration time is up to 1 hour, but lets play on safe side

                var payload = new Dictionary<string, object>()
                {
                    { "sub", "mr.x@contoso.com" },
                    { "iss", "mailto:dan@black.com" },
                    { "aud", "testAud" },
                    { "nbf", 1507100207 },
                    { "iat",  iat },
                    { "exp", exp }
                };
                var token =  Jose.JWT.Encode(payload, rsa, Jose.JwsAlgorithm.RS256);
                return token;
            }
        }
    }
}