using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace JwtValidator2
{
    class Program
    {

        private const string PUBLIC_KEY = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA33TqqLR3eeUmDtHS89qF
3p4MP7Wfqt2Zjj3lZjLjjCGDvwr9cJNlNDiuKboODgUiT4ZdPWbOiMAfDcDzlOxA
04DDnEFGAf+kDQiNSe2ZtqC7bnIc8+KSG/qOGQIVaay4Ucr6ovDkykO5Hxn7OU7s
Jp9TP9H0JH8zMQA6YzijYH9LsupTerrY3U6zyihVEDXXOv08vBHk50BMFJbE9iwF
wnxCsU5+UZUZYw87Uu0n4LPFS9BT8tUIvAfnRXIEWCha3KbFWmdZQZlyrFw0buUE
f0YN3/Q0auBkdbDR/ES2PbgKTJdkjc/rEeM0TxvOUf7HuUNOhrtAVEN1D5uuxE1W
SwIDAQAB
-----END PUBLIC KEY-----";

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
        static void Main(string[] args)
        {
           string token =  Encode();
            Decode(token);
        }

        private static string Encode()
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

        private static void Decode(string token)
        {
            JsonWebKey jsonWebKey;
            using (var textReader = new StringReader(PUBLIC_KEY))
            {
                var pubkeyReader = new PemReader(textReader);

                RsaKeyParameters KeyParameters = (RsaKeyParameters) pubkeyReader.ReadObject();
                var e = Base64UrlEncoder.Encode(KeyParameters.Exponent.ToByteArrayUnsigned());
                var n = Base64UrlEncoder.Encode(KeyParameters.Modulus.ToByteArrayUnsigned());
                var dict = new Dictionary<string, string>()
                {
                    {"e", e},
                    {"kty", "RSA"},
                    {"n", n}
                };

                var hash = SHA256.Create();
                Byte[] hashBytes =
                    hash.ComputeHash(System.Text.Encoding.ASCII.GetBytes(JsonConvert.SerializeObject(dict)));
                jsonWebKey = new JsonWebKey()
                {
                    Kid = Base64UrlEncoder.Encode(hashBytes),
                    Kty = "RSA",
                    E = e,
                    N = n
                };
            }
            TokenValidationParameters validationParameters =
                new TokenValidationParameters
                {
                    ValidIssuer = "mailto:dan@black.com",
                    ValidAudiences = new[] {"testAud"},
                    IssuerSigningKeys = new[] {jsonWebKey}
                };

            SecurityToken validatedToken;
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            var jwt =
                "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsIm5iZiI6MTUwNzEwMDIwNywiZXhwIjoxNTA3MTAzODA3LCJpYXQiOjE1MDcxMDAyMDcsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9.miYBTOintXrtC6_2lHXfUaNsIwNwDcPkRSQ7Q3VPw6dwHawu80GhVIdPno9nIZ0VurlHQWEX9MWacekHvgjfcjO9KexO5ir3aV4PtyXYrmBVBhn3dqQgzy5K5gLek09-jUf84lW15DY6wNP6Gu2LTc9mKwDOcqJWub_LR6mTjZv5HKx3vjqWBF6Jnwus9hmvThv-TtWWlUp7qKaIDvYFhRRoI0_llYFq5pmHol5PVh7npBpSIaTki9Ew66z2jseBS_RKHAklftv6JYBibsYjxz9jGV-oDWzqbWF9ez_xkNksPivkGjQsMT1O_cvNoSbi-FZ06BoBUYZfNJsfXd_2fg";
            var claimsPrincipal = handler.ValidateToken(token, validationParameters, out validatedToken);
            var user = claimsPrincipal;
        }
    }

    class PasswordFinder : IPasswordFinder
    {
        private string password;

        public PasswordFinder(string password)
        {
            this.password = password;
        }


        public char[] GetPassword()
        {
            return password.ToCharArray();
        }
    }
}
