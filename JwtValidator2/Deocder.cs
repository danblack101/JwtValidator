using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace JwtValidator2
{
    class Deocder
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
}