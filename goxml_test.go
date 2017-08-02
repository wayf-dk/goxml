package goxml

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"github.com/lestrrat/go-libxml2/types"
//    . "github.com/y0ssar1an/q"
)

type Testparams struct {
	spmd, idpmd, hubmd, testidpmd *Xp
	cookiejar                     map[string]map[string]*http.Cookie
	idpentityID                   string
	usescope                      bool
	usedoubleproxy                bool
	resolv                        map[string]string
	initialrequest                *Xp
	newresponse                   *Xp
	resp                          *http.Response
	responsebody                  []byte
	err                           error
	logredirects                  bool
}

var (
	_  = log.Printf // For debugging; delete when done.

    response = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:zzz="urn:oasis:names:tc:SAML:2.0:assertion" ID="_229827eaf5c5b8a7b49b3eb6b87e2bc5c564e49b8a" Version="2.0" IssueInstant="2017-06-27T13:17:46Z" Destination="https://wayfsp.wayf.dk/ss/module.php/saml/sp/saml2-acs.php/default-sp" InResponseTo="_1b83ac6f594b5a8c090e6559b4bf93195e5e766735"><saml:Issuer>https://wayf.wayf.dk</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="pfx2e019b04-679e-c848-ff60-9d7159ad84dc" Version="2.0" IssueInstant="2017-06-27T13:17:46Z"><saml:Issuer>https://wayf.wayf.dk</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="https://wayfsp.wayf.dk" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_a310d22cbc3be669f6c7906e409772a54af79b04e5</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2017-06-27T13:22:46Z" Recipient="https://wayfsp.wayf.dk/ss/module.php/saml/sp/saml2-acs.php/default-sp" InResponseTo="_1b83ac6f594b5a8c090e6559b4bf93195e5e766735"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2017-06-27T13:17:16Z" NotOnOrAfter="2017-06-27T13:22:46Z"><saml:AudienceRestriction><saml:Audience>https://wayfsp.wayf.dk</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2017-06-27T13:17:44Z" SessionNotOnOrAfter="2017-06-27T21:17:46Z" SessionIndex="_270f753ff25f97b7c70f981c052d59b7326d5a05c6"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef><saml:AuthenticatingAuthority>https://wayf.ait.dtu.dk/saml2/idp/metadata.php</saml:AuthenticatingAuthority></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">madpe@dtu.dk</saml:AttributeValue></saml:Attribute><saml:Attribute Name="gn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">Mads Freek</saml:AttributeValue></saml:Attribute><saml:Attribute Name="sn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">Petersen</saml:AttributeValue></saml:Attribute><saml:Attribute Name="cn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">Mads Freek Petersen</saml:AttributeValue></saml:Attribute><saml:Attribute Name="preferredLanguage" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">da-DK</saml:AttributeValue></saml:Attribute><saml:Attribute Name="organizationName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">Danmarks Tekniske Universitet</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonPrincipalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">madpe@dtu.dk</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonPrimaryAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">staff</saml:AttributeValue></saml:Attribute><saml:Attribute Name="schacPersonalUniqueID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408590763</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonAssurance" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">2</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonEntitlement" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:tcs:escience-user</saml:AttributeValue></saml:Attribute><saml:Attribute Name="schacHomeOrganization" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">dtu.dk</saml:AttributeValue></saml:Attribute><saml:Attribute Name="schacHomeOrganizationType" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:homeOrganizationType:eu:higherEducationalInstitution</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonTargetedID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">WAYF-DK-e13a9b00ecfc2d34f2d3d1f349ddc739a73353a3</saml:AttributeValue></saml:Attribute><saml:Attribute Name="schacYearOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">1959</saml:AttributeValue></saml:Attribute><saml:Attribute Name="schacDateOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">19590824</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`

	privatekey = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----`


    htmlwithresponse = `
<!DOCTYPE html>
<html>
<head>
    <title>
        attributeRelease
    </title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
    <link type="text/css" rel="stylesheet" href="/resources/wayf_new.css" media="all" />
    <style>
        body {
            font: 13px/18px Helvetica, Arial, sans-serif;
        }

        input {
            margin: 5px 5px 5px 0;
            padding: 5px;
            font: 15px/18px Helvetica, Arial, sans-serif;
        }

        div,
        p {
            margin: 1em 0;
        }

        div.r {
            text-align: right;
        }

        .prevattrs li::before {
            content: 'X';
            color: orange;
            margin-right: .5em;
        }

        @media only screen and (max-width: 800px) {
            span.input {
                display: block;
            }
        }
    </style>
    <meta name="robots" content="noindex, nofollow" />
    <script type="text/javascript" src="/resources/mustache.min.js"></script>
    <script type="text/javascript" src="/resources/tippy.min.js"></script>
    <link type="text/css" rel="stylesheet" href="/resources/tippy.css" media="all" />

</head>

<body>
    <div id="header">
        <a id="wayflogo" href="http://www.wayf.dk" title="WAYF homepage" target="_blank">
			WAYF
		</a>
        <div id="langs"></div>
        <a id="deiclogo" href="http://www.deic.dk" title="DeiC homepage" target="_blank">
			DeiC
		</a>
    </div>
    <div id="subheader">
    </div>
    <div id="sectionouter">
        <div id="section">
            <div id=error>
            </div>
            <div id=content>
            </div>
        </div>
    </div>
    <div style="clear:both;">
    </div>
    <div id="footer">
    </div>
    <!-- div id footer -->
    <br />

<form method="post" id="samlform" action="https://wayfsp.wayf.dk/ss/module.php/saml/sp/saml2-acs.php/default-sp">
<input type="hidden" name="SAMLResponse" value="PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIElEPSJfY2FjNWY1YmU0ODVlOGRlN2FhZjVkZTdhZjE4ZmU1ZDM4YmI3MDRkOTA5IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNy0wNi0wN1QxMTo1Mjo1OVoiIERlc3RpbmF0aW9uPSJodHRwczovL3dheWZzcC53YXlmLmRrL3NzL21vZHVsZS5waHAvc2FtbC9zcC9zYW1sMi1hY3MucGhwL2RlZmF1bHQtc3AiIEluUmVzcG9uc2VUbz0iXzkxNGY0MmU4NDMyMjg4ODJiZWM1NjZkYTJiNDAzYTE4MjdmY2E3NDIxNCI+PHNhbWw6SXNzdWVyPmh0dHBzOi8vd2F5Zi53YXlmLmRrPC9zYW1sOklzc3Vlcj48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48c2FtbDpBc3NlcnRpb24geG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiBJRD0icGZ4ODNhNjhiMzAtYWUzMC01MWUzLTU0NWYtYzgzN2ExZmI1NDY4IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNy0wNi0wN1QxMTo1Mjo1OVoiPjxzYW1sOklzc3Vlcj5odHRwczovL3dheWYud2F5Zi5kazwvc2FtbDpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+CiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KICAgIDxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz4KICA8ZHM6UmVmZXJlbmNlIFVSST0iI3BmeDgzYTY4YjMwLWFlMzAtNTFlMy01NDVmLWM4MzdhMWZiNTQ2OCI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6RGlnZXN0VmFsdWU+ekg5NkwyU2JUcGNQZXVMS2V5ZWVOU3VHSHc4PTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5ML080aG9wY01wVUFsRnM3NHh5K0h5VnN6VEF4SmhsdHBZcld5WkxhWkVjUnZ6Y2Q2cnFpOVlKNWs0OXpHMU9GaVJ6WGF0bmFpS2lWUzdTUzVWVVVSR25qT2dMWGFKOStsdFRteStYbTQ4VzFRVHpxdEtNRTdyYXo3cGh6THE4V0NXSFNuaHZ5L3JTTnlQcmpjT20vbUtCdXJaNlBKOHRtaGVwVFpoSlZBSzFiVTl3Q3BHOWR3UVo4RE5aclhUR2Y0YTRNcEdxTW5qcVRxTmRiaFRjWXUweG14N1grMU9OYThCaHNhdk8vQ2MxRnNYQ1VwUVBoM2hNcHh5aHpZVERTZlB0WVR1TjYzOUFOcFd6cDBKRk5iVm03VzExdFVKRkxZaGxHSWdmWUZiK3VvY2tTMXQzUFVKYzNGR3BhV3ZtRTVERmxVY2NZWjVtdDVzbVY3R28vUUE9PTwvZHM6U2lnbmF0dXJlVmFsdWU+CjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUROakNDQWg0Q0NRRHNFMGVMeUMrRmpEQU5CZ2txaGtpRzl3MEJBUVVGQURDQmlERUxNQWtHQTFVRUJoTUNSRXN4RURBT0JnTlZCQWdUQjBSbGJtMWhjbXN4RXpBUkJnTlZCQWNVQ2t2RHVHSmxibWhoZG00eEZ6QVZCZ05WQkFvVERuUmxjM1FnVjBGWlJpQjBaWE4wTVJzd0dRWURWUVFERXhKMFpYTjBJRmRCV1VZZ2RHVnpkQzVzWVc0eEhEQWFCZ2txaGtpRzl3MEJDUUVXRFdacGJtNWtRSGRoZVdZdVpHc3dIaGNOTVRVd05qRXdNRGMxTmpFd1doY05NakF3TlRFME1EYzFOakV3V2pBeE1Rc3dDUVlEVlFRR0V3SkVTekVOTUFzR0ExVUVDaE1FVjBGWlJqRVRNQkVHQTFVRUF4UUtLaTUwWlhOMExteGhiakNDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFKOXI0SjYzRVlYS1NRQzFsUFNWRit5a1hxOGlKRzN1ZDNVeVN4UitXb3F4RmpUREhPcW8yenk2NC95Z2szVDBLNU5SajdLeXVKOGRaNTdrdGpzV2tMT09NRjU5MVcyVWRvOEtqWFdNdTh3K1ZvdlZxODExdHpZTUZ4U09tcG9TamR0anBJalhYWlR1YUlnVmY4b2J3LzdXa0ZHU2hFamxJYTRoVTA0T3UyZmZwVVEzT0xNYkVJL0pTUFh5VmFTeld0NDBXTGoxWXZJSVVVbHhHYUNNR1VYYTN4ZDFTQW1MWXQ3OFFtNGVKdWw3SjFCSHlYY2haUWg5bVY5RExoQUlXbTRkSVJHSGpZR1BoRUNlcy9UdkZyRE5IYmNjZW5JdEQ4c3liZGZ2c2RJa0RHVE1QTGZDb01EZFZlSTRtdCsyeDhQNWxqbVN1NldoSnhmWUtUNXlJZDBDQXdFQUFUQU5CZ2txaGtpRzl3MEJBUVVGQUFPQ0FRRUFlVldFbEtMaWFJa1gyU1lweG9lUG4yQXR4Yi9tS0lWMXR0bTRoWkxKV0FoTXdVazl4WVJRQ2ltOVgxYU84T01wTUkzNDZvbXJFRC93VGJQakFDNHdHME0wSy9uKzdHVkMreEZieXVwK044RDVQMWZJbGJCK2hzL2hRaWgxVzNON1dBdGNSQ0hja0JoWU9uVXROWVpUZ0tiaWxYRkxZSVJSQ21GTkdOMnZSVTlLZllvUTE5QVlIdUs1K3ZHVnplWXFSRlk2RUp4MHR0WFpWVkg4WWM3RllqdWU2cmhlTmFFNFpHT01TalZNb2VxcHM3cTZqcXJidzFlTWRoZEZabkQ3SHpyUm5kcHF6anZUME9nU0FXcXJqem5FUlJiNWh1LzI0MTBkME4xbkdxTE9IZmdTbTVvdG5sdGcrLzNXdnVhcXhUZk1ua2dML3FKUGFWZDhaRGVXQmc9PTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1sOlN1YmplY3Q+PHNhbWw6TmFtZUlEIFNQTmFtZVF1YWxpZmllcj0iaHR0cHM6Ly93YXlmc3Aud2F5Zi5kayIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDp0cmFuc2llbnQiPl9lYzZlZWVjYTJiNjcwNDRhNTQwNjVhOWVjZjZhNjQzMzM4YmY1OWUyNjI8L3NhbWw6TmFtZUlEPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMTctMDYtMDdUMTE6NTc6NTlaIiBSZWNpcGllbnQ9Imh0dHBzOi8vd2F5ZnNwLndheWYuZGsvc3MvbW9kdWxlLnBocC9zYW1sL3NwL3NhbWwyLWFjcy5waHAvZGVmYXVsdC1zcCIgSW5SZXNwb25zZVRvPSJfOTE0ZjQyZTg0MzIyODg4MmJlYzU2NmRhMmI0MDNhMTgyN2ZjYTc0MjE0Ii8+PC9zYW1sOlN1YmplY3RDb25maXJtYXRpb24+PC9zYW1sOlN1YmplY3Q+PHNhbWw6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMTctMDYtMDdUMTE6NTI6MjlaIiBOb3RPbk9yQWZ0ZXI9IjIwMTctMDYtMDdUMTE6NTc6NTlaIj48c2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPjxzYW1sOkF1ZGllbmNlPmh0dHBzOi8vd2F5ZnNwLndheWYuZGs8L3NhbWw6QXVkaWVuY2U+PC9zYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24+PC9zYW1sOkNvbmRpdGlvbnM+PHNhbWw6QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDE3LTA2LTA3VDExOjUyOjI0WiIgU2Vzc2lvbk5vdE9uT3JBZnRlcj0iMjAxNy0wNi0wN1QxOTo1Mjo1OVoiIFNlc3Npb25JbmRleD0iXzA4ZjA2NzAyMGU1MzFiYTIzZDVmZWE4NjkzZmQ3ZTNiMWNiOWI4YWVhNCI+PHNhbWw6QXV0aG5Db250ZXh0PjxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjxzYW1sOkF1dGhlbnRpY2F0aW5nQXV0aG9yaXR5Pmh0dHBzOi8vb3JwaGFuYWdlLndheWYuZGs8L3NhbWw6QXV0aGVudGljYXRpbmdBdXRob3JpdHk+PC9zYW1sOkF1dGhuQ29udGV4dD48L3NhbWw6QXV0aG5TdGF0ZW1lbnQ+PHNhbWw6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJjbiIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+TWFkcyBGcmVlayBQZXRlcnNlbjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJlZHVQZXJzb25FbnRpdGxlbWVudCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+aHR0cHM6Ly93YXlmLmRrL2ZlZWRiYWNrL3ZpZXc8L3NhbWw6QXR0cmlidXRlVmFsdWU+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+aHR0cHM6Ly93YXlmLmRrL2thbmphL2FkbWluPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmh0dHBzOi8vd2F5Zi5kay9vcnBoYW5hZ2UvYWRtaW48L3NhbWw6QXR0cmlidXRlVmFsdWU+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+aHR0cHM6Ly93YXlmLmRrL3ZvL2FkbWluPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Im9yZ2FuaXphdGlvbk5hbWUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPldBWUYgV2hlcmUgQXJlIFlvdSBGcm9tPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9InByZWZlcnJlZExhbmd1YWdlIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5kYTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJtYWlsIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5mcmVla0B3YXlmLmRrPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9ImVkdVBlcnNvblByaW5jaXBhbE5hbWUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmdpa2Nhc3dpZEBvcnBoYW5hZ2Uud2F5Zi5kazwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJnbiIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+TWFkcyBGcmVlazwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJzbiIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+UGV0ZXJzZW48L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iZWR1UGVyc29uUHJpbWFyeUFmZmlsaWF0aW9uIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5tZW1iZXI8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iZWR1UGVyc29uQXNzdXJhbmNlIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj4xPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9InNjaGFjSG9tZU9yZ2FuaXphdGlvbiIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+b3JwaGFuYWdlLndheWYuZGs8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0ic2NoYWNIb21lT3JnYW5pemF0aW9uVHlwZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+dXJuOm1hY2U6dGVyZW5hLm9yZzpzY2hhYzpob21lT3JnYW5pemF0aW9uVHlwZTppbnQ6TlJFTkFmZmlsaWF0ZTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJlZHVQZXJzb25UYXJnZXRlZElEIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5XQVlGLURLLWM1YmM3ZTE2YmI2ZDI4Y2I1YTIwYjZhYWQ4NGQxY2JhMmRmNWM0OGY8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48L3NhbWw6QXR0cmlidXRlU3RhdGVtZW50Pjwvc2FtbDpBc3NlcnRpb24+PC9zYW1scDpSZXNwb25zZT4=" />
<input type="hidden" name="RelayState" value="https://wayfsp.wayf.dk/ss/module.php/core/postredirect.php?RedirId=_68b38b094f5e258d5e2a224d7c39b3b06ef0020e53">
</form>
</body>
</html>
`
)

func ExampleSignAndValidate() {
	xp := NewXp(response)
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	xp.Sign(assertion.(types.Element), privatekey, "-", "", "sha256")

	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm"))
	fmt.Println(xp.Query1(nil, "/samlp:Response/saml:Assertion/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm"))

	block, _ := pem.Decode([]byte(privatekey))
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := &priv.PublicKey

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion.(types.Element), pub))

	xp.Sign(assertion.(types.Element), privatekey, "-", "", "sha1")

	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm"))
	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm"))
	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue"))
	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignatureValue"))
	// Output:
	// http://www.w3.org/2001/04/xmlenc#sha256
	// http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
	// verify: <nil>
	// http://www.w3.org/2000/09/xmldsig#sha1
	// http://www.w3.org/2000/09/xmldsig#rsa-sha1
	// 3NN6sB8hU2sKZhm8kUKzHQhfBps=
	// IlyDYG8Q7IwkQD6jWDq1WDPIrBcRgTFpGx6VCh8i0aFVL2XHQUu6sD23UmZqmoiqUXPQLFIotFEwJMZ8VlYOSBfePrFBu4ug8JiYYPII0d2njl0aN1iSe+Jf6Rp5Z7T0IIilD7DijECjt+joNkohWYYXuf2CFJM8HfNSMrya++Y=
}

func ExampleXSW1() {
	xp := NewXp(response)
	response := xp.Query(nil, "/samlp:Response[1]")[0]
	xp.Sign(response.(types.Element), privatekey, "-", "", "sha256")

    clonedResponse, _ := response.Copy()
    clonedSignature := xp.Query(clonedResponse, "ds:Signature[1]")[0]
    clonedResponse.RemoveChild(clonedSignature)
    signature := xp.Query(response, "ds:Signature[1]")[0]
    signature.(types.Element).AddChild(clonedResponse)
    response.(types.Element).SetAttribute("ID", "_evil_response_ID")

	response = xp.Query(nil, "/samlp:Response[1]")[0]

	block, _ := pem.Decode([]byte(privatekey))
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := &priv.PublicKey

	fmt.Printf("verify: %v\n", xp.VerifySignature(response.(types.Element), pub))

	// Output:
	// verify: ID mismatch
}

func ExampleXSW2() {
	xp := NewXp(response)
	response := xp.Query(nil, "/samlp:Response[1]")[0]
	xp.Sign(response.(types.Element), privatekey, "-", "", "sha256")

    clonedResponse, _ := response.Copy()
    clonedSignature := xp.Query(clonedResponse, "ds:Signature[1]")[0]
    clonedResponse.RemoveChild(clonedSignature)
    signature := xp.Query(response, "ds:Signature[1]")[0]
    signature.AddPrevSibling(clonedResponse)
    response.(types.Element).SetAttribute("ID", "_evil_response_ID")

	response = xp.Query(nil, "/samlp:Response[1]")[0]

	block, _ := pem.Decode([]byte(privatekey))
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := &priv.PublicKey

	fmt.Printf("verify: %v\n", xp.VerifySignature(response.(types.Element), pub))

	// Output:
	// verify: ID mismatch
}

func ExampleXSW3() {
	xp := NewXp(response)
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	xp.Sign(assertion.(types.Element), privatekey, "-", "", "sha256")

    evilAssertion, _ := assertion.Copy()
    copiedSignature := xp.Query(evilAssertion, "ds:Signature[1]")[0]
    evilAssertion.(types.Element).SetAttribute("ID", "_evil_response_ID")
    evilAssertion.RemoveChild(copiedSignature)
    assertion.AddPrevSibling(evilAssertion)

	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	block, _ := pem.Decode([]byte(privatekey))
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := &priv.PublicKey

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion.(types.Element), pub))

	// Output:
	// verify: no signature found
}

func ExampleXSW4() {
	xp := NewXp(response)
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	xp.Sign(assertion.(types.Element), privatekey, "-", "", "sha256")

    evilAssertion, _ := assertion.Copy()
    copiedSignature := xp.Query(evilAssertion, "ds:Signature[1]")[0]
    evilAssertion.(types.Element).SetAttribute("ID", "_evil_response_ID")
    evilAssertion.RemoveChild(copiedSignature)

    root, _ := xp.Doc.DocumentElement()
    root.AddChild(evilAssertion)
    root.RemoveChild(assertion)
    evilAssertion.AddChild(assertion)

	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	block, _ := pem.Decode([]byte(privatekey))
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := &priv.PublicKey

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion.(types.Element), pub))

	// Output:
	// verify: no signature found
}

func ExampleXSW5() {
	xp := NewXp(response)
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	xp.Sign(assertion.(types.Element), privatekey, "-", "", "sha256")

    evilAssertion := xp.Query(nil, "saml:Assertion[1]")[0]
    assertionCopy, _ := evilAssertion.Copy()
    copiedSignature := xp.Query(evilAssertion, "ds:Signature[1]")[0]
    assertionCopy.RemoveChild(copiedSignature)

    root, _ := xp.Doc.DocumentElement()
    root.AddChild(assertionCopy)

    evilAssertion.(types.Element).SetAttribute("ID", "_evil_response_ID")
	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	block, _ := pem.Decode([]byte(privatekey))
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := &priv.PublicKey

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion.(types.Element), pub))

	// Output:
	// verify: ID mismatch
}

func ExampleXSW6() {
	xp := NewXp(response)
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	xp.Sign(assertion.(types.Element), privatekey, "-", "", "sha256")

    evilAssertion := xp.Query(nil, "saml:Assertion[1]")[0]
    originalSignature := xp.Query(evilAssertion, "ds:Signature[1]")[0]
    assertionCopy, _ := evilAssertion.Copy()
    copiedSignature := xp.Query(evilAssertion, "ds:Signature[1]")[0]
    assertionCopy.RemoveChild(copiedSignature)
    originalSignature.AddChild(assertionCopy)
    evilAssertion.(types.Element).SetAttribute("ID", "_evil_response_ID")

	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	block, _ := pem.Decode([]byte(privatekey))
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := &priv.PublicKey

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion.(types.Element), pub))

	// Output:
	// verify: ID mismatch
}

func ExampleXSW7() {
	xp := NewXp(response)
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	xp.Sign(assertion.(types.Element), privatekey, "-", "", "sha256")

    extensions, _ := xp.Doc.CreateElement("Extensions")
    assertion.AddPrevSibling(extensions)
    evilAssertion, _ := assertion.Copy()
    copiedSignature := xp.Query(evilAssertion, "ds:Signature[1]")[0]
    evilAssertion.RemoveChild(copiedSignature)
    extensions.AddChild(evilAssertion)

	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	block, _ := pem.Decode([]byte(privatekey))
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := &priv.PublicKey

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion.(types.Element), pub))

	// Output:
	// verify: <nil>
}

func ExampleXSW8() {
	xp := NewXp(response)
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	xp.Sign(assertion.(types.Element), privatekey, "-", "", "sha256")

    evilAssertion := xp.Query(nil, "saml:Assertion[1]")[0]
    originalSignature := xp.Query(evilAssertion, "ds:Signature[1]")[0]
    assertionCopy, _ := evilAssertion.Copy()
    copiedSignature := xp.Query(assertionCopy, "ds:Signature[1]")[0]
    assertionCopy.RemoveChild(copiedSignature)
    object, _ := xp.Doc.CreateElement("Object")
    originalSignature.AddChild(object)
    object.AddChild(assertionCopy)

	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	block, _ := pem.Decode([]byte(privatekey))
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := &priv.PublicKey

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion.(types.Element), pub))

	// Output:
	// verify: <nil>
}

func ExampleQueryDashP_1() {
	xp := NewXp(response)
	xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[1]`, "anton", nil)
	xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[2]`, "joe", nil)
	xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`, "banton", nil)
	xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[4]`, "xxx", nil)

	fmt.Println(xp.Query1(nil, "saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[4]"))
	fmt.Println(xp.Query1(nil, "saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]"))
	fmt.Println(xp.Query1(nil, "saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[2]"))
	fmt.Println(xp.Query1(nil, "saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[1]"))
	// Output:
	// xxx
	// banton
	// joe
	// anton
}

func ExampleQueryDashP_2() {
	xp := NewXp(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`)
	xp.QueryDashP(nil, `/samlp:Response/@ID`, "zf0de122f115e3bb7e0c2eebcc4537ac44189c6dc", nil)
	xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`, "banton", nil)

	fmt.Print(xp.Doc.Dump(true))
	fmt.Println(xp.Query1(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`))
	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
	//   <samlp:Response ID="zf0de122f115e3bb7e0c2eebcc4537ac44189c6dc"/>
	//   <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
	//     <saml:AuthnStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
	//       <saml:AuthnContext xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
	//         <saml:AuthenticatingAuthority xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
	//         <saml:AuthenticatingAuthority xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
	//         <saml:AuthenticatingAuthority xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">banton</saml:AuthenticatingAuthority>
	//       </saml:AuthnContext>
	//     </saml:AuthnStatement>
	//   </saml:Assertion>
	// </samlp:Response>
	// banton
}

func ExampleQueryDashP_3() {
	xp := NewXp(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`)
	xp.QueryDashP(nil, `./@ID`, "zf0de122f115e3bb7e0c2eebcc4537ac44189c6dc", nil)
	xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`, "banton", nil)

	fmt.Print(xp.Doc.Dump(true))
	fmt.Println(xp.Query1(nil, `//saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`))
	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="zf0de122f115e3bb7e0c2eebcc4537ac44189c6dc">
	//   <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
	//     <saml:AuthnStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
	//       <saml:AuthnContext xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
	//         <saml:AuthenticatingAuthority xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
	//         <saml:AuthenticatingAuthority xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
	//         <saml:AuthenticatingAuthority xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">banton</saml:AuthenticatingAuthority>
	//       </saml:AuthnContext>
	//     </saml:AuthnStatement>
	//   </saml:Assertion>
	// </samlp:Response>
	// banton
}

func ExampleEncryptAndDecrypt() {

	xp := NewXp(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`)
	xp.QueryDashP(nil, `./@ID`, "zf0de122f115e3bb7e0c2eebcc4537ac44189c6dc", nil)
	xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`, "banton", nil)

	fmt.Print(xp.Doc.Dump(true))

	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	pk := Pem2PrivateKey(privatekey, "")
    ea := NewXp(`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:EncryptedAssertion>`)
	xp.Encrypt(assertion.(types.Element), &pk.PublicKey, ea)
	assertion = xp.Query(nil, "//saml:EncryptedAssertion")[0]

	xp.Decrypt(assertion.(types.Element), pk)
	fmt.Print(xp.Doc.Dump(true))
	// Output:
    // <?xml version="1.0" encoding="UTF-8"?>
    // <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="zf0de122f115e3bb7e0c2eebcc4537ac44189c6dc">
    //   <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    //     <saml:AuthnStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    //       <saml:AuthnContext xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    //         <saml:AuthenticatingAuthority xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
    //         <saml:AuthenticatingAuthority xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
    //         <saml:AuthenticatingAuthority xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">banton</saml:AuthenticatingAuthority>
    //       </saml:AuthnContext>
    //     </saml:AuthnStatement>
    //   </saml:Assertion>
    // </samlp:Response>
    // <?xml version="1.0" encoding="UTF-8"?>
    // <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="zf0de122f115e3bb7e0c2eebcc4537ac44189c6dc">
    //   <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    //   <saml:AuthnStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    //     <saml:AuthnContext xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    //       <saml:AuthenticatingAuthority xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
    //       <saml:AuthenticatingAuthority xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
    //       <saml:AuthenticatingAuthority xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">banton</saml:AuthenticatingAuthority>
    //     </saml:AuthnContext>
    //   </saml:AuthnStatement>
    // </saml:Assertion>
    // </samlp:Response>
}

func ExampleValidateSchema() {
	xp := NewXp(response)
	fmt.Println(xp.SchemaValidate("schemas/saml-schema-protocol-2.0.xsd"))
	// make the document schema-invalid
	issuer := xp.Query(nil, "//saml:Assertion/saml:Issuer")[0]
	parent, _ := issuer.ParentNode()
	parent.RemoveChild(issuer)
	fmt.Println(xp.SchemaValidate("schemas/saml-schema-protocol-2.0.xsd"))
	// Output:
	// [] <nil>
	// [Element '{urn:oasis:names:tc:SAML:2.0:assertion}Subject': This element is not expected. Expected is ( {urn:oasis:names:tc:SAML:2.0:assertion}Issuer ).] schema validation failed

}
