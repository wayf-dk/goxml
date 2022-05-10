package goxml

import (
    "crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/wayf-dk/go-libxml2/types"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"testing"
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
	_ = log.Printf // For debugging; delete when done.
)

func printHashedDom(xp *Xp) {
	fmt.Println(xp.DomSha1SumToBase64())
}

func gotExpected(was interface{}, expected interface{}, f string, t *testing.T) {
	if was != expected {
		t.Errorf(f+"; got %+v expected %+v", was, expected)
	}
}

// ExampleC14NWithComment does the canonilisation with comment in response.
func ExampleC14NWithComment() {
	xp := NewXpFromFile("testdata/response.xml")
	printHashedDom(xp)
	xp = NewXpFromFile("testdata/response-with-comment.xml")
	printHashedDom(xp)
	// Output:
	// 8fqgdCA2D9Ywkf/OOzIwQRmbXTM=
	// 8fqgdCA2D9Ywkf/OOzIwQRmbXTM=
}

func ExampleCpxp() {
	xp := NewXpFromFile("testdata/response.xml")
	printHashedDom(xp)
	// Output:
	// 8fqgdCA2D9Ywkf/OOzIwQRmbXTM=
}

/*func TestC14n(*testing.T) {
	xp := NewXpFromFile("testdata/response.xml")
	c14n := ""
	i := 0
	for _ = range [1]int{} {
		for _ = range [1]int{} {
			c14n = xp.C14n(nil, "")
			i++
		}
		fmt.Println(i)
		runtime.GC()
	}
	fmt.Println(c14n)
}*/

func ExampleAddXPathContext() {
	xp := NewXpFromFile("testdata/response.xml")
	xp.addXPathContext()
	// Output:
	//
}

/*func ExampleInvalidDoc(){
	xp := NewXpFromFile("testdata/invaliddoc.xml")
	fmt.Println(xp)
	// Output:
	//Invalid Document
}*/

func ExampleQueryAllNodes() {
	xp := NewXpFromFile("testdata/response.xml")
	xpRes := xp.Query(nil, `./saml:Assertion/saml:AttributeStatement/saml:Attribute`)
	fmt.Println(xpRes)
	// Output:
	// <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">madpe@dtu.dk</saml:AttributeValue></saml:Attribute><saml:Attribute Name="gn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">Mads Freek</saml:AttributeValue></saml:Attribute><saml:Attribute Name="sn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">Petersen</saml:AttributeValue></saml:Attribute><saml:Attribute Name="cn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">Mads Freek Petersen</saml:AttributeValue></saml:Attribute><saml:Attribute Name="preferredLanguage" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">da-DK</saml:AttributeValue></saml:Attribute><saml:Attribute Name="organizationName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">Danmarks Tekniske Universitet</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonPrincipalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">madpe@dtu.dk</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonPrimaryAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">staff</saml:AttributeValue></saml:Attribute><saml:Attribute Name="schacPersonalUniqueID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408590763</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonAssurance" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">2</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonEntitlement" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:tcs:escience-user</saml:AttributeValue></saml:Attribute><saml:Attribute Name="schacHomeOrganization" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">dtu.dk</saml:AttributeValue></saml:Attribute><saml:Attribute Name="schacHomeOrganizationType" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:homeOrganizationType:eu:higherEducationalInstitution</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonTargetedID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">WAYF-DK-e13a9b00ecfc2d34f2d3d1f349ddc739a73353a3</saml:AttributeValue></saml:Attribute><saml:Attribute Name="schacYearOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">1959</saml:AttributeValue></saml:Attribute><saml:Attribute Name="schacDateOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">19590824</saml:AttributeValue></saml:Attribute>
}

func ExampleQueryAllNodeValues() {
	xp := NewXpFromFile("testdata/response.xml")
	xpRes := xp.Query(nil, `./saml:Assertion/saml:AttributeStatement/saml:Attribute/saml:AttributeValue`)
	fmt.Println(xpRes)
	// Output:
	// <saml:AttributeValue xsi:type="xs:string">madpe@dtu.dk</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">Mads Freek</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">Petersen</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">Mads Freek Petersen</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">da-DK</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">Danmarks Tekniske Universitet</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">madpe@dtu.dk</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">staff</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408590763</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">2</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:tcs:escience-user</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">dtu.dk</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:homeOrganizationType:eu:higherEducationalInstitution</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">WAYF-DK-e13a9b00ecfc2d34f2d3d1f349ddc739a73353a3</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">1959</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">19590824</saml:AttributeValue>
}

func ExampleQueryNumber() {
	xp := NewXpFromFile("testdata/response.xml")
	count := xp.QueryNumber(nil, `count(./saml:Assertion/saml:AttributeStatement/saml:Attribute/saml:AttributeValue)`)
	fmt.Println("count", count)
	// Output:
	// count 16
}

func ExampleQueryBool() {
	xp := NewXpFromFile("testdata/response.xml")
	boolean := xp.QueryBool(nil, `count(./saml:Assertion/saml:AttributeStatement/saml:Attribute/saml:AttributeValue) > 10`)
	fmt.Println("count", boolean)
	// Output:
	// count true
}

func ExampleNewXpFromNode() {
	/*for i := 0; i <= 2000; i++ {
	   	for j := 0; j <= 1; j++ {
	  	        xp_res = NewXpFromNode(node)
	  	    }
	  	}*/
	xp := NewXpFromFile("testdata/response.xml")
	node := xp.Query(nil, `./saml:Assertion`)[0]
	xpRes := NewXpFromNode(node)
	printHashedDom(xpRes)
	// Output:
	// 3NN6sB8hU2sKZhm8kUKzHQhfBps=
}

func ExampleQueryMulti() {
	xp := NewXpFromFile("testdata/response.xml")
	xpRes := xp.QueryMulti(nil, `./saml:Assertion/saml:AttributeStatement/saml:Attribute/saml:AttributeValue`)
	fmt.Println(xpRes)
	// Output:
	// [madpe@dtu.dk Mads Freek Petersen Mads Freek Petersen da-DK Danmarks Tekniske Universitet madpe@dtu.dk staff urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408590763 2 urn:mace:terena.org:tcs:escience-user dtu.dk urn:mace:terena.org:schac:homeOrganizationType:eu:higherEducationalInstitution WAYF-DK-e13a9b00ecfc2d34f2d3d1f349ddc739a73353a3 1959 19590824]
}

func ExampleQueryMultiMulti() {
	xp := NewXpFromFile("testdata/testmetadata.xml")
	xpRes := xp.QueryMultiMulti(nil, `md:SPSSODescriptor/md:KeyDescriptor[@use="encryption"]`, []string{`.//ds:X509Certificate`, `.//md:EncryptionMethod/@Algorithm`})
	fmt.Printf("%v\n", xpRes[0])
	fmt.Printf("%v\n", xpRes[1])
	// Output:
    // [[abc] [def]]
    // [[http://www.w3.org/2009/xmlenc11#aes128-gcm http://www.w3.org/2009/xmlenc11#aes192-gcm] [http://www.w3.org/2009/xmlenc11#aes256-gcm http://www.w3.org/2001/04/xmlenc#aes128-cbc]]
}

func ExampleEmptyDoc() {
	xp := NewXpFromFile("testdata/emptydoc.xml")
	fmt.Println(xp.Doc.Dump(false))
	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
}

func ExampleExternalEntity() {
	xp := NewXpFromFile("testdata/externalentity.xml")
	fmt.Println(xp.Doc.Dump(false))
	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <!DOCTYPE foo [
	// <!ELEMENT foo ANY>
	// <!ENTITY bar SYSTEM "file:///etc/lsb-release">
	// ]>
	// <foo>
	//   &bar;
	// </foo>
}

func ExampleValidDoc() {
	xp := NewXpFromFile("testdata/validdoc.xml")
	printHashedDom(xp)
	// Output:
	// GKAdV32WvPN3sv6a+mSV4bSnZ14=
}

func ExampleSignAndValidate() {
	xp := NewXpFromFile("testdata/response.xml")
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	before := xp.Query(assertion, "*[2]")[0]
	privatekey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	block, _ := pem.Decode(privatekey)
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := []crypto.PublicKey{&priv.PublicKey}

	for _, hashfunc := range []string{"rsa256", "rsa384", "rsa512"} {
		xp.Sign(assertion.(types.Element), before.(types.Element), privatekey, []byte("-"), "", hashfunc)
		assertion = xp.Query(nil, "saml:Assertion[1]")[0]

		fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm"))
		fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm"))
		fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue"))
		fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignatureValue"))

		fmt.Printf("verify: %v\n", xp.VerifySignature(assertion.(types.Element), pub))
		// VerifySignature re-inserts the signature so we must remove it now
		assertion.RemoveChild(xp.Query(assertion, "ds:Signature[1]")[0])
	}

	// Output:
	// http://www.w3.org/2001/04/xmlenc#sha256
	// http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
	// 4+l1oINdPA8pA7YJpaykq9KsJObgJgkkufhIUOPqOE0=
	// eTlL9mzLOkH9wMuwdxIxgAi7QfIYvvqHWd8Icb19I7/ZfuCYNXsfJY4MbSiefL5jSOKQB5tDN8FlV/263N4z0nHZ1vsns/HBKPCP8uJBcSzliJC+8XSUXdGaWz7jGPl1fLoqA1NhxbWXZFC/WoaVnYnPXlY1BR+OPa8Q9k2gu89xosx3gbkYv93CpKIRfyputxtqxXa1gNX59Gcp4hjbpeSF6FPSQ55BS0pIuxZ4+N1xsrJx93+NOdpxZ+Vimx7y3iwtO/vNVsvIEJNgv9w1Tfz6G/l3JYSsqQYZyzOA3m8mzA+KfoL9nEZuuoNmF12cs7QnG8eYWplbtUyuKao8Zg==
	// verify: <nil>
	// http://www.w3.org/2001/04/xmldsig-more#sha384
	// http://www.w3.org/2001/04/xmldsig-more#rsa-sha384
	// 8eGAd4VP4Y5k0XRracuWXXOU7ZjzCbEYgVZM3AIBOSDBo9uIyVQqJBnDRvJ0Lx9H
	// WjN5SfxI54ZniyfFqFWHfskWbuPA07A2r4P55xI2JcNSX8KALiP5S98qZqJ9veKtIMdeFLEraYKTqlv6n5jxQgIJwnVB1GGZ9cYMTEO33sPcDexqKXJKT/lqNh5k9M9MAl0y4rFlLwn4KDfclPKqOFLVesBYeNnCaQUzUcqfcmm0jhlA1hMaAJFkbLrXyXLl+7NAkkrEPXPAXIXQY2EORbz9b1o8YU+CDwwb2+rdwmBSJiUCYl7u8BE26I+l8JZ6Ebvt2tlCcPXiQhwu8FNTuNKpbcXZumz6KOizK1dedJantN74WhmyLS4ATyvJzntGr7JaKkAPSLeMxlUpXL2GDA==
	// verify: <nil>
	// http://www.w3.org/2001/04/xmlenc#sha512
	// http://www.w3.org/2001/04/xmldsig-more#rsa-sha512
	// S1Jc/6AgPplPSLYKNss2bE5E+wR+gCEKazomuA3qf5DKk5KOU2KZUiucBHhe0zOKT4qdD11+gXd8f02MNSYiWQ==
	// FrNCTtNUkGmKVvdKyh6UdYgI1B+gJouXHuGr/99LfdJ3hwNrBDC4PYCMoROwMOH1HXCKSIYskCITLfOcptk+p87V1AwxjKwWJF1yref5tUcBKXiYVq99B97ewvHdnT8hTJ9bTGkAUyHBUPn+KzOVSKDcIvR3Z5RTCiFgaxrySMo4VbfS86XKx3t8oeVS/6RaeTi7ekIHzTpvPFC7h4YeIHXdTYuQzlBc4SMyJJ+RMz5J4Fdjnr9wCtU5AQUKstXXB5a5iyov0rHuqnaijL8988IPzbso9Kr9sUBFSOjERkVu2r+xVfHwXej0mzJrWgp8GsVQGwNOhVV2xjcSkBAMpQ==
	// verify: <nil>

}

func ExampleParser1() {
    fmt.Println(parse(`/abc/def[@abc="1/2/3"][1]//hij[@abc='1/2/3'][1]/xyz/@abc`))
    fmt.Println(parse(`//abc/def[@abc="1/2/3"][1]//hij[@abc='1/2/3'][1]/xyz/@abc`))
    fmt.Println(parse(`.//abc/def[@abc="1/2/3"][1]//hij[@abc='1/2/3'][1]/xyz/@abc`))
    // Output:
    // [abc def[@abc="1/2/3"][1] .//hij[@abc='1/2/3'][1] xyz @abc]
    // [.//abc def[@abc="1/2/3"][1] .//hij[@abc='1/2/3'][1] xyz @abc]
    // [. .//abc def[@abc="1/2/3"][1] .//hij[@abc='1/2/3'][1] xyz @abc]
}


func ExampleXSW1() {
	xp := NewXpFromFile("testdata/response.xml")
	response := xp.Query(nil, "/samlp:Response[1]")[0]
	before := xp.Query(response, "*[2]")[0]
	privatekey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	xp.Sign(response.(types.Element), before.(types.Element), privatekey, []byte("-"), "", "rsa256")

	clonedResponse := xp.CopyNode(response, 1)
	clonedSignature := xp.Query(clonedResponse, "ds:Signature[1]")[0]
	clonedResponse.RemoveChild(clonedSignature)
	signature := xp.Query(response, "ds:Signature[1]")[0]
	signature.(types.Element).AddChild(clonedResponse)
	response.(types.Element).SetAttribute("ID", "_evil_response_ID")

	response = xp.Query(nil, "/samlp:Response[1]")[0]

	block, _ := pem.Decode(privatekey)
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := []crypto.PublicKey{&priv.PublicKey}

	fmt.Printf("verify: %v\n", xp.VerifySignature(response.(types.Element), pub))

	// Output:
	// verify: ID mismatch
}

func ExampleCopyNode() {
	xp := NewXpFromFile("testdata/response.xml")
	response := xp.Query(nil, "/samlp:Response[1]")[0]
	cpNode := xp.CopyNode(response, 2)
	fmt.Println(cpNode)
	// Output:
	// <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:zzz="urn:oasis:names:tc:SAML:2.0:assertion" ID="_229827eaf5c5b8a7b49b3eb6b87e2bc5c564e49b8a" Version="2.0" IssueInstant="2017-06-27T13:17:46Z" Destination="https://wayfsp.wayf.dk/ss/module.php/saml/sp/saml2-acs.php/default-sp" InResponseTo="_1b83ac6f594b5a8c090e6559b4bf93195e5e766735"/>
}

func ExampleXSW2() {
	xp := NewXpFromFile("testdata/response.xml")
	response := xp.Query(nil, "/samlp:Response[1]")[0]
	before := xp.Query(response, "*[2]")[0]
	privatekey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	xp.Sign(response.(types.Element), before.(types.Element), privatekey, []byte("-"), "", "rsa256")

	clonedResponse := xp.CopyNode(response, 1)
	clonedSignature := xp.Query(clonedResponse, "ds:Signature[1]")[0]
	clonedResponse.RemoveChild(clonedSignature)
	signature := xp.Query(response, "ds:Signature[1]")[0]
	signature.AddPrevSibling(clonedResponse)
	response.(types.Element).SetAttribute("ID", "_evil_response_ID")

	response = xp.Query(nil, "/samlp:Response[1]")[0]

	block, _ := pem.Decode(privatekey)
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := []crypto.PublicKey{&priv.PublicKey}

	fmt.Printf("verify: %v\n", xp.VerifySignature(response.(types.Element), pub))

	// Output:
	// verify: ID mismatch
}

func ExampleXSW3() {
	xp := NewXpFromFile("testdata/response.xml")
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	before := xp.Query(assertion, "*[2]")[0]
	privatekey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	xp.Sign(assertion.(types.Element), before.(types.Element), privatekey, []byte("-"), "", "rsa256")

	evilAssertion := xp.CopyNode(assertion, 1)
	copiedSignature := xp.Query(evilAssertion, "ds:Signature[1]")[0]
	evilAssertion.(types.Element).SetAttribute("ID", "_evil_response_ID")
	evilAssertion.RemoveChild(copiedSignature)
	assertion.AddPrevSibling(evilAssertion)

	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	block, _ := pem.Decode(privatekey)
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := []crypto.PublicKey{&priv.PublicKey}

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion.(types.Element), pub))

	// Output:
	// verify: no signature found
}

func ExampleXSW4() {
	xp := NewXpFromFile("testdata/response.xml")
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	before := xp.Query(assertion, "*[2]")[0]
	privatekey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	xp.Sign(assertion.(types.Element), before.(types.Element), privatekey, []byte("-"), "", "rsa256")

	evilAssertion := xp.CopyNode(assertion, 1)
	copiedSignature := xp.Query(evilAssertion, "ds:Signature[1]")[0]
	evilAssertion.(types.Element).SetAttribute("ID", "_evil_response_ID")
	evilAssertion.RemoveChild(copiedSignature)

	root, _ := xp.Doc.DocumentElement()
	root.AddChild(evilAssertion)
	root.RemoveChild(assertion)
	evilAssertion.AddChild(assertion)

	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	block, _ := pem.Decode(privatekey)
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := []crypto.PublicKey{&priv.PublicKey}

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion.(types.Element), pub))

	// Output:
	// verify: no signature found
}

func ExampleXSW5() {
	xp := NewXpFromFile("testdata/response.xml")
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	before := xp.Query(assertion, "*[2]")[0]
	privatekey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	xp.Sign(assertion.(types.Element), before.(types.Element), privatekey, []byte("-"), "", "rsa256")

	evilAssertion := xp.Query(nil, "saml:Assertion[1]")[0]
	assertionCopy := xp.CopyNode(evilAssertion, 1)
	copiedSignature := xp.Query(evilAssertion, "ds:Signature[1]")[0]
	assertionCopy.RemoveChild(copiedSignature)

	root, _ := xp.Doc.DocumentElement()
	root.AddChild(assertionCopy)

	evilAssertion.(types.Element).SetAttribute("ID", "_evil_response_ID")
	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	block, _ := pem.Decode(privatekey)
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := []crypto.PublicKey{&priv.PublicKey}

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion.(types.Element), pub))

	// Output:
	// verify: ID mismatch
}

func ExampleXSW6() {
	xp := NewXpFromFile("testdata/response.xml")
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	before := xp.Query(assertion, "*[2]")[0]
	privatekey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	xp.Sign(assertion.(types.Element), before.(types.Element), privatekey, []byte("-"), "", "rsa256")

	evilAssertion := xp.Query(nil, "saml:Assertion[1]")[0]
	originalSignature := xp.Query(evilAssertion, "ds:Signature[1]")[0]
	assertionCopy := xp.CopyNode(evilAssertion, 1)
	copiedSignature := xp.Query(evilAssertion, "ds:Signature[1]")[0]
	assertionCopy.RemoveChild(copiedSignature)
	originalSignature.AddChild(assertionCopy)
	evilAssertion.(types.Element).SetAttribute("ID", "_evil_response_ID")

	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	block, _ := pem.Decode(privatekey)
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := []crypto.PublicKey{&priv.PublicKey}

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion.(types.Element), pub))

	// Output:
	// verify: ID mismatch
}

func ExampleXSW7() {
	xp := NewXpFromFile("testdata/response.xml")
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	before := xp.Query(assertion, "*[2]")[0]
	privatekey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	xp.Sign(assertion.(types.Element), before.(types.Element), privatekey, []byte("-"), "", "rsa256")

	extensions, _ := xp.Doc.CreateElement("Extensions")
	assertion.AddPrevSibling(extensions)
	evilAssertion := xp.CopyNode(assertion, 1)
	copiedSignature := xp.Query(evilAssertion, "ds:Signature[1]")[0]
	evilAssertion.RemoveChild(copiedSignature)
	extensions.AddChild(evilAssertion)

	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	block, _ := pem.Decode(privatekey)
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := []crypto.PublicKey{&priv.PublicKey}

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion.(types.Element), pub))

	// Output:
	// verify: <nil>
}

func ExampleXSW8() {
	xp := NewXpFromFile("testdata/response.xml")
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	before := xp.Query(assertion, "*[2]")[0]
	privatekey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	xp.Sign(assertion.(types.Element), before.(types.Element), privatekey, []byte("-"), "", "rsa256")

	evilAssertion := xp.Query(nil, "saml:Assertion[1]")[0]
	originalSignature := xp.Query(evilAssertion, "ds:Signature[1]")[0]
	assertionCopy := xp.CopyNode(evilAssertion, 1)
	copiedSignature := xp.Query(assertionCopy, "ds:Signature[1]")[0]
	assertionCopy.RemoveChild(copiedSignature)
	object, _ := xp.Doc.CreateElement("Object")
	originalSignature.AddChild(object)
	object.AddChild(assertionCopy)

	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	block, _ := pem.Decode(privatekey)
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := []crypto.PublicKey{&priv.PublicKey}

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion.(types.Element), pub))

	// Output:
	// verify: <nil>
}

func ExampleQueryDashP1() {
	for range [1]int{} {

		xp := NewXpFromFile("testdata/response.xml")
		xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[1]`, "anton", nil)
		xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[2]`, "joe", nil)
		xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`, "banton", nil)
		xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[4]`, "xxx", nil)


       fmt.Println(xp.Query1(nil, "saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[4]"))
       xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[4]`, "\x1b", nil)
       fmt.Println(xp.Query1(nil, "saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[4]"))
       fmt.Println(xp.Query1(nil, "saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]"))
       fmt.Println(xp.Query1(nil, "saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[2]"))
       fmt.Println(xp.Query1(nil, "saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[1]"))

	}
	// Output:
	// xxx
	//
	// banton
	// joe
	// anton
}

func ExampleQueryDashP2() {
	xp := NewXpFromString(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`)
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

func ExampleQueryDashP3() {
	xp := NewXpFromString(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`)
	xp.QueryDashP(nil, `./@ID`, "zf0de122f115e3bb7e0c2eebcc4537ac44189c6dc", nil)
	xp.QueryDashP(nil, `./saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`, "banton", nil)

	fmt.Print(xp.PP())
	fmt.Println(xp.Query1(nil, `//saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`))
	xp.Rm(nil, `//saml:AuthenticatingAuthority`)
	fmt.Print(xp.PP())
	xp.Rm(nil, `./saml:Assertion`)
	fmt.Print(xp.PP())

	// Output:
	// <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
	//                 ID="zf0de122f115e3bb7e0c2eebcc4537ac44189c6dc">
	//     <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
	//         <saml:AuthnStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
	//             <saml:AuthnContext xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
	//                 <saml:AuthenticatingAuthority xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
	//                 <saml:AuthenticatingAuthority xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
	//                 <saml:AuthenticatingAuthority xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
	//                     banton
	//                 </saml:AuthenticatingAuthority>
	//             </saml:AuthnContext>
	//         </saml:AuthnStatement>
	//     </saml:Assertion>
	// </samlp:Response>
	// banton
	// <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
	//                 ID="zf0de122f115e3bb7e0c2eebcc4537ac44189c6dc">
	//     <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
	//         <saml:AuthnStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
	//             <saml:AuthnContext xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
	//         </saml:AuthnStatement>
	//     </saml:Assertion>
	// </samlp:Response>
	// <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
	//                 ID="zf0de122f115e3bb7e0c2eebcc4537ac44189c6dc"/>
}


func ExampleQueryDashP4() {
    xp := NewXpFromFile("testdata/testmetadata.xml")
    before := xp.Query(nil, `./md:SPSSODescriptor/md:KeyDescriptor[@use="encryption"]`)
    xp.QueryDashP(nil, `/md:SPSSODescriptor/md:KeyDescriptor[0][@use="encryption"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`, "cert", before[0])
    //fmt.Println(xp.PP())
    xp.QueryDashP(nil, `/md:SPSSODescriptor/md:KeyDescriptor[@use="encryption"][1]/md:EncryptionMethod/@Algorithm`, "cbc", nil)

    fmt.Println(xp.Query1(nil, `./md:SPSSODescriptor/md:KeyDescriptor[@use="encryption"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`))
    fmt.Println(xp.Query1(nil, `./md:SPSSODescriptor/md:KeyDescriptor[@use="encryption"][1]/md:EncryptionMethod/@Algorithm`))
	// Output:
	// cert
	// cbc
}

func TestEncryptAndDecrypt(t *testing.T) {

	// Build document
	xp := NewXpFromString(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`)
	xp.QueryDashP(nil, `./@ID`, "zf0de122f115e3bb7e0c2eebcc4537ac44189c6dc", nil)
	xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`, "banton", nil)
	before := xp.PP()

	// Encrypt
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	privatekey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	pk, _ := Pem2PrivateKey(privatekey, []byte("-"))
	xp.Encrypt(assertion, "saml:EncryptedAssertion", &pk.(*rsa.PrivateKey).PublicKey, []string{})
	encrypted := xp.PP()

	// Decrypt
	encryptedAssertion := xp.Query(nil, "//saml:EncryptedAssertion")[0]
	xp.Decrypt(encryptedAssertion.(types.Element), privatekey, []byte("-"))
	after := xp.PP()

	// Test
	if before == encrypted {
		t.Errorf("before == encrypted")
	}
	if encrypted == after {
		t.Errorf("encrypted == after")
	}
	if before != after {
		t.Errorf("before != after")
	}
}

func TestValidateSchema(t *testing.T) {

	// Build document
	xp := NewXpFromFile("testdata/response.xml")
	err := xp.SchemaValidate()
	gotExpected(err, nil, "Unexpected error", t)

	// Make the document schema-invalid
	issuer := xp.Query(nil, "//saml:Assertion/saml:Issuer")[0]
	parent, _ := issuer.ParentNode()
	parent.RemoveChild(issuer)
	err = xp.SchemaValidate()

	// Test
	gotExpected(err.Error(), "schema validation failed", "Unexpected error", t)
}

func TestDecryptShibResponse(t *testing.T) {

	// Build document
	shibresponse := NewXpFromFile("testdata/testshib.org.encryptedresponse.xml")

	// Decrypt
	privatekey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		t.Error(err)
	}
	encryptedAssertion := shibresponse.Query(nil, "//saml:EncryptedAssertion")[0]
	shibresponse.Decrypt(encryptedAssertion.(types.Element), privatekey, []byte("-"))

	// Test
	gotExpected(shibresponse.DomSha1SumToBase64(), "ZWiDjYoc03iQr5or7lpvv6Nb8vc=", "Bad sum", t)
}

func TestDecryptNemloginResponse(t *testing.T) {

	// Build document
	nemloginresponse := NewXpFromFile("testdata/nemlogin.encryptedresponse.xml")

	// Decrypt
	privatekey, err := ioutil.ReadFile("testdata/nemlogin.key.pem")
	if err != nil {
		t.Error(err)
	}
	encryptedAssertion := nemloginresponse.Query(nil, "//saml:EncryptedAssertion")[0]
	nemloginresponse.Decrypt(encryptedAssertion.(types.Element), privatekey, []byte("-"))

	// Test
	gotExpected(nemloginresponse.DomSha1SumToBase64(), "GuWLBRb1kEiwx/86+R0RmQnI8Mw=", "Bad sum", t)
}

func TestDecryptW3C(t *testing.T) {

	// OAEP does not support different key Encryption methods "digestMethod != keyEncryptionMethod not supported"

	test := map[string]bool{
		"cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p.xml":                    true,
		"cipherText__RSA-3072__aes192-gcm__rsa-oaep-mgf1p__Sha256.xml":            false,
		"cipherText__RSA-3072__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1.xml":         false,
		"cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource.xml": false,
	}

	for test, supported := range test {

		// Load private key
		parts := strings.Split(test, "__")
		pemFile := "testdata/w3c/" + parts[1] + ".pem"
		pemBlock, _ := ioutil.ReadFile(pemFile)

		// Build document
		cipherText, _ := ioutil.ReadFile("testdata/w3c/" + test)
		// We need 2 layers of test nodes around the EncryptedData node
		// Otherwise the parent of the EncryptedData becomes DocumentNode and
		// ParentNode throws an "unknown node" error.
		xp2 := NewXpFromString("<test><test>" + string(cipherText) + "</test></test>")

		err := xp2.Decrypt(xp2.Query(nil, "/test/test")[0], pemBlock, []byte("-"))
		if supported {
			if err != nil {
				t.Error(test, err)
			}
			// Free decrypted data of parent test node and compare with plaintext
			got := NewXpFromNode(xp2.Query(nil, "/test/node()")[0]).DomSha1SumToBase64()
			expected := NewXpFromFile("testdata/w3c/plaintext.xml").DomSha1SumToBase64()
			gotExpected(got, expected, "Bad sum", t)
		} else {
			if err == nil || err.Error() != "digestMethod != keyEncryptionMethod not supported" {
				t.Error(test, err)
			}
		}
	}
}
