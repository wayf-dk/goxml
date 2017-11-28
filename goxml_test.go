package goxml

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/wayf-dk/go-libxml2/types"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
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

func xpFromFile(file string) (res *Xp) {
	xml, err := ioutil.ReadFile(file)
	if err != nil {
		log.Panic(err)
	}
	res = NewXp(string(xml))
	return
}

func printHashedDom(xp *Xp) {
	fmt.Println(base64.StdEncoding.EncodeToString(Hash(crypto.SHA1, xp.C14n(nil, ""))))
}

func ExampleCpXp(){
	xp := xpFromFile("testdata/response.xml")
	printHashedDom(xp)
	// Output:
	// 8fqgdCA2D9Ywkf/OOzIwQRmbXTM=
}

func ExampleAddXPathContext(){
	xp := xpFromFile("testdata/response.xml")
	xp.addXPathContext()
	// Output:
	//
}

/*func ExampleInvalidDoc(){
	xp := xpFromFile("testdata/invaliddoc.xml")
	fmt.Println(xp)
	// Output:
	//Invalid Document
}*/

func ExampleQueryAllNodes() {
	xp := xpFromFile("testdata/response.xml")
	xp_res := xp.Query(nil, `./saml:Assertion/saml:AttributeStatement/saml:Attribute`)
	fmt.Println(xp_res)
	// Output:
	// <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">madpe@dtu.dk</saml:AttributeValue></saml:Attribute><saml:Attribute Name="gn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">Mads Freek</saml:AttributeValue></saml:Attribute><saml:Attribute Name="sn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">Petersen</saml:AttributeValue></saml:Attribute><saml:Attribute Name="cn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">Mads Freek Petersen</saml:AttributeValue></saml:Attribute><saml:Attribute Name="preferredLanguage" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">da-DK</saml:AttributeValue></saml:Attribute><saml:Attribute Name="organizationName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">Danmarks Tekniske Universitet</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonPrincipalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">madpe@dtu.dk</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonPrimaryAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">staff</saml:AttributeValue></saml:Attribute><saml:Attribute Name="schacPersonalUniqueID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408590763</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonAssurance" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">2</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonEntitlement" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:tcs:escience-user</saml:AttributeValue></saml:Attribute><saml:Attribute Name="schacHomeOrganization" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">dtu.dk</saml:AttributeValue></saml:Attribute><saml:Attribute Name="schacHomeOrganizationType" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:homeOrganizationType:eu:higherEducationalInstitution</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonTargetedID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">WAYF-DK-e13a9b00ecfc2d34f2d3d1f349ddc739a73353a3</saml:AttributeValue></saml:Attribute><saml:Attribute Name="schacYearOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">1959</saml:AttributeValue></saml:Attribute><saml:Attribute Name="schacDateOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">19590824</saml:AttributeValue></saml:Attribute>
}

func ExampleQueryAllNodeValues() {
	xp := xpFromFile("testdata/response.xml")
	xp_res := xp.Query(nil, `./saml:Assertion/saml:AttributeStatement/saml:Attribute/saml:AttributeValue`)
	fmt.Println(xp_res)
	// Output:
	// <saml:AttributeValue xsi:type="xs:string">madpe@dtu.dk</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">Mads Freek</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">Petersen</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">Mads Freek Petersen</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">da-DK</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">Danmarks Tekniske Universitet</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">madpe@dtu.dk</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">staff</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408590763</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">2</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:tcs:escience-user</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">dtu.dk</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:homeOrganizationType:eu:higherEducationalInstitution</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">WAYF-DK-e13a9b00ecfc2d34f2d3d1f349ddc739a73353a3</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">1959</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">19590824</saml:AttributeValue>
}

func ExampleQueryNumber() {
	xp := xpFromFile("testdata/response.xml")
	count := xp.QueryNumber(nil, `count(./saml:Assertion/saml:AttributeStatement/saml:Attribute/saml:AttributeValue)`)
	fmt.Println("count", count)
	// Output:
	// count 16
}

func ExampleQueryBool() {
	xp := xpFromFile("testdata/response.xml")
	boolean := xp.QueryBool(nil, `count(./saml:Assertion/saml:AttributeStatement/saml:Attribute/saml:AttributeValue) > 10`)
	fmt.Println("count", boolean)
	// Output:
	// count true
}

func ExampleNewXpFromNode() {
	xp := xpFromFile("testdata/response.xml")
	node := xp.Query(nil, `./saml:Assertion`)[0]
	xp_res := NewXpFromNode(node)
	printHashedDom(xp_res)
	// Output:
	// 3NN6sB8hU2sKZhm8kUKzHQhfBps=
}

func ExampleQueryMulti() {
	xp := xpFromFile("testdata/response.xml")
	xp_res := xp.QueryMulti(nil, `./saml:Assertion/saml:AttributeStatement/saml:Attribute/saml:AttributeValue`)
	fmt.Println(xp_res)
	// Output:
	// [madpe@dtu.dk Mads Freek Petersen Mads Freek Petersen da-DK Danmarks Tekniske Universitet madpe@dtu.dk staff urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408590763 2 urn:mace:terena.org:tcs:escience-user dtu.dk urn:mace:terena.org:schac:homeOrganizationType:eu:higherEducationalInstitution WAYF-DK-e13a9b00ecfc2d34f2d3d1f349ddc739a73353a3 1959 19590824]
}

func ExampleEmptyDoc() {
	xp := xpFromFile("testdata/emptydoc.xml")
	fmt.Println(xp.Doc.Dump(false))
	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
}

func ExampleExternalEntity() {
	xp := xpFromFile("testdata/externalentity.xml")
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
	xp := xpFromFile("testdata/validdoc.xml")
	printHashedDom(xp)
	// Output:
	// GKAdV32WvPN3sv6a+mSV4bSnZ14=
}

func ExampleSignAndValidate() {
	xp := xpFromFile("testdata/response.xml")
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	before := xp.Query(assertion, "*[2]")[0]
	pkey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	privatekey := string(pkey)
	xp.Sign(assertion.(types.Element), before.(types.Element), privatekey, "-", "", "sha256")

	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm"))
	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm"))

	block, _ := pem.Decode([]byte(privatekey))
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := &priv.PublicKey

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion.(types.Element), pub))

	xp.Sign(assertion.(types.Element), before.(types.Element), privatekey, "-", "", "sha1")
	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm"))
	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm"))
	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue"))
	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignatureValue"))

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion.(types.Element), pub))

	// Output:
	// http://www.w3.org/2001/04/xmlenc#sha256
	// http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
	// verify: <nil>
	// http://www.w3.org/2000/09/xmldsig#sha1
	// http://www.w3.org/2000/09/xmldsig#rsa-sha1
	// 3NN6sB8hU2sKZhm8kUKzHQhfBps=
	// gZQYBrzigDvKZTJcSaNfPJOYvqDBgV6zOCV9ghw67jEMVrbcz4XCBp3wjVI2z9rUnkn0Swi11BvW/qOIKhS13BAfGH+j6+1qRHDOlfcZntmqb1fFPVq+geuwQ1CVWWFFQ4zhg96ihzvQG1P2Sqj1TzUWIRtYHueleDJLXLD8yYAxj1TReT6flzPKtJAGr7h03GHgQPyBk6hWvvrP3Jb/sDYRWBOUFoj2uCqpQcU2nA8Li1QWmhDGSjgMmgNtTF2Zr8bukfEMvxjt0YZBAFcf26EGqQS3wbmBGSGpszKL78AdFFJZRBLs9Zk4iClu8GnEvCdB68T0klywvLzu/tsVDQ==
	// verify: <nil>
}

func ExampleXSW1() {
	xp := xpFromFile("testdata/response.xml")
	response := xp.Query(nil, "/samlp:Response[1]")[0]
	before := xp.Query(response, "*[2]")[0]
	pkey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	privatekey := string(pkey)
	xp.Sign(response.(types.Element), before.(types.Element), privatekey, "-", "", "sha256")

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
	xp := xpFromFile("testdata/response.xml")
	response := xp.Query(nil, "/samlp:Response[1]")[0]
	before := xp.Query(response, "*[2]")[0]
	pkey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	privatekey := string(pkey)
	xp.Sign(response.(types.Element), before.(types.Element), privatekey, "-", "", "sha256")

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
	xp := xpFromFile("testdata/response.xml")
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	before := xp.Query(assertion, "*[2]")[0]
	pkey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	privatekey := string(pkey)
	xp.Sign(assertion.(types.Element), before.(types.Element), privatekey, "-", "", "sha256")

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
	xp := xpFromFile("testdata/response.xml")
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	before := xp.Query(assertion, "*[2]")[0]
	pkey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	privatekey := string(pkey)
	xp.Sign(assertion.(types.Element), before.(types.Element), privatekey, "-", "", "sha256")

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
	xp := xpFromFile("testdata/response.xml")
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	before := xp.Query(assertion, "*[2]")[0]
	pkey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	privatekey := string(pkey)
	xp.Sign(assertion.(types.Element), before.(types.Element), privatekey, "-", "", "sha256")

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
	xp := xpFromFile("testdata/response.xml")
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	before := xp.Query(assertion, "*[2]")[0]
	pkey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	privatekey := string(pkey)
	xp.Sign(assertion.(types.Element), before.(types.Element), privatekey, "-", "", "sha256")

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
	xp := xpFromFile("testdata/response.xml")
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	before := xp.Query(assertion, "*[2]")[0]
	pkey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	privatekey := string(pkey)
	xp.Sign(assertion.(types.Element), before.(types.Element), privatekey, "-", "", "sha256")

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
	xp := xpFromFile("testdata/response.xml")
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	before := xp.Query(assertion, "*[2]")[0]
	pkey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	privatekey := string(pkey)
	xp.Sign(assertion.(types.Element), before.(types.Element), privatekey, "-", "", "sha256")

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
	xp := xpFromFile("testdata/response.xml")
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
	pkey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	privatekey := string(pkey)

	pk := Pem2PrivateKey(privatekey, "")
	ea := NewXp(`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:EncryptedAssertion>`)
	xp.Encrypt(assertion.(types.Element), &pk.PublicKey, ea)

	encryptedAssertion := xp.Query(nil, "//saml:EncryptedAssertion")[0]
	encryptedData := xp.Query(encryptedAssertion, "xenc:EncryptedData")[0]
	decryptedAssertion, _ := xp.Decrypt(encryptedData.(types.Element), pk)

	decryptedAssertionElement, _ := decryptedAssertion.Doc.DocumentElement()
	_ = encryptedAssertion.AddPrevSibling(decryptedAssertionElement)
	parent, _ := encryptedAssertion.ParentNode()
	parent.RemoveChild(encryptedAssertion)

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
	xp := xpFromFile("testdata/response.xml")
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

func ExampleDecryptShibResponse() {
	xml, err := ioutil.ReadFile("testdata/testshib.org.encryptedresponse.xml")
	if err != nil {
		log.Panic(err)
	}
	shibresponse := NewXp(string(xml))

	privatekey, err := ioutil.ReadFile("testdata/private.key.pem")
	if err != nil {
		log.Panic(err)
	}
	block, _ := pem.Decode([]byte(privatekey))
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	encryptedAssertion := shibresponse.Query(nil, "//saml:EncryptedAssertion")[0]
	encryptedData := shibresponse.Query(encryptedAssertion, "xenc:EncryptedData")[0]
	decryptedAssertion, _ := shibresponse.Decrypt(encryptedData.(types.Element), priv)

	decryptedAssertionElement, _ := decryptedAssertion.Doc.DocumentElement()
	_ = encryptedAssertion.AddPrevSibling(decryptedAssertionElement)
	parent, _ := encryptedAssertion.ParentNode()
	parent.RemoveChild(encryptedAssertion)

	printHashedDom(shibresponse)

	/*
		signatures := shibresponse.Query(nil, "/samlp:Response[1]/saml:Assertion[1]/ds:Signature[1]/..")
		// don't do this in real life !!!
		certs := shibresponse.Query(nil, "/samlp:Response[1]/saml:Assertion[1]/ds:Signature[1]/ds:KeyInfo/ds:X509Data/ds:X509Certificate")

		if len(signatures) == 1 {
		    // fix - using package above us
			if err = gosaml.VerifySign(shibresponse, certs, signatures); err != nil {
				log.Panic(err)
			}
		}
		fmt.Println(shibresponse.PP())
	*/

	// Output:
	// ZWiDjYoc03iQr5or7lpvv6Nb8vc=
}

func ExampleDecryptNemloginResponse() {

	xml, err := ioutil.ReadFile("testdata/nemlogin.encryptedresponse.xml")
	if err != nil {
		log.Panic(err)
	}
	nemloginresponse := NewXp(string(xml))

	privatekey, err := ioutil.ReadFile("testdata/nemlogin.key.pem")
	if err != nil {
		log.Panic(err)
	}
	block, _ := pem.Decode([]byte(privatekey))
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	encryptedAssertion := nemloginresponse.Query(nil, "//saml:EncryptedAssertion")[0]
	encryptedData := nemloginresponse.Query(encryptedAssertion, "xenc:EncryptedData")[0]
	decryptedAssertion, _ := nemloginresponse.Decrypt(encryptedData.(types.Element), priv)

	decryptedAssertionElement, _ := decryptedAssertion.Doc.DocumentElement()
	_ = encryptedAssertion.AddPrevSibling(decryptedAssertionElement)
	parent, _ := encryptedAssertion.ParentNode()
	parent.RemoveChild(encryptedAssertion)

	printHashedDom(nemloginresponse)
	/*
		signatures := nemloginresponse.Query(nil, "/samlp:Response[1]/saml:Assertion[1]/ds:Signature[1]/..")
		// don't do this in real life !!!
		certs := nemloginresponse.Query(nil, "/samlp:Response[1]/saml:Assertion[1]/ds:Signature[1]/ds:KeyInfo/ds:X509Data/ds:X509Certificate")

		if len(signatures) == 1 {
		    // fix - using package above us
			if err = gosaml.VerifySign(nemloginresponse, certs, signatures); err != nil {
				log.Panic(err)
			}
		}
		fmt.Println(nemloginresponse.PP())
	*/

	// Output:
	// GuWLBRb1kEiwx/86+R0RmQnI8Mw=
}

func ExampleDecrypt() { //OAEP does not support  different key Encryption methods "digestMethod != keyEncryptionMethod not supported"

	tests := []string{
		"cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p.xml",
		"cipherText__RSA-3072__aes192-gcm__rsa-oaep-mgf1p__Sha256.xml",
		"cipherText__RSA-3072__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1.xml",
		"cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource.xml",
	}

	for _, test := range tests {
		cipherText, _ := ioutil.ReadFile("testdata/w3c/" + test)
		parts := strings.Split(test, "__")
		//fmt.Println(parts)

		pemFile := "testdata/private.key.pem"
		pemBlock, _ := ioutil.ReadFile(pemFile)
		block, _ := pem.Decode(pemBlock)
		pKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
		xp := NewXp("<dummy>" + string(cipherText) + "</dummy>")
		encryptedData := xp.Query(nil, "//dummy/xenc:EncryptedData")[0]

		decrypted, err := xp.Decrypt(encryptedData.(types.Element), pKey)
		if err == rsa.ErrDecryption {
			pemFile := "testdata/w3c/" + parts[1] + ".pem"
			pemBlock, _ := ioutil.ReadFile(pemFile)
			block, _ := pem.Decode(pemBlock)
			pKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
			xp := NewXp("<dummy>" + string(cipherText) + "</dummy>")
			encryptedData := xp.Query(nil, "//dummy/xenc:EncryptedData")[0]

			decrypted, err = xp.Decrypt(encryptedData.(types.Element), pKey)
			if err != nil {
				fmt.Println("Error =", err)
			}
		}
		if err != nil {
			fmt.Println("Error =", err)
		}

		if decrypted != nil {
			printHashedDom(decrypted)
		} else {
			fmt.Println(decrypted)
		}
	}
	// Output:
	// 6naYuUBtlCi/Yf1/DIZgJXIghWM=
	// Error = digestMethod != keyEncryptionMethod not supported
	// <nil>
	// Error = digestMethod != keyEncryptionMethod not supported
	// <nil>
	// Error = digestMethod != keyEncryptionMethod not supported
	// <nil>
}
