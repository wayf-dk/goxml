package goxml

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	//	"github.com/wayf-dk/go-libxml2/parser"
	"github.com/wayf-dk/go-libxml2"
	"github.com/wayf-dk/go-libxml2/clib"
	"github.com/wayf-dk/go-libxml2/dom"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/go-libxml2/xpath"
	"github.com/wayf-dk/go-libxml2/xsd"
	"github.com/y0ssar1an/q"
	"runtime"
)

var (
	_ = log.Printf // For debugging; delete when done.
	_ = q.Q
)

type (

	// Xp is a wrapper for the libxml2 xmlDoc and xmlXpathContext
	// master is a pointer to the original struct with the shared
	// xmlDoc so that is never gets deallocated before any copies
	Xp struct {
		Doc    *dom.Document
		Xpath  *xpath.Context
		master *Xp
	}

	// algo xmlsec digest and signature algorith and their Go name
	algo struct {
		digest    string
		Signature string
		Algo      crypto.Hash
		derprefix string
	}

	Werror struct {
		C     []string
		PC    []uintptr `json:"-"`
		Cause error
	}
)

// algos from shorthand to xmlsec and golang defs of digest and signature algorithms
var (
	Algos = map[string]algo{
		"sha1":   algo{"http://www.w3.org/2000/09/xmldsig#sha1", "http://www.w3.org/2000/09/xmldsig#rsa-sha1", crypto.SHA1, "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"},
		"sha256": algo{"http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", crypto.SHA256, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"},
		//        "ecdsa-sha256" : algo{"http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", crypto.SHA256, ""},
	}

	// m map of prefix to uri for namespaces
	Namespaces = map[string]string{
		"algsupport": "urn:oasis:names:tc:SAML:metadata:algsupport",
		"corto":      "http://corto.wayf.dk",
		"ds":         "http://www.w3.org/2000/09/xmldsig#",
		"idpdisc":    "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol",
		"init":       "urn:oasis:names:tc:SAML:profiles:SSO:request-init",
		"md":         "urn:oasis:names:tc:SAML:2.0:metadata",
		"mdattr":     "urn:oasis:names:tc:SAML:metadata:attribute",
		"mdrpi":      "urn:oasis:names:tc:SAML:metadata:rpi",
		"mdui":       "urn:oasis:names:tc:SAML:metadata:ui",
		"saml":       "urn:oasis:names:tc:SAML:2.0:assertion",
		"samlp":      "urn:oasis:names:tc:SAML:2.0:protocol",
		"sdss":       "http://sdss.ac.uk/2006/06/WAYF",
		"shibmd":     "urn:mace:shibboleth:metadata:1.0",
		"SOAP-ENV":   "http://schemas.xmlsoap.org/soap/envelope/",
		"ukfedlabel": "http://ukfederation.org.uk/2006/11/label",
		"wayf":       "http://wayf.dk/2014/08/wayf",
		"xenc":       "http://www.w3.org/2001/04/xmlenc#",
		"xenc11":     "http://www.w3.org/2009/xmlenc11#",
		"xml":        "http://www.w3.org/XML/1998/namespace",
		"xs":         "http://www.w3.org/2001/XMLSchema",
		"xsi":        "http://www.w3.org/2001/XMLSchema-instance",
		"xsl":        "http://www.w3.org/1999/XSL/Transform",
		"ec":         "http://www.w3.org/2001/10/xml-exc-c14n#",
		"aslo":       "urn:oasis:names:tc:SAML:2.0:protocol:ext:async-slo",
	}

	// persistent cache of compiled schemas
	schemaCache = make(map[string]*xsd.Schema)
)

// init the library
func init() {
	// from xmlsec idents to golang defs of digest algorithms
	for _, a := range Algos {
		Algos[a.digest] = algo{"", "", a.Algo, a.derprefix}
		Algos[a.Signature] = algo{"", "", a.Algo, a.derprefix}
	}
}

/**
  Werror allows us to make error that are list of semistructured messages "tag: message" to
  allow for textual error messages that can be interpreted by a program.
*/

func NewWerror(ctx ...string) Werror {
	x := Werror{C: ctx}
	x.PC = make([]uintptr, 32)
	n := runtime.Callers(2, x.PC)
	x.PC = x.PC[:n]
	return x
}

func Wrap(err error, ctx ...string) error {
	switch x := err.(type) {
	case Werror:
		x.C = append(x.C, ctx...)
		return x
	default:
		werr := NewWerror("cause:" + err.Error())
		werr.Cause = err
		return Wrap(werr, ctx...)
	}
	return err
}

func (e Werror) Error() (err string) {
	errjson, _ := json.Marshal(e.C)
	err = string(errjson)
	return
}

func (e Werror) Stack(depth int) (st string) {
	n := len(e.PC)
	if n > 0 && depth < n {
		pcs := e.PC[:n-depth]
		frames := runtime.CallersFrames(pcs)
		for {
			frame, more := frames.Next()
			function := frame.Function
			file := strings.Split(frame.File, "/")
			st += fmt.Sprintf(" %s %s %d\n", function, file[len(file)-1:][0], frame.Line)
			if !more {
				break
			}
		}
	}
	return
}

// Parse SAML xml to Xp object with doc and xpath with relevant namespaces registered
func NewXp(xml []byte) *Xp {
	x := new(Xp)
	if len(xml) == 0 {
		x.Doc = dom.NewDocument("1.0", "")
	} else {
		doc, _ := libxml2.Parse(xml, 0)
		//doc, _ := libxml2.ParseString(xml, 0)
		x.Doc = doc.(*dom.Document)
	}

	x.addXPathContext()
	return x
}

// Parse SAML xml to Xp object with doc and xpath with relevant namespaces registered
func NewXpFromString(xml string) *Xp {
	x := new(Xp)
	if len(xml) == 0 {
		x.Doc = dom.NewDocument("1.0", "")
	} else {
		doc, _ := libxml2.ParseString(xml, 0)
		x.Doc = doc.(*dom.Document)
	}

	x.addXPathContext()
	return x
}

func NewXpFromFile(file string) *Xp {
	xml, err := ioutil.ReadFile(file)
	if err != nil {
		log.Panic(err)
	}
	return NewXp(xml)
}

// Make a copy of the Xp object - shares the document with the source, but allocates a new xmlXPathContext because
// they are not thread/gorutine safe as the context is set for each query call
// Only the document "owning" Xp releases the C level document and it needs be around as long as any copies - ie. do
// not let the original document be garbage collected or havoc will be wreaked
func (src *Xp) CpXp() (xp *Xp) {
	xp = new(Xp)
	xp.Doc = src.Doc
	xp.master = src
	xp.addXPathContext()
	return
}

func (xp *Xp) addXPathContext() {
	root, _ := xp.Doc.DocumentElement()
	xp.Xpath, _ = xpath.NewContext(root)
	for prefix, ns := range Namespaces {
		xp.Xpath.RegisterNS(prefix, ns)
	}
}

// NewXpFromNode creates a new *Xp from a node (subtree) from another *Xp
func NewXpFromNode(node types.Node) *Xp {
	xp := NewXp([]byte{})
	xp.Doc.SetDocumentElement(xp.CopyNode(node, 1))
	return xp
}

// Parse html object with doc - used in testing for "forwarding" samlresponses from html to http
// Disables error reporting - libxml2 complains about html5 elements
func NewHtmlXp(html []byte) *Xp {
	x := new(Xp)
	if len(html) == 0 {
		x.Doc = dom.NewDocument("1.0", "")
	} else {
		doc, _ := libxml2.ParseHTML(html)
		x.Doc = doc.(*dom.Document)
	}
	// to-do look into making the namespaces map come from the client
	x.addXPathContext()
	return x
}

func (xp *Xp) DocGetRootElement() *types.Node {
	root, _ := xp.Doc.DocumentElement()
	return &root
}

// to-do make go-libxml2 accept extended param
// to-do remove it from Xp
func (xp *Xp) CopyNode(node types.Node, extended int) types.Node {
	nptr, err := clib.XMLDocCopyNode(node, xp.Doc, extended)
	if err != nil {
		return nil
	}
	cp, _ := dom.WrapNode(nptr)
	return cp
}

// C14n Canonicalise the node using the SAML specified exclusive method
// Very slow on large documents with node != nil
func (xp *Xp) C14n(node types.Node, nsPrefixes string) (s string) {
	s, err := clib.C14n(xp.Doc, node, nsPrefixes)
	//	s, err := dom.C14NSerialize{Mode: dom.C14NExclusive1_0, WithComments: false}.Serialize(xp.Doc, node)
	if err != nil {
		log.Panic(err)
	}
	return
}

func (xp *Xp) PP() string {
	root, _ := xp.Doc.DocumentElement()
	return xp.PPE(root)
}

func (xp *Xp) PPE(element types.Node) string {
	return walk(element, 0)
}

// Query Do a xpath query with the given context
// returns a slice of nodes
func (xp *Xp) Query(context types.Node, path string) types.NodeList {
	if context == nil {
		context, _ = xp.Doc.DocumentElement()
	}
	xp.Xpath.SetContextNode(context)
	res, err := xp.Xpath.Find(path)
	return xpath.NodeList(res, err)
}

// QueryNumber evaluates an xpath expressions that returns a number
func (xp *Xp) QueryNumber(context types.Element, path string) (val int) {
	if context != nil {
		xp.Xpath.SetContextNode(context)
	}
	return int(xpath.Number(xp.Xpath.Find(path)))
}

// QueryString evaluates an xpath expressions that returns a string
func (xp *Xp) QueryString(context types.Element, path string) (val string) {
	if context != nil {
		xp.Xpath.SetContextNode(context)
	}
	return xpath.String(xp.Xpath.Find(path))
}

// QueryNumber evaluates an xpath expressions that returns a bool
func (xp *Xp) QueryBool(context types.Element, path string) bool {
	if context != nil {
		xp.Xpath.SetContextNode(context)
	}
	return xpath.Bool(xp.Xpath.Find(path))
}

// Q1 Utility function to get the content of the nodes from a xpath query
// as a slice of strings
func (xp *Xp) QueryMulti(context types.Node, path string) (res []string) {
	nodes := xp.Query(context, path)

	for _, node := range nodes {
		res = append(res, strings.TrimSpace(node.NodeValue()))
	}
	return
}

// Q1 Utility function to get the content of the first node from a xpath query
// as a string
func (xp *Xp) Query1(context types.Node, path string) string {
	res := xp.QueryMulti(context, path)
	if len(res) > 0 {
		return res[0]
	}
	return ""
}

//  QueryDashP generative xpath query - ie. mkdir -p for xpath ...
//  Understands simple xpath expressions including indexes and attribute values
func (xp *Xp) QueryDashP(context types.Node, query string, data string, before types.Node) types.Node {
	// split in path elements, an element might include an attribute expression incl. value eg.
	// /md:EntitiesDescriptor/md:EntityDescriptor[@entityID="https://wayf.wayf.dk"]/md:SPSSODescriptor
	var attrContext types.Node

	re := regexp.MustCompile(`\/?([^\/"]*("[^"]*")?[^\/"]*)`) // slashes inside " is the problem
	re2 := regexp.MustCompile(`^(?:(\w+):?)?([^\[@]*)(?:\[(\d+)\])?(?:\[?@([^=]+)(?:="([^"]*)"])?)?()$`)
	path := re.FindAllStringSubmatch(query, -1)
	if query[0] == '/' {
		var buffer bytes.Buffer
		//buffer.WriteString("/")
		buffer.WriteString(path[0][1])
		path[0][1] = buffer.String()
	}
	for _, elements := range path {
		element := elements[1]
		attrContext = nil
		nodes := xp.Query(context, element)
		if len(nodes) > 0 {
			context = nodes[0]
			continue
		} else {
			d := re2.FindAllStringSubmatch(element, -1)
			if len(d) == 0 {
				panic("QueryDashP problem")
			}
			dn := d[0]
			ns, element, position_s, attribute, value := dn[1], dn[2], dn[3], dn[4], dn[5]
			if element != "" {
				if position_s != "" {
					position, _ := strconv.ParseInt(position_s, 10, 0)
					originalcontext := context
					for i := 1; i <= int(position); i++ {
						q := ns + ":" + element + "[" + strconv.Itoa(i) + "]"
						existingelement := xp.Query(originalcontext, q)
						if len(existingelement) > 0 {
							context = existingelement[0].(types.Element)
						} else {
							context = xp.createElementNS(ns, element, originalcontext, nil)
						}
					}
				} else {
					context = xp.createElementNS(ns, element, context, before)
				}
				before = nil
			}
			if attribute != "" {
				context.(types.Element).SetAttribute(attribute, value)
				ctx, _ := context.(types.Element).GetAttribute(attribute)
				attrContext = ctx.(types.Node)
			}
		}
	}
	// adding the provided value always at end ..
	if data != "" {
		if attrContext != nil {
			attrContext.SetNodeValue(html.EscapeString(data))
		} else {
			context.SetNodeValue(html.EscapeString(data))
		}
	}
	return context
}

// CreateElementNS Create an element with the given namespace
func (xp *Xp) createElementNS(prefix, element string, context types.Node, before types.Node) (newcontext types.Element) {

	newcontext, _ = xp.Doc.CreateElementNS(Namespaces[prefix], prefix+":"+element)

	if before != nil {
		before.AddPrevSibling(newcontext)
	} else {
		if context == nil {
			context, _ = xp.Doc.DocumentElement()
			if context == nil {
				xp.Doc.SetDocumentElement(newcontext)
				return
			}
		}
		context.AddChild(newcontext)
	}
	return
}

// Validate - Schemavalidate the document against the the schema file given in url
func (xp *Xp) SchemaValidate(url string) (errs []error, err error) {
	//    xsdsrc, _ := ioutil.ReadFile(url)
	var schema *xsd.Schema
	if schema = schemaCache[url]; schema == nil {
		schema, err = xsd.Parse([]byte(url))
		if err != nil {
			panic(err)
		}
		schemaCache[url] = schema
	}
	//	defer schema.Free() // never free keep them around until we terminate
	if err := schema.Validate(xp.Doc); err != nil {
		return err.(xsd.SchemaValidationError).Errors(), err
	}
	return nil, nil
}

// Sign the given context with the given private key - which is a PEM or hsm: key
// A hsm: key is a urn 'key' that points to a specific key/action in a goeleven interface to a HSM
// See https://github.com/wayf-dk/goeleven
func (xp *Xp) Sign(context, before types.Element, privatekey, pw []byte, cert, algo string) (err error) {
	contextHash := Hash(Algos[algo].Algo, xp.C14n(context, ""))
	contextDigest := base64.StdEncoding.EncodeToString(contextHash)

	id := xp.Query1(context, "@ID")

	signedInfo := xp.QueryDashP(context, `ds:Signature/ds:SignedInfo`, "", before).(types.Element)
	xp.QueryDashP(signedInfo, `/ds:CanonicalizationMethod/@Algorithm`, "http://www.w3.org/2001/10/xml-exc-c14n#", nil)
	xp.QueryDashP(signedInfo, `ds:SignatureMethod[1]/@Algorithm`, Algos[algo].Signature, nil)
	xp.QueryDashP(signedInfo, `ds:Reference/@URI`, "#"+id, nil)
	xp.QueryDashP(signedInfo, `ds:Reference/ds:Transforms/ds:Transform[1][@Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"]`, "", nil)
	xp.QueryDashP(signedInfo, `ds:Reference/ds:Transforms/ds:Transform[2][@Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"]`, "", nil)
	xp.QueryDashP(signedInfo, `ds:Reference/ds:DigestMethod[1]/@Algorithm`, Algos[algo].digest, nil)
	xp.QueryDashP(signedInfo, `ds:Reference/ds:DigestValue[1]`, contextDigest, nil)

	signedInfoC14n := xp.C14n(signedInfo, "")
	digest := Hash(Algos[algo].Algo, signedInfoC14n)

	signaturevalue, err := Sign(digest, privatekey, pw, algo)
	if err != nil {
		return
	}

	signatureval := base64.StdEncoding.EncodeToString(signaturevalue)
	xp.QueryDashP(context, `ds:Signature/ds:SignatureValue`, signatureval, nil)
	xp.QueryDashP(context, `ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate`, cert, nil)
	return
}

// VerifySignature Verify a signature for the given context and public key
func (xp *Xp) VerifySignature(context types.Element, pub *rsa.PublicKey) error {
	signaturelist := xp.Query(context, "ds:Signature[1]")
	if len(signaturelist) != 1 {
		return fmt.Errorf("no signature found")
	}
	signature := signaturelist[0].(types.Element)

	signatureValue := xp.Query1(signature, "ds:SignatureValue")
	signedInfo := xp.Query(signature, "ds:SignedInfo")[0].(types.Element)
	signedInfoC14n := xp.C14n(signedInfo, "")
	digestValue := xp.Query1(signedInfo, "ds:Reference/ds:DigestValue")
	ID := xp.Query1(context, "@ID")
	URI := xp.Query1(signedInfo, "ds:Reference/@URI")
	isvalid := "#"+ID == URI
	if !isvalid {
		return fmt.Errorf("ID mismatch")
	}

	digestMethod := xp.Query1(signedInfo, "ds:Reference/ds:DigestMethod/@Algorithm")

	nsPrefix := xp.Query1(signature, ".//ec:InclusiveNamespaces/@PrefixList")

	context.RemoveChild(signature)
	contextDigest := Hash(Algos[digestMethod].Algo, xp.C14n(context, nsPrefix))
	contextDigestValueComputed := base64.StdEncoding.EncodeToString(contextDigest)

	isvalid = isvalid && contextDigestValueComputed == digestValue
	if !isvalid {
		return fmt.Errorf("digest mismatch")
	}
	signatureMethod := xp.Query1(signedInfo, "ds:SignatureMethod/@Algorithm")
	signedInfoDigest := Hash(Algos[signatureMethod].Algo, signedInfoC14n)

	ds, _ := base64.StdEncoding.DecodeString(signatureValue)
	err := rsa.VerifyPKCS1v15(pub, Algos[signatureMethod].Algo, signedInfoDigest[:], ds)
	return err
}

func Sign(digest, privatekey, pw []byte, algo string) (signaturevalue []byte, err error) {
	signFuncs := map[bool]func([]byte, []byte, []byte, string) ([]byte, error){true: signGoEleven, false: signGo}
	signaturevalue, err = signFuncs[bytes.HasPrefix(privatekey, []byte("hsm:"))](digest, privatekey, pw, algo)
	return
}

func signGo(digest, privatekey, pw []byte, algo string) (signaturevalue []byte, err error) {
	var priv *rsa.PrivateKey
	block, _ := pem.Decode(privatekey)
	if block == nil {
		return nil, NewWerror("errmsg:PEM decode")
	}
	if string(pw) != "-" {
		privbytes, err := x509.DecryptPEMBlock(block, pw)
		if err != nil {
			return nil, Wrap(err, "errmsg:Password error")
		}
		priv, err = x509.ParsePKCS1PrivateKey(privbytes)
	} else {
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if err != nil {
		return
	}
	signaturevalue, err = rsa.SignPKCS1v15(rand.Reader, priv, Algos[algo].Algo, digest)
	return
}

func signGoEleven(digest, privatekey, pw []byte, algo string) ([]byte, error) {
	data := append([]byte(Algos[algo].derprefix), digest...)
	return callHSM("sign", data, string(privatekey), "CKM_RSA_PKCS", "")
}

// Encrypt the context with the given publickey
// Hardcoded to aes256-cbc for the symetric part and
// rsa-oaep-mgf1p and sha1 for the rsa part
func (xp *Xp) Encrypt(context types.Element, publickey *rsa.PublicKey, ee *Xp) (err error) {
	ects := ee.QueryDashP(nil, `/xenc:EncryptedData`, "", nil)
	ects.(types.Element).SetAttribute("Type", "http://www.w3.org/2001/04/xmlenc#Element")
	ee.QueryDashP(ects, `xenc:EncryptionMethod[@Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"]`, "", nil)
	ee.QueryDashP(ects, `ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"]/ds:DigestMethod[@Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"]`, "", nil)

	sessionkey, ciphertext, err := encryptAESCBC([]byte(context.ToString(1, true)))
	if err != nil {
		return
	}
	sessionkey, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, publickey, sessionkey, nil)
	if err != nil {
		return
	}

	ee.QueryDashP(ects, `ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue`, base64.StdEncoding.EncodeToString(sessionkey), nil)
	ee.QueryDashP(ects, `xenc:CipherData/xenc:CipherValue`, base64.StdEncoding.EncodeToString(ciphertext), nil)
	parent, _ := context.ParentNode()

	ec, _ := ee.Doc.DocumentElement()
	ec = xp.CopyNode(ec, 1)
	context.AddPrevSibling(ec)
	parent.RemoveChild(context)
	return
}

// Decrypt decrypts the context using the given privatekey .
// The context element is removed
func (xp *Xp) Decrypt(context types.Element, privatekey []byte) (x *Xp, err error) {
	encryptionMethod := xp.Query1(context, "./xenc:EncryptionMethod/@Algorithm")
	keyEncryptionMethod := xp.Query1(context, "./ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm")
	digestMethod := xp.Query1(context, "./ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/ds:DigestMethod/@Algorithm")
	OAEPparams := xp.Query1(context, "./ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/xenc:OAEPparams")
	MGF := xp.Query1(context, "./ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/xenc11:MGF/@Algorithm")
	encryptedKey := xp.Query1(context, "./ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue")

	decrypt := decryptGCM
	digestAlgorithm := crypto.SHA1
	mgfAlgorithm := crypto.SHA1

	switch keyEncryptionMethod {
	case "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p":
		mgfAlgorithm = crypto.SHA1
	case "http://www.w3.org/2009/xmlenc11#rsa-oaep":
		switch MGF {
		case "http://www.w3.org/2009/xmlenc11#mgf1sha1":
			mgfAlgorithm = crypto.SHA1
		case "http://www.w3.org/2009/xmlenc11#mgf1sha256":
			mgfAlgorithm = crypto.SHA256
		default:
			return nil, NewWerror("unsupported MGF", "MGF: "+MGF)
		}
	default:
		return nil, NewWerror("unsupported keyEncryptionMethod", "keyEncryptionMethod: "+keyEncryptionMethod)
	}

	switch digestMethod {
	case "http://www.w3.org/2000/09/xmldsig#sha1":
		digestAlgorithm = crypto.SHA1
	case "http://www.w3.org/2001/04/xmlenc#sha256":
		digestAlgorithm = crypto.SHA256
	case "http://www.w3.org/2001/04/xmldsig-more#sha384":
		digestAlgorithm = crypto.SHA384
	case "http://www.w3.org/2001/04/xmlenc#sha512":
		digestAlgorithm = crypto.SHA512
	default:
		return nil, NewWerror("unsupported digestMethod", "digestMethod: "+digestMethod)
	}

	switch encryptionMethod {
	case "http://www.w3.org/2001/04/xmlenc#aes128-cbc", "http://www.w3.org/2009/xmlenc11#aes192-cbc", "http://www.w3.org/2001/04/xmlenc#aes256-cbc":
		decrypt = decryptCBC
	case "http://www.w3.org/2009/xmlenc11#aes128-gcm", "http://www.w3.org/2009/xmlenc11#aes192-gcm", "http://www.w3.org/2009/xmlenc11#aes256-gcm":
		decrypt = decryptGCM
	default:
		return nil, NewWerror("unsupported encryptionMethod", "encryptionMethod: "+encryptionMethod)
	}

	encryptedKeybyte, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encryptedKey))
	if err != nil {
		return
	}

	OAEPparamsbyte, err := base64.StdEncoding.DecodeString(strings.TrimSpace(OAEPparams))
	if err != nil {
		return
	}

	if digestAlgorithm != mgfAlgorithm {
		return nil, errors.New("digestMethod != keyEncryptionMethod not supported")
	}

	var sessionkey []byte
	switch bytes.HasPrefix(privatekey, []byte("hsm:")) {
	case true:
		sessionkey, err = callHSM("decrypt", encryptedKeybyte, string(privatekey), "CKM_RSA_PKCS_OAEP", "CKM_SHA_1")
	case false:
		block, _ := pem.Decode(privatekey)
		/*
		   if pw != "-" {
		       privbytes, _ := x509.DecryptPEMBlock(block, []byte(pw))
		       priv, _ = x509.ParsePKCS1PrivateKey(privbytes)
		   } else {
		       priv, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
		   }
		*/
		priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

		sessionkey, err = rsa.DecryptOAEP(digestAlgorithm.New(), rand.Reader, priv, encryptedKeybyte, OAEPparamsbyte)
	}
	//sessionkey, err := rsa.DecryptPKCS1v15(rand.Reader, privatekey, encryptedKeybyte, nil)
	if err != nil {
		return
	}

	switch len(sessionkey) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("Unsupported keylength for AES %d", len(sessionkey))
	}

	ciphertext := xp.Query1(context, "./xenc:CipherData/xenc:CipherValue")
	ciphertextbyte, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ciphertext))
	if err != nil {
		return
	}

	plaintext, err := decrypt([]byte(sessionkey), bytes.TrimSpace(ciphertextbyte))
	if err != nil {
		return
	}

	return NewXp(plaintext), nil
}

// Pem2PrivateKey converts a PEM encoded private key with an optional password to a *rsa.PrivateKey
func Pem2PrivateKey(privatekeypem, pw []byte) (privatekey *rsa.PrivateKey) {
	block, _ := pem.Decode(privatekeypem)
	if string(pw) != "" {
		privbytes, _ := x509.DecryptPEMBlock(block, pw)
		privatekey, _ = x509.ParsePKCS1PrivateKey(privbytes)
	} else {
		privatekey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	return
}

// encryptAES encrypts the plaintext with a generated random key and returns both the key and the ciphertext
func encryptAESCBC(plaintext []byte) (key, ciphertext []byte, err error) {
	key = make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, key); err != nil {
		return
	}
	paddinglen := aes.BlockSize - len(plaintext)%aes.BlockSize

	plaintext = append(plaintext, bytes.Repeat([]byte{byte(paddinglen)}, paddinglen)...)
	ciphertext = make([]byte, aes.BlockSize+len(plaintext))

	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	return
}

// decryptAES decrypts the ciphertext using the supplied key
func decryptGCM(key, ciphertext []byte) (plaintext []byte, err error) {
	if len(ciphertext) < 40 { // we want at least 12 bytes of actual data in addition to 12 bytes Initialization Vector and 16 bytes Authentication Tag
		return nil, errors.New("Not enough data to decrypt for AES-GCM")
	}

	iv := ciphertext[:12]
	ciphertext = ciphertext[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	plaintext, err = aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return
	}
	return
}

// decryptAES decrypts the ciphertext using the supplied key
func decryptCBC(key, ciphertext []byte) (plaintext []byte, err error) {
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	paddinglen := int(ciphertext[len(ciphertext)-1])
	if paddinglen > aes.BlockSize || paddinglen == 0 {
		return nil, errors.New("decrypted plaintext is not padded correctly")
	}
	// remove padding
	plaintext = ciphertext[:len(ciphertext)-int(paddinglen)]
	return
}

/*
   private function signHSM($data, $keyident, $algo) {
       // we do the hashing here - the $algo int/string confusion is due to xmlseclibs
       // openssl_sign confusingly enough accepts just the hashing algorithm
       $hashalgo = array(OPENSSL_ALGO_SHA1 => 'sha1', 'sha1' => 'sha1', 'SHA256' => 'sha256');
       // always just do the RSA signing - we assume that the service can do the padding/DER encoding
       if (!key_exists($algo, $hashalgo)) {
           return false;
       }
       $algo = $hashalgo[$algo];

       switch ($algo) {
           case 'sha1':
               $t = pack('H*', '3021300906052b0e03021a05000414');
               break;
           case 'sha256':
               $t = pack('H*', '3031300d060960864801650304020105000420');
               break;
       }

       $data = $t . hash($hashalgo[$algo], $data, true);
       return $this->callHSM('sign', $data, $keyident, 'CKM_RSA_PKCS', '');
   }




   private function decryptHSM($data, $keyident) {
       return $this->callHSM('decrypt', $data, $keyident, 'CKM_RSA_PKCS_OAEP', 'CKM_SHA_1');
   }
*/

func callHSM(function string, data []byte, privatekey, mech, digest string) (res []byte, err error) {
	type request struct {
		Data      string `json:"data"`
		Mech      string `json:"mech"`
		Digest    string `json:"digest"`
		Function  string `json:"function"`
		Sharedkey string `json:"sharedkey"`
	}

	var response struct {
		Signed []byte `json:"signed"`
	}

	parts := strings.SplitN(strings.TrimSpace(privatekey), ":", 3)

	payload := request{
		Data:      base64.StdEncoding.EncodeToString(data),
		Mech:      mech,
		Digest:    digest,
		Function:  function,
		Sharedkey: parts[1],
	}

	jsontxt, err := json.Marshal(payload)
	if err != nil {
		return nil, Wrap(err)
	}

	resp, err := http.Post(parts[2], "application/json", bytes.NewBuffer(jsontxt))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, Wrap(err)
	}
	return response.Signed, err
}

// Hash Perform a digest calculation using the given crypto.Hash
func Hash(h crypto.Hash, data string) []byte {
	digest := h.New()
	io.WriteString(digest, data)
	return digest.Sum(nil)
}

func walk(n types.Node, level int) (pp string) {
	switch n := n.(type) {
	case types.Element:
		tag := n.NodeName()
		attrs := []string{}
		namespaces, _ := n.GetNamespaces()
		for _, ns := range namespaces {
			prefix := "xmlns"
			if ns.Prefix() != "" {
				prefix = prefix + ":" + ns.Prefix()
			}
			attrs = append(attrs, prefix+"=\""+ns.URI()+"\"")
		}

		attributes, _ := n.Attributes()
		for _, ats := range attributes {
			attrs = append(attrs, strings.TrimSpace(ats.String()))
		}
		l := len(attrs)
		x := ""
		if l == 0 {
			//x = ">"
		} else if l > 0 {
			x = " " + attrs[0]
			attrs = attrs[1:]
			if l == 1 {
				//x += ">"
			}
			l--
		}

		pp = fmt.Sprintf("%*s<%s%s", level*4, "", tag, x)
		x = ""
		for i, attr := range attrs {
			newline1 := "\n"
			if i == l-1 {
				//x = ">"
				newline1 = ""
			}
			newline := ""
			if i == 0 {
				newline = "\n"
			}
			pp += fmt.Sprintf("%s%*s%s%s%s", newline, level*4+2+len(tag), "", attr, x, newline1)
		}
		children, _ := n.ChildNodes()
		elements := false
		subpp := ""
		for _, c := range children {
			_, ok := c.(types.Element)
			elements = elements || ok
			subpp += walk(c, level+1)
		}
		if elements {
			pp += fmt.Sprintf(">\n%s%*s</%s>\n", subpp, level*4, "", n.NodeName())
		} else {
			if subpp == "" {
				pp += "/>\n"
			} else {
				pp += fmt.Sprintf(">\n%*s%s\n%*s</%s>\n", level*5, "", subpp, level*4, "", n.NodeName())
			}
		}
	case types.Node:
		if txt := strings.TrimSpace(n.TextContent()); txt != "" {
			pp = txt
		}
	}
	return
}
