package goxml

import (
	"bytes"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/wayf-dk/go-libxml2"
	"github.com/wayf-dk/go-libxml2/clib"
	"github.com/wayf-dk/go-libxml2/dom"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/go-libxml2/xpath"
	"github.com/wayf-dk/go-libxml2/xsd"
)

type (
	// Xp is a wrapper for the libxml2 xmlDoc and xmlXpathContext
	// master is a pointer to the original struct with the shared
	// xmlDoc so that is never gets deallocated before any copies
	Xp struct {
		Doc      *dom.Document
		Xpath    *xpath.Context
		master   *Xp
		released bool
	}
)

var (
	re  = regexp.MustCompile(`\/?([^\/"]*("[^"]*")?[^\/"]*)`) // slashes inside " is the problem
	re2 = regexp.MustCompile(`^(?:(\w+):?)?([^\[@]*)(?:\[(\d+)\])?(?:\[?@([^=]+)(?:="([^"]*)"])?)?()$`)

	// persistent cache of compiled schemas
	schemaCache = make(map[string]*xsd.Schema)
	libxml2Lock sync.Mutex
	qdpLock     sync.Mutex
)

// freeXp free the Memory
func freeXp(xp *Xp) {
	//q.Q(xp)
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
	//q.Q("freeXp", xp, NewWerror("freeXp").Stack(2))
	if xp.released {
		return
	}
	xp.Xpath.Free()
	if xp.master == nil { // the Doc is shared - only Free the master
		xp.Doc.Free()
	}
	xp.released = true
}

// NewXp Parse SAML xml to Xp object with doc and xpath with relevant namespaces registered
func NewXp(xml []byte) (xp *Xp) {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
	xp = new(Xp)
	doc, _ := libxml2.Parse(xml, 0)
	if doc != nil {
		xp.Doc = doc.(*dom.Document)
	} else {
		xp.Doc = dom.NewDocument("1.0", "")
	}

	xp.addXPathContext()
	runtime.SetFinalizer(xp, freeXp)
	//q.Q("Newxp", xp, NewWerror("Newxp").Stack(2))
	return
}

// NewXpFromString Parse SAML xml to Xp object with doc and xpath with relevant namespaces registered
func NewXpFromString(xml string) (xp *Xp) {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
	xp = new(Xp)
	doc, _ := libxml2.ParseString(xml, 0)
	if doc != nil {
		xp.Doc = doc.(*dom.Document)
	} else {
		xp.Doc = dom.NewDocument("1.0", "")
	}

	xp.addXPathContext()
	runtime.SetFinalizer(xp, freeXp)
	//q.Q("NewXpFromString", xp, NewWerror("NewXpFromString").Stack(2))
	return
}

// NewXpFromFile Creates a NewXP from File. Used for testing purposes
func NewXpFromFile(file string) *Xp {
	xml, err := ioutil.ReadFile(file)
	if err != nil {
		log.Panic(err)
	}
	return NewXp(xml)
}

// CpXp Make a copy of the Xp object - shares the document with the source, but allocates a new xmlXPathContext because
// They are not thread/gorutine safe as the context is set for each query call
// Only the document "owning" Xp releases the C level document and it needs be around as long as any copies - ie. do
// not let the original document be garbage collected or havoc will be wreaked
func (src *Xp) CpXp() (xp *Xp) {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
	xp = new(Xp)
	xp.Doc = src.Doc
	xp.master = src
	xp.addXPathContext()
	runtime.SetFinalizer(xp, freeXp)
	//q.Q("cpXp", xp, NewWerror("cpXp").Stack(2))
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

// NewHTMLXp - Parse html object with doc - used in testing for "forwarding" samlresponses from html to http
// Disables error reporting - libxml2 complains about html5 elements
func NewHTMLXp(html []byte) (xp *Xp) {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
	xp = new(Xp)
	if len(html) == 0 {
		xp.Doc = dom.NewDocument("1.0", "")
	} else {
		doc, _ := libxml2.ParseHTML(html)
		xp.Doc = doc.(*dom.Document)
	}
	// to-do look into making the namespaces map come from the client
	runtime.SetFinalizer(xp, freeXp)
	xp.addXPathContext()
	//	q.Q("NewHTMLXp", xp, NewWerror("NewHTMLXp").Stack(2))
	return
}

// DocGetRootElement returns the root element of the document
func (xp *Xp) DocGetRootElement() types.Node {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
	root, _ := xp.Doc.DocumentElement()
	return root
}

// Rm deletes the node
func (xp *Xp) Rm(context types.Node, path string) {
	for _, node := range xp.Query(context, path) {
		libxml2Lock.Lock()
		parent, _ := node.ParentNode()
		switch x := node.(type) {
		case types.Attribute:
			parent.(types.Element).RemoveAttribute(x.NodeName())
		case types.Element:
			parent.RemoveChild(x)
		}
		node.Free()
		libxml2Lock.Unlock()
	}
}

// CopyNode - copies the node
// to-do make go-libxml2 accept extended param
// to-do remove it from Xp
func (xp *Xp) CopyNode(node types.Node, extended int) types.Node {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
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
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
	s, err := clib.C14n(xp.Doc, node, nsPrefixes)
	//	s, err := dom.C14NSerialize{Mode: dom.C14NExclusive1_0, WithComments: false}.Serialize(xp.Doc, node)
	if err != nil {
		log.Panic(err)
	}
	return
}

// Dump dumps the whole document
func (xp *Xp) Dump() []byte {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
	return []byte(xp.Doc.Dump(false))
}

// PP Pretty Prints the document
func (xp *Xp) PP() string {
	root, _ := xp.Doc.DocumentElement()
	return xp.PPE(root)
}

// PPE Pretty Prints an element
func (xp *Xp) PPE(element types.Node) string {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
	return walk(element, 0)
}

// Query Do a xpath query with the given context
// returns a slice of nodes
func (xp *Xp) Query(context types.Node, path string) types.NodeList {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
	if context == nil {
		context, _ = xp.Doc.DocumentElement()
	}
	xp.Xpath.SetContextNode(context)
	return xpath.NodeList(xp.Xpath.Find(path))
}

// QueryNumber evaluates an xpath expressions that returns a number
func (xp *Xp) QueryNumber(context types.Node, path string) (val int) {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
	if context != nil {
		xp.Xpath.SetContextNode(context)
	}
	return int(xpath.Number(xp.Xpath.Find(path)))
}

// QueryString evaluates an xpath expressions that returns a string
func (xp *Xp) QueryString(context types.Node, path string) (val string) {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
	if context != nil {
		xp.Xpath.SetContextNode(context)
	}
	return xpath.String(xp.Xpath.Find(path))
}

// QueryBool evaluates an xpath expressions that returns a bool
func (xp *Xp) QueryBool(context types.Node, path string) bool {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
	if context != nil {
		xp.Xpath.SetContextNode(context)
	}
	return xpath.Bool(xp.Xpath.Find(path))
}

// QueryXMLBool evaluates an xpath element that is XML boolean ie 1 or true - '.' works for both elements and attributes
func (xp *Xp) QueryXMLBool(context types.Node, path string) bool {
	switch strings.TrimSpace(xp.Query1(context, path)) {
	case "1", "true":
		return true
	default:
		return false
	}
	//	return xp.QueryBool(context, "boolean("+path+"[normalize-space(.)='1' or normalize-space(.)='true'])")
}

func (xp *Xp) find(context types.Node, path string) (res types.XPathResult) {
	if context == nil {
		context, _ = xp.Doc.DocumentElement()
	}
	xp.Xpath.SetContextNode(context)
	res, _ = xp.Xpath.Find(path)
	return
}

// QueryMulti function to get the content of the nodes from a xpath query
// as a slice of strings
func (xp *Xp) QueryMulti(context types.Node, path string) (res []string) {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
	x := xp.find(context, path)
	switch x.Type() {
	case xpath.NodeSetType:
		for _, node := range x.NodeList() {
			res = append(res, strings.TrimSpace(node.NodeValue()))
		}
	case xpath.StringType:
		res = []string{clib.XMLXPathObjectString(x)}
	default:
		res = []string{fmt.Sprintf("%v", x)}
	}
	x.Free()
	return
}

// Query1 Utility function to get the content of the first node from a xpath query
// as a string
func (xp *Xp) Query1(context types.Node, path string) string {
	res := xp.QueryMulti(context, path)
	if len(res) > 0 {
		return res[0]
	}
	return ""
}

// QueryDashP generative xpath query - ie. mkdir -p for xpath ...
// Understands simple xpath expressions including indexes and attribute values
func (xp *Xp) QueryDashP(context types.Node, query string, data string, before types.Node) types.Node {
	qdpLock.Lock()
	defer qdpLock.Unlock()

	// split in path elements, an element might include an attribute expression incl. value eg.
	// /md:EntitiesDescriptor/md:EntityDescriptor[@entityID="https://wayf.wayf.dk"]/md:SPSSODescriptor
	var attrContext types.Node

	if context == nil {
		context, _ = xp.Doc.DocumentElement()
	}
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
			ns, element, positionS, attribute, value := dn[1], dn[2], dn[3], dn[4], dn[5]
			if element != "" {
				if positionS == "0" {
					context = xp.createElementNS(ns, element, context, before)
				} else if positionS != "" {
					position, _ := strconv.ParseInt(positionS, 10, 0)
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
				//defer attrContext.Free()
			}
		}
	}
	// adding the provided value always at end ..
	if data != "" {
		if data == "\x1b" {
			data = ""
		}
		if attrContext != nil {
			attrContext.SetNodeValue(html.EscapeString(data))
		} else {
			context.SetNodeValue(html.EscapeString(data))
		}
	}
	return context
}

func (xp *Xp) QueryDashPOptional(context types.Node, query string, data string, before types.Node) types.Node {
	if data != "" {
		return xp.QueryDashP(context, query, data, before)
	}
	return nil
}

// CreateElementNS Create an element with the given namespace
func (xp *Xp) createElementNS(prefix, element string, context types.Node, before types.Node) (newcontext types.Element) {

	//    q.Q(context, xp.PPE(context))
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

// SchemaValidate validate the document against the the schema file given in url
func (xp *Xp) SchemaValidate(url string) (errs []error, err error) {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
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
