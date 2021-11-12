package goxml

/*
#cgo pkg-config: libxml-2.0
#include <stdio.h>
#include <string.h>
#include <libxml/tree.h>
#include <libxml/xmlIO.h>
#include <libxml/xmlschemas.h>

static int rlen;
static int roffset;

char* samlp;
char* saml;
char* xmldsig;
char* xenc;
char* xenc11;

static int
xpMatch(const char * URI) {
//    printf("match: %s\n", URI);
    if (!strcmp(URI, "saml-schema-assertion-2.0.xsd")) return(1);
    if (!strcmp(URI, "xmldsig-core-schema.xsd")) return(1);
    if (!strcmp(URI, "xenc-schema-11.xsd")) return(1);
    if (!strcmp(URI, "xenc-schema.xsd")) return(1);
    return(0);
}

static void *
xpOpen(const char * URI) {
//    printf("open %s\n", URI);
    roffset = 0;
    if (!strcmp(URI, "saml-schema-assertion-2.0.xsd")) { rlen = strlen(saml); return(saml); }
    if (!strcmp(URI, "xmldsig-core-schema.xsd")) { rlen = strlen(xmldsig); return(xmldsig); }
    if (!strcmp(URI, "xenc-schema-11.xsd")) { rlen = strlen(xenc11); return(xenc11); }
    if (!strcmp(URI, "xenc-schema.xsd")) { rlen = strlen(xenc); return(xenc); }
    return NULL;
}

static int
xpRead(void * context, char * buffer, int len) {
//  printf("read %d\n", len);
  const char *ptr = (const char *) context;
//  printf("buffer len %d %d\n", rlen, len);
  if (len > rlen) len = rlen;
  memcpy(buffer, ptr+roffset, len);
  rlen -= len;
  roffset += len;
  return(len);

}

static int
xpClose(void * context) {
//    printf("close\n");
    return(0);
}

xmlSchemaPtr Samlschema(char* samlpSchema, char* samlSchema, char *xmldsigSchema, char* xencSchema, char* xencSchema11) {
    xmlDocPtr doc;
    xmlSchemaParserCtxtPtr schemaCtx;
    xmlSchemaPtr schemaPtr;

    samlp = samlpSchema;
    saml = samlSchema;
    xmldsig = xmldsigSchema;
    xenc = xencSchema;
    xenc11 = xencSchema11;

    if (xmlRegisterInputCallbacks(xpMatch, xpOpen, xpRead, xpClose) < 0) {
        fprintf(stderr, "failed to register sp handler\n");
	    exit(1);
    }

    schemaCtx = xmlSchemaNewMemParserCtxt(samlp, strlen(samlp));
    schemaPtr = xmlSchemaParse(schemaCtx);
    xmlRegisterDefaultInputCallbacks();

    free(samlp);
    free(saml);
    free(xmldsig);
    free(xenc);
    free(xenc11);
    return(schemaPtr);
}

void devnull(void * ctx, const char * msg, ...) {
    return;
}

void DisableErrorOutput(xmlSchemaValidCtxtPtr ctx) {
    xmlGenericErrorFunc handler = (xmlGenericErrorFunc)devnull;
    xmlSetGenericErrorFunc(ctx, handler);
//    initGenericErrorDefaultFunc(handler);
}

*/
import "C"

import (
	_ "embed"
    "fmt"
	"github.com/wayf-dk/go-libxml2/types"
	"unsafe"
)

var (
	//go:embed schemas/saml-schema-protocol-2.0.xsd
	samlpSchema string

	//go:embed schemas/saml-schema-assertion-2.0.xsd
	samlSchema string

	//go:embed schemas/xmldsig-core-schema.xsd
	xmldsigSchema string

	//go:embed schemas/xenc-schema.xsd
	xencSchema string

	//go:embed schemas/xenc-schema-11.xsd
	xencSchema11 string

	sptr C.xmlSchemaPtr
)

func init() {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
    sptr = C.Samlschema(C.CString(samlpSchema), C.CString(samlSchema), C.CString(xmldsigSchema), C.CString(xencSchema), C.CString(xencSchema11))
}

func validate(d types.Document) error {
	ctx := C.xmlSchemaNewValidCtxt(sptr)
	if ctx == nil {
		return fmt.Errorf("failed to build validator")
	}
	C.DisableErrorOutput(ctx)
	defer C.xmlSchemaFreeValidCtxt(ctx)

	dptr := (*C.xmlDoc)(unsafe.Pointer(d.Pointer()))

	if C.xmlSchemaValidateDoc(ctx, dptr) == 0 {
		return nil
	}
	return fmt.Errorf("schema validation failed")
}
