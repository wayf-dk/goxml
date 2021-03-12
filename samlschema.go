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

static int
xpMatch(const char * URI) {
//    printf("match: %s\n", URI);
    if (!strncmp(URI, "saml", 4)) return(1);
    if (!strncmp(URI, "xmldsig", 6)) return(1);
    if (!strncmp(URI, "xenc", 4)) return(1);
    return(0);
}

static void *
xpOpen(const char * URI) {
//    printf("open %s\n", URI);
    roffset = 0;
    if (!strncmp(URI, "saml", 4)) { rlen = strlen(saml); return(saml); }
    if (!strncmp(URI, "xmldsig", 4)) { rlen = strlen(xmldsig); return(xmldsig); }
    if (!strncmp(URI, "xenc", 4)) { rlen = strlen(xenc); return(xenc); }
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

xmlSchemaPtr Samlschema(char* samlpSchema, char* samlSchema, char *xmldsigSchema, char* xencSchema) {
    xmlDocPtr doc;
    xmlSchemaParserCtxtPtr schemaCtx;
    xmlSchemaPtr schemaPtr;

    samlp = samlpSchema;
    saml = samlSchema;
    xmldsig = xmldsigSchema;
    xenc = xencSchema;

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
	"log"
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

	sptr C.xmlSchemaPtr
)

func init() {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
    sptr = C.Samlschema(C.CString(samlpSchema), C.CString(samlSchema), C.CString(xmldsigSchema), C.CString(xencSchema))
	log.Println("samlschema.go")
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
