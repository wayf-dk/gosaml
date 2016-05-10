// Gosaml is a library for doing SAML stuff in Go.
// It uses a libxml2 dom representation of SAML "objects" and combines it with xpath for extracting information
//
// It also supplies a "generative-xpath" function that allows insertion into SAML "objects" using (a subset of) xpath queries.
// It uses Go's native crypto for signing and signature verification
//
// Except for the crypto stuff it is just a thin layer on top of a few facilities from libxml2
package gosaml

/*
#cgo pkg-config: libxml-2.0
#include <stdlib.h>
#include <libxml2/libxml/tree.h>
#include <libxml2/libxml/HTMLparser.h>
#include <libxml2/libxml/xmlsave.h>
#include <libxml2/libxml/c14n.h>
#include <libxml2/libxml/xpath.h>
#include <libxml2/libxml/xpathInternals.h>
#include <libxml2/libxml/xmlmemory.h>
#include <libxml/xmlschemas.h>
xmlNode* fetchNode(xmlNodeSet *nodeset, int index) {
    return nodeset->nodeTab[index];
}
// for now we just ignore the actual errors - the end result of xmlSchemaValidateDoc will tell if there were any
void void_libxml_error_handler(void *ctx, const char *msg, const char *param) {
    printf(msg, param);
}
*/
import "C"

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

var _ = log.Printf // For debugging; delete when done.

const (
	xsDateTime   = "2006-01-02T15:04:05Z"
	IdpCertQuery = `./md:IDPSSODescriptor/md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`
	spCertQuery  = `./md:SPSSODescriptor/md:KeyDescriptor[@use="encryption" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`
	samlSchema   = "/home/mz/src/github.com/wayf-dk/gosaml/schemas/saml-schema-protocol-2.0.xsd"
	certPath     = "/etc/ssl/wayf/signing/"

	basic      = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	uri        = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	transient  = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	persistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
)

// Xp is a wrapper for the libxml2 xmlDoc and xmlXpathContext
// master is a pointer to the original struct with the shared
// xmlDoc so that is never gets deallocated before any copies
type (
	Md interface {
		MDQ(key string) (xp *Xp, err error)
	}

	Xp struct {
		doc      *C.xmlDoc
		xpathCtx *C.xmlXPathContext
		master *Xp
	}

	// HtmlXp si a wrapper for libxml2 and xmlXpathContext for html docs
	HtmlXp struct {
		doc      *C.xmlDoc
		xpathCtx *C.xmlXPathContext
	}

	// IdAndTiming is a type that allows to client to pass the ids and timing used when making
	// new requests and responses - also used for fixed ids and timings when testing
	IdAndTiming struct {
		Now                    time.Time
		Slack, Sessionduration time.Duration
		Id, Assertionid        string
	}

	// NamespaceMap is namespace struct (in *C.char format) from ns prefix to urn/url
	namespaceMap struct {
		prefix *C.xmlChar
		ns_uri *C.xmlChar
	}

	// algo xmlsec digest and signature algorith and their Go name
	algo struct {
		digest    string
		signature string
		algo      crypto.Hash
		derprefix string
	}
)

// namespaces maps between a ns prefix and the urn/url
var namespaces map[string]namespaceMap
var metadatacache = make(map[string]*Xp)

// exclc14nxpath is the xpath used for node based exclusive canonicalisation
var exclc14nxpath *C.xmlChar = (*C.xmlChar)(unsafe.Pointer(C.CString("(.//. | .//@* | .//namespace::*)")))

// m map of prefix to uri for namespaces
var m = map[string]string{
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
	"xml":        "http://www.w3.org/XML/1998/namespace",
	"xs":         "http://www.w3.org/2001/XMLSchema",
	"xsi":        "http://www.w3.org/2001/XMLSchema-instance",
	"xsl":        "http://www.w3.org/1999/XSL/Transform",
}

// algos from shorthand to xmlsec and golang defs of digest and signature algorithms
var algos = map[string]algo{
	"sha1":   algo{"http://www.w3.org/2000/09/xmldsig#sha1", "http://www.w3.org/2000/09/xmldsig#rsa-sha1", crypto.SHA1, "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"},
	"sha256": algo{"http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", crypto.SHA256, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"},
}

// init the library
func init() {
	C.xmlInitParser()

	// initialize a global namespace array - it is not obvious who should free the allocated const C strings after
	// being used in C.xmlXPathRegisterNs - if we only have one globally shared we don't care ...

	namespaces = make(map[string]namespaceMap)
	for i, value := range m {
		namespaces[i] = namespaceMap{
			(*C.xmlChar)(unsafe.Pointer(C.CString(i))),
			(*C.xmlChar)(unsafe.Pointer(C.CString(value))),
		}
	}

	// from xmlsec idents to golang defs of digest algorithms
	for _, a := range algos {
		algos[a.digest] = algo{"", "", a.algo, a.derprefix}
		algos[a.signature] = algo{"", "", a.algo, a.derprefix}
	}
}

// Parse SAML xml to Xp object with doc and xpath with relevant namespaces registered
func NewXp(xml []byte) *Xp {
	x := new(Xp)
	if len(xml) == 0 {
		x.doc = C.xmlNewDoc((*C.xmlChar)(unsafe.Pointer(C.CString("1.0"))))
	} else {
		x.doc = C.xmlParseMemory((*C.char)(unsafe.Pointer(&xml[0])), C.int(len(xml)))
	}
	x.xpathCtx = C.xmlXPathNewContext(x.doc)
	runtime.SetFinalizer(x, (*Xp).free)

	for _, ns := range namespaces {
		C.xmlXPathRegisterNs(x.xpathCtx, ns.prefix, ns.ns_uri)
	}
	return x
}

// Make a copy of the Xp object - shares the document with the source, but allocates a new xmlXPathContext because
// they are not thread/gorutine safe as the context is set for each query call
// Only the document "owning" Xp releases the C level document and it needs be around as long as any copies - ie. do
// not let the original document be garbage collected or havoc will be wreaked
func (src *Xp) CpXp() (xp *Xp) {
	xp = new(Xp)
	xp.doc = src.doc
	xp.master = src
	//xp.doc = C.xmlCopyDoc(src.doc, 1)
	xp.xpathCtx = C.xmlXPathNewContext(xp.doc)
	runtime.SetFinalizer(xp, (*Xp).freexpathCtx)

	for _, ns := range namespaces {
		C.xmlXPathRegisterNs(xp.xpathCtx, ns.prefix, ns.ns_uri)
	}
	return
}

// Free the libxml2 allocated objects
func (xp *Xp) free() {
	C.xmlXPathFreeContext(xp.xpathCtx)
	xp.xpathCtx = nil
	C.xmlFreeDoc(xp.doc)
	xp.doc = nil
}

// Free a xmlPathContext, but not the document
func (xp *Xp) freexpathCtx() {
	C.xmlXPathFreeContext(xp.xpathCtx)
	xp.xpathCtx = nil
	xp.doc = nil
	xp.master = nil
}

// NewXpFromNode creates a new *Xp from a node (subtree) from another *Xp
func NewXpFromNode(node *C.xmlNode) *Xp {
	xp := NewXp(nil)
	C.xmlAddChild((*C.xmlNode)(unsafe.Pointer(xp.doc)), C.xmlDocCopyNode(node, xp.doc, 1))
	return xp
}

// Parse html object with doc - used in testing for "forwarding" samlresponses from html to http
// Disables error reporting - libxml2 complains about html5 elements
func NewHtmlXp(html []byte) *Xp {
	x := new(Xp)
	//x.doc = C.htmlParseDoc((*C.xmlChar)(unsafe.Pointer(&html[0])), nil)
	ctxt := C.htmlCreateMemoryParserCtxt((*C.char)(unsafe.Pointer(&html[0])), C.int(len(html)))
	C.htmlCtxtUseOptions(ctxt, C.HTML_PARSE_NOERROR)
	C.htmlParseDocument(ctxt)
	x.doc = ctxt.myDoc
	C.htmlFreeParserCtxt(ctxt)
	x.xpathCtx = C.xmlXPathNewContext(x.doc)
	runtime.SetFinalizer(x, (*Xp).free)
	return x
}

// Free the libxml2 allocated objects
func (xp *HtmlXp) free() {
	C.xmlXPathFreeContext(xp.xpathCtx)
	xp.xpathCtx = nil
	C.xmlFreeDoc(xp.doc)
	xp.doc = nil
}

func (xp *Xp) DocGetRootElement() (res *C.xmlNode) {
    return C.xmlDocGetRootElement(xp.doc)
}

func (parent *C.xmlNode) FirstElementChild() (res *C.xmlNode) {
    res = C.xmlFirstElementChild(parent)
    return
}

func (destination *C.xmlNode) AddChild(source *C.xmlNode) (res *C.xmlNode) {
	res = C.xmlAddChild(destination, source)
	return
}

func (xp *Xp) CopyNode(node *C.xmlNode, extended int) (copy *C.xmlNode) {
	copy = C.xmlDocCopyNode(node, xp.doc, C.int(extended))
	return
}

// NodeSetName sets the name/tag of a node
func (xp *Xp) NodeSetName(node *C.xmlNode, name string) {
	Cname := unsafe.Pointer(C.CString(name))
	C.xmlNodeSetName(C.xmlNodePtr(node), (*C.xmlChar)(Cname))
	C.free(Cname)
}

// NodeSetContent sets the content of a node (or attribute)
func (xp *Xp) NodeSetContent(node *C.xmlNode, content string) {
	Ccontent := unsafe.Pointer(C.CString(content))
	C.xmlNodeSetContent(C.xmlNodePtr(node), (*C.xmlChar)(Ccontent))
	C.free(Ccontent)
}

// NodeGetContent gets the content of a node (or attribute)
func (xp *Xp) NodeGetContent(node *C.xmlNode) (res string) {
	content := C.xmlNodeGetContent(node)
	res = C.GoString((*C.char)(unsafe.Pointer(content)))
	C.free(unsafe.Pointer(content))
	return
}

// UnlinkNode shim around the libxml2 function with the same name
func (xp *Xp) UnlinkNode(node *C.xmlNode) {
	C.xmlUnlinkNode(node)
}

// GetAttr gets the value of the non-namespaced attribute attr
func (node *C.xmlNode) GetAttr(attr string) (res string) {
	Cattr := (*C.xmlChar)(unsafe.Pointer(C.CString(attr)))
	value := (*C.char)(unsafe.Pointer(C.xmlGetProp(node, Cattr)))
	C.free(unsafe.Pointer(Cattr))
	res = C.GoString(value)
	C.free(unsafe.Pointer(value))
	return
}

// SetAttr sets the value of the non-namespaced attribute attr
func (node *C.xmlNode) SetAttr(attr, value string) {
	Cattr := (*C.xmlChar)(unsafe.Pointer(C.CString(attr)))
	Cvalue := (*C.xmlChar)(unsafe.Pointer(C.CString(value)))
	C.xmlSetProp(node, Cattr, Cvalue)
	C.free(unsafe.Pointer(Cattr))
	C.free(unsafe.Pointer(Cvalue))
	return
}

// C14n Canonicalise the node using the SAML specified exclusive method
// Very slow on large documents with node != nil
func (xp *Xp) C14n(node *C.xmlNode) string {
	var buffer *C.xmlChar
	var nodeset *C.xmlNodeSet

	if node != nil {
		C.xmlXPathSetContextNode(node, xp.xpathCtx)
		xpathObj := C.xmlXPathEvalExpression(exclc14nxpath, xp.xpathCtx)
		defer C.xmlXPathFreeObject(xpathObj)
		nodeset = xpathObj.nodesetval
		//fmt.Printf("%+v\n", nodeset)
	}

	C.xmlC14NDocDumpMemory(xp.doc, nodeset, C.XML_C14N_EXCLUSIVE_1_0, nil, 0, &buffer)
	defer C.free(unsafe.Pointer(buffer))
	p := (*C.char)(unsafe.Pointer(buffer))
	return C.GoString(p)
}

// dump the xml - pretty makes it readable ie. withindent
func (xp *Xp) dump(pretty int) string {
	var buffer *C.xmlChar
	var size C.int
	if pretty == 0 {
		C.xmlDocDumpMemory(xp.doc, &buffer, &size)
	} else {
		C.xmlDocDumpFormatMemory(xp.doc, &buffer, &size, C.int(pretty))
	}
	defer C.free(unsafe.Pointer(buffer))
	p := (*C.char)(unsafe.Pointer(buffer))
	return C.GoString(p)
}

// dump the xml from the cur node
func (xp *Xp) Dump2(cur *C.xmlNode) string {
	buf := C.xmlAllocOutputBuffer(nil)
	C.xmlNodeDumpOutput(buf, xp.doc, cur, C.int(4), C.int(0), nil)
	p := C.GoString((*C.char)(unsafe.Pointer(C.xmlOutputBufferGetContent(buf))))
	C.xmlOutputBufferClose(buf)
	return p
}

// Pp Dump the document with indentation - ie pretty print
func (xp *Xp) Pp() string {
	return xp.dump(1)
}

// X2s dumps the document without indentation
func (xp *Xp) X2s() string {
	return xp.dump(0)
}

// Query Do a xpath query with the given context
// returns a slice of nodes
func (xp *Xp) Query(context *C.xmlNode, path string) (nodes []*C.xmlNode) {
	var xmlXPathObject *C.xmlXPathObject
	if xmlXPathObject = xp.xmlXPathEvalExpression(context, path); xmlXPathObject == nil {
		return nil
	}

	defer C.xmlXPathFreeNodeSetList(xmlXPathObject)

	// curtesy of https://github.com/moovweb/gokogiri/blob/master/xpath/xpath.go#L164

	if nodesetPtr := xmlXPathObject.nodesetval; nodesetPtr != nil {
		if nodesetSize := int(nodesetPtr.nodeNr); nodesetSize > 0 {
			nodes = make([]*C.xmlNode, nodesetSize)
			for i := 0; i < nodesetSize; i++ {
				nodes[i] = C.fetchNode(nodesetPtr, C.int(i))
			}
		}
	}
	return
}

// xmlXPathEvalExpression shim around the libxml2 function of the same name
func (xp *Xp) xmlXPathEvalExpression(context *C.xmlNode, path string) (xmlXPathObject *C.xmlXPathObject) {
	if context == nil {
		context = C.xmlDocGetRootElement(xp.doc)
	}
	C.xmlXPathSetContextNode(context, xp.xpathCtx)

	Cpath := unsafe.Pointer(C.CString(path))
	defer C.free(Cpath)
	xmlXPathObject = C.xmlXPathEvalExpression((*C.xmlChar)(Cpath), xp.xpathCtx)
	return
}

// QueryNumber evaluates an xpath expressions that returns a number
func (xp *Xp) QueryNumber(context *C.xmlNode, path string) (val int) {
	var xmlXPathObject *C.xmlXPathObject
	if xmlXPathObject = xp.xmlXPathEvalExpression(context, path); xmlXPathObject == nil {
		return 0
	}
	defer C.xmlXPathFreeNodeSetList(xmlXPathObject)

	if xmlXPathObject._type == C.XPATH_NUMBER {
		val = int(xmlXPathObject.floatval)
	}
	return
}

// QueryNumber evaluates an xpath expressions that returns a bool
func (xp *Xp) QueryBool(context *C.xmlNode, path string) bool {
	return xp.Query1(context, path) == "true" || xp.Query1(context, path) == "1"
}

// Q1 Utility function to get the content of the nodes from a xpath query
// as a slice of strings
func (xp *Xp) QueryMulti(context *C.xmlNode, path string) (res []string) {
	nodes := xp.Query(context, path)

	for _, node := range nodes {
		content := C.xmlNodeGetContent(node)
		res = append(res, C.GoString((*C.char)(unsafe.Pointer(content))))
		C.free(unsafe.Pointer(content))
	}
	return
}

// Q1 Utility function to get the content of the first node from a xpath query
// as a string
func (xp *Xp) Query1(context *C.xmlNode, path string) (res string) {
	nodes := xp.Query(context, path)

	for _, node := range nodes {
		content := C.xmlNodeGetContent(node)
		res = C.GoString((*C.char)(unsafe.Pointer(content)))
		C.free(unsafe.Pointer(content))
		return
	}
	return
}

//  QueryDashP generative xpath query - ie. mkdir -p for xpath ...
//  Understands simple xpath expressions including indexes and attribute values
func (xp *Xp) QueryDashP(context *C.xmlNode, query string, data string, before *C.xmlNode) *C.xmlNode {
	// $query always starts with / ie. is alwayf 'absolute' in relation to the $context
	// split in path elements, an element might include an attribute expression incl. value eg.
	// /md:EntitiesDescriptor/md:EntityDescriptor[@entityID="https://wayf.wayf.dk"]/md:SPSSODescriptor

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
						existingelement := xp.Query(originalcontext, ns+":"+element+"["+strconv.Itoa(i)+"]")
						if len(existingelement) > 0 {
							context = existingelement[0]
						} else {
							context = xp.createElementNS(ns, element, originalcontext, before)
						}
					}
				} else {
					context = xp.createElementNS(ns, element, context, before)
				}
				before = nil
			}
			if attribute != "" {
				Cattribute := unsafe.Pointer(C.CString(attribute))
				Cvalue := unsafe.Pointer(C.CString(value))
				context = (*C.xmlNode)(unsafe.Pointer(C.xmlSetProp(context, (*C.xmlChar)(Cattribute), (*C.xmlChar)(Cvalue))))
				C.free(Cattribute)
				C.free(Cvalue)
			}
		}
	}
	// adding the provided value always at end ..
	if data != "" {
		xp.NodeSetContent(context, html.EscapeString(data))
	}
	return context
}

// CreateElementNS Create an element with the given namespace
func (xp *Xp) createElementNS(prefix, element string, context *C.xmlNode, before *C.xmlNode) (newcontext *C.xmlNode) {

	ns := C.xmlNewNs(nil, namespaces[prefix].ns_uri, namespaces[prefix].prefix) // candidate for cache ...
	if ns == nil {
		panic("ns is nil")
	}
	celement := unsafe.Pointer(C.CString(element))
	newelement := C.xmlNewDocNode(xp.doc, ns, (*C.xmlChar)(celement), nil)
	C.free(celement)

	if before != nil {
		newcontext = C.xmlAddPrevSibling(before, newelement)
	} else {
		if context == nil {
			context = C.xmlDocGetRootElement(xp.doc)
		}
		newcontext = C.xmlAddChild(context, newelement)
	}
	return
}

// Validate - Schemavalidate the document against the the schema file given in url
func (xp *Xp) SchemaValidate(url string) (errs []string, err error) {
	cSchemaNewMemParserCtxt := C.xmlSchemaNewParserCtxt((*C.char)(unsafe.Pointer(C.CString(url))))
	if cSchemaNewMemParserCtxt == nil {
		return nil, errors.New("Could not create schema parser")
	}
	defer C.xmlSchemaFreeParserCtxt(cSchemaNewMemParserCtxt)
	cSchema := C.xmlSchemaParse(cSchemaNewMemParserCtxt)
	if cSchema == nil {
		return nil, errors.New("Could not parse schema")
	}
	defer C.xmlSchemaFree(cSchema)

	validCtxt := C.xmlSchemaNewValidCtxt(cSchema)
	if validCtxt == nil {
		return nil, errors.New("Could not build validator")
	}
	defer C.xmlSchemaFreeValidCtxt(validCtxt)

	// void_libxml_error_handler is a null function - no info collected - just the final result matters - for now
	C.xmlSchemaSetValidErrors(validCtxt, (*[0]byte)(C.void_libxml_error_handler), (*[0]byte)(C.void_libxml_error_handler), nil)

	if errno := C.xmlSchemaValidateDoc(validCtxt, xp.doc); errno != 0 {
		return nil, fmt.Errorf("Document validation error %d", errno)
	}
	return nil, nil
}

// VerifySignature Verify a signature for the given context and public key
func (xp *Xp) VerifySignature(context *C.xmlNode, pub *rsa.PublicKey) error {
	signaturelist := xp.Query(context, "ds:Signature[1]")
	isvalid := len(signaturelist) > 0
	if !isvalid {
		return fmt.Errorf("no signature found")
	}
	signature := signaturelist[0]
	signatureValue := xp.Query1(signature, "ds:SignatureValue")
	signedInfo := xp.Query(signature, "ds:SignedInfo")[0]
	signedInfoC14n := xp.C14n(signedInfo)
	digestValue := xp.Query1(signedInfo, "ds:Reference/ds:DigestValue")
	ID := xp.Query1(context, "@ID")
	URI := xp.Query1(signedInfo, "ds:Reference/@URI")
	isvalid = "#"+ID == URI
	if !isvalid {
		return fmt.Errorf("ID mismatch")
	}

	digestMethod := xp.Query1(signedInfo, "ds:Reference/ds:DigestMethod/@Algorithm")

	C.xmlUnlinkNode(signature)
	contextDigest := Hash(algos[digestMethod].algo, xp.C14n(context))
	contextDigestValueComputed := base64.StdEncoding.EncodeToString(contextDigest)
	isvalid = isvalid && contextDigestValueComputed == digestValue
	if !isvalid {
		return fmt.Errorf("digest mismatch")
	}
	signatureMethod := xp.Query1(signedInfo, "ds:SignatureMethod/@Algorithm")
	signedInfoDigest := Hash(algos[signatureMethod].algo, signedInfoC14n)
	ds, _ := base64.StdEncoding.DecodeString(signatureValue)
	err := rsa.VerifyPKCS1v15(pub, algos[signatureMethod].algo, signedInfoDigest[:], ds)
	if err != nil {
		return err
	}
	return nil
}

// Sign the given context with the given private key - which is a PEM or hsm: key
// A hsm: key is a urn 'key' that points to a specific key/action in a goeleven interface to a HSM
// See https://github.com/wayf-dk/goeleven
func (xp *Xp) Sign(context *C.xmlNode, privatekey, pw, cert, algo string) (err error) {
	contextHash := Hash(algos[algo].algo, xp.C14n(context))
	contextDigest := base64.StdEncoding.EncodeToString(contextHash)
	signaturexml := `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
  <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <ds:SignatureMethod Algorithm=""/>
  <ds:Reference URI="">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    </ds:Transforms>
    <ds:DigestMethod Algorithm=""/>
    <ds:DigestValue></ds:DigestValue>
  </ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue></ds:SignatureValue>
</ds:Signature>`

	signature := C.xmlNewDocFragment(xp.doc)
	var res C.xmlNodePtr
	buf := ([]byte)(signaturexml)
	C.xmlParseBalancedChunkMemory(xp.doc, nil, nil, 0, (*C.xmlChar)(&buf[0]), &res)
	C.xmlAddChildList(signature, res)
	C.xmlAddNextSibling(C.xmlFirstElementChild(context), signature)

	id := xp.Query1(context, "@ID")

	signedInfo := xp.QueryDashP(signature, `ds:Signature/ds:SignedInfo[1]`, "", nil)
	xp.QueryDashP(signedInfo, `ds:SignatureMethod[1]/@Algorithm`, algos[algo].signature, nil)
	xp.QueryDashP(signedInfo, `ds:Reference/@URI`, "#"+id, nil)
	xp.QueryDashP(signedInfo, `ds:Reference/ds:DigestMethod[1]/@Algorithm`, algos[algo].digest, nil)
	xp.QueryDashP(signedInfo, `ds:Reference/ds:DigestValue[1]`, contextDigest, nil)

	signedInfoC14n := xp.C14n(signedInfo)
	digest := Hash(algos[algo].algo, signedInfoC14n)

	var signaturevalue []byte
	if strings.HasPrefix(privatekey, "hsm:") {
		signaturevalue, err = signGoEleven(digest, privatekey, algo)
	} else {
		signaturevalue, err = signGo(digest, privatekey, pw, algo)
	}
	signatureval := base64.StdEncoding.EncodeToString(signaturevalue)
	xp.QueryDashP(signature, `ds:Signature/ds:SignatureValue`, signatureval, nil)
	xp.QueryDashP(signature, `ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate`, cert, nil)
	//	log.Println(xp.Pp())
	return
}

func signGo(digest []byte, privatekey, pw, algo string) (signaturevalue []byte, err error) {
	var priv *rsa.PrivateKey
	block, _ := pem.Decode([]byte(privatekey))
	if pw != "-" {
		privbytes, _ := x509.DecryptPEMBlock(block, []byte(pw))
		priv, err = x509.ParsePKCS1PrivateKey(privbytes)
	} else {
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if err != nil {
	    return
	}
	signaturevalue, err = rsa.SignPKCS1v15(rand.Reader, priv, algos[algo].algo, digest)
	return
}

func signGoEleven(digest []byte, privatekey, algo string) (signaturevalue []byte, err error) {

	type req struct {
		Data      string `json:"data"`
		Mech      string `json:"mech"`
		Sharedkey string `json:"sharedkey"`
	}

	var res struct {
		Slot   string `json:"slot"`
		Mech   string `json:"mech"`
		Signed []byte `json:"signed"`
	}

	parts := strings.SplitN(privatekey, ":", 3)

	payload := req{
		Data:      base64.StdEncoding.EncodeToString(append([]byte(algos[algo].derprefix), digest...)),
		Mech:      "CKM_RSA_PKCS",
		Sharedkey: parts[1],
	}

	jsontxt, err := json.Marshal(payload)

	resp, err := http.Post(parts[2], "application/json", bytes.NewBuffer(jsontxt))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	err = json.Unmarshal(body, &res)

	signaturevalue = res.Signed
	return
}

// Encrypt the context with the given publickey
// Hardcoded to aes256-cbc for the symetric part and
// rsa-oaep-mgf1p and sha1 for the rsa part
func (xp *Xp) Encrypt(context *C.xmlNode, publickey *rsa.PublicKey) {
	template := []byte(`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
    <xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element">
        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc" />
        <ds:KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <xenc:EncryptedKey >
                <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">
                    <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
                </xenc:EncryptionMethod>
                <xenc:CipherData>
                    <xenc:CipherValue>encryptedsessionkey</xenc:CipherValue>
                </xenc:CipherData>
            </xenc:EncryptedKey>
        </ds:KeyInfo>
        <xenc:CipherData>
            <xenc:CipherValue>encryptedassertion</xenc:CipherValue>
        </xenc:CipherData>
    </xenc:EncryptedData>
</saml:EncryptedAssertion>`)

	var res C.xmlNodePtr
	encryptedAssertion := C.xmlNewDocFragment(xp.doc)
	C.xmlParseBalancedChunkMemory(xp.doc, nil, nil, 0, (*C.xmlChar)(&template[0]), &res)
	C.xmlAddChildList(encryptedAssertion, res)

	//sessionkey, ciphertext := encryptAES([]byte(xp.C14n(context)))
	sessionkey, ciphertext := encryptAES([]byte(xp.Dump2(context)))
	sessionkey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, publickey, sessionkey, nil)
	if err != nil {
		panic(err)
	}

	ec := xp.QueryDashP(encryptedAssertion, `saml:EncryptedAssertion/xenc:EncryptedData`, "", nil)
	xp.QueryDashP(ec, `ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue`, base64.StdEncoding.EncodeToString(sessionkey), nil)
	xp.QueryDashP(ec, `xenc:CipherData/xenc:CipherValue`, base64.StdEncoding.EncodeToString(ciphertext), nil)
	C.xmlReplaceNode(context, encryptedAssertion)
}

// Decrypt decrypts the context using the given privatekey
func (xp *Xp) Decrypt(context *C.xmlNode, privatekey *rsa.PrivateKey) (decryptedAssertion *C.xmlNode) {
	// for now just use what we send ourselves ...
	encryptedkey := xp.Query1(context, "./xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue")
	encryptedkeybyte, _ := base64.StdEncoding.DecodeString(encryptedkey)
	sessionkey, _ := rsa.DecryptOAEP(sha1.New(), rand.Reader, privatekey, encryptedkeybyte, nil)
	encryptedassertion := xp.Query1(context, "./xenc:EncryptedData/xenc:CipherData/xenc:CipherValue")
	encryptedassertionbyte, _ := base64.StdEncoding.DecodeString(encryptedassertion)
	assertion := decryptAES([]byte(sessionkey), encryptedassertionbyte)
	assertion = append(assertion, 0)

	var res C.xmlNodePtr
	decryptedAssertion = C.xmlNewDocFragment(xp.doc)
	C.xmlParseBalancedChunkMemory(xp.doc, nil, nil, 0, (*C.xmlChar)(&assertion[0]), &res)
	C.xmlAddChildList(decryptedAssertion, res)
	C.xmlReplaceNode(context, decryptedAssertion)
	C.xmlReconciliateNs(xp.doc, decryptedAssertion)

	return
}

// Pem2PrivateKey converts a PEM encoded private key with an optional password to a *rsa.PrivateKey
func Pem2PrivateKey(privatekeypem, pw string) (privatekey *rsa.PrivateKey) {
	block, _ := pem.Decode([]byte(privatekeypem))
	if pw != "" {
		privbytes, _ := x509.DecryptPEMBlock(block, []byte(pw))
		privatekey, _ = x509.ParsePKCS1PrivateKey(privbytes)
	} else {
		privatekey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	return
}

// encryptAES encrypts the plaintext with a generated random key and returns both the key and the ciphertext
func encryptAES(plaintext []byte) (key, ciphertext []byte) {
	key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	paddinglen := aes.BlockSize - len(plaintext)%aes.BlockSize

	plaintext = append(plaintext, bytes.Repeat([]byte{byte(paddinglen)}, paddinglen)...)
	ciphertext = make([]byte, aes.BlockSize+len(plaintext))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	return
}

// decryptAES decrypts the ciphertext using the supplied key
func decryptAES(key, ciphertext []byte) (plaintext []byte) {
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	paddinglen := int(ciphertext[len(ciphertext)-1])
	if paddinglen > aes.BlockSize || paddinglen == 0 {
		panic("decrypted plaintext is not padded correctly")
	}
	// remove padding
	plaintext = ciphertext[:len(ciphertext)-int(paddinglen)]
	return
}

// PublicKeyInfo extracts the keyname, publickey and cert (base64 DER - no PEM) from the give certificate.
// The keyname is computed from the public key corresponding to running this command: openssl x509 -modulus -noout -in <cert> | openssl sha1.
func PublicKeyInfo(cert string) (keyname string, publickey *rsa.PublicKey, err error) {
	// no pem so no pem.Decode
	key, err := base64.StdEncoding.DecodeString(regexp.MustCompile("\\s").ReplaceAllString(cert, ""))
	pk, err := x509.ParseCertificate(key)
	if err != nil {
		return
	}
	publickey = pk.PublicKey.(*rsa.PublicKey)
	keyname = fmt.Sprintf("%x", sha1.Sum([]byte(fmt.Sprintf("Modulus=%X\n", publickey.N))))
	return
}

/*  NewAuthnRequest - create an AuthnRequest using the supplied metadata for setting the fields according to the following rules:
    - The Destination is the 1st SingleSignOnService with a redirect binding in the idpmetadata
    - The AssertionConsumerServiceURL is Location of the 1st ACS with a post binding in the spmetadata
    - The ProtocolBinding is post
    - The Issuer is the entityID ín the idpmetadata
    - The NameID defaults to transient
*/
func NewAuthnRequest(params IdAndTiming, spmd *Xp, idpmd *Xp) (request *Xp) {
	template := []byte(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    Version="2.0"
                    ID="x"
                    IssueInstant="IssueInstant"
                    Destination="Destination"
                    AssertionConsumerServiceURL="ACSURL"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    >
<saml:Issuer>Issuer</saml:Issuer>
<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true" />
</samlp:AuthnRequest>`)

	issueInstant := params.Now.Format(xsDateTime)
	msgid := params.Id
	if msgid == "" {
		msgid = Id()
	}

	request = NewXp(template)
	request.QueryDashP(nil, "./@ID", msgid, nil)
	request.QueryDashP(nil, "./@IssueInstant", issueInstant, nil)
	request.QueryDashP(nil, "./@Destination", idpmd.Query1(nil, `//md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location`), nil)
	request.QueryDashP(nil, "./@AssertionConsumerServiceURL", spmd.Query1(nil, `//md:AssertionConsumerService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"]/@Location`), nil)
	request.QueryDashP(nil, "./saml:Issuer", spmd.Query1(nil, `/md:EntityDescriptor/@entityID`), nil)
	return
}

// NewResponse - create a new response using the supplied metadata and resp. authnrequest and response for filling out the fields
// The response is primarily for the attributes, but other fields is eg. the AuthnContextClassRef is also drawn from it
func NewResponse(params IdAndTiming, idpmd, spmd, authnrequest, sourceResponse *Xp) (response *Xp) {
	template := []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                ID=""
                Version="2.0"
                IssueInstant=""
                InResponseTo=""
                Destination=""
                >
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </samlp:Status>
    <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                    xmlns:xs="http://www.w3.org/2001/XMLSchema"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID=""
                    Version="2.0"
                    IssueInstant=""
                    >
        <saml:Issuer></saml:Issuer>
        <saml:Subject>
            <saml:NameID SPNameQualifier=""
                         Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
                         ></saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter=""
                                              Recipient=""
                                              InResponseTo=""
                                              />
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore=""
                         NotOnOrAfter=""
                         >
            <saml:AudienceRestriction>
                <saml:Audience></saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant=""
                             SessionNotOnOrAfter=""
                             SessionIndex=""
                             >
            <saml:AuthnContext>
                <saml:AuthnContextClassRef></saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema">
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`)

	response = NewXp(template)

	issueInstant := params.Now.Format(xsDateTime)
	assertionIssueInstant := params.Now.Format(xsDateTime)
	assertionNotOnOrAfter := params.Now.Add(params.Slack).Format(xsDateTime)
	sessionNotOnOrAfter := params.Now.Add(params.Sessionduration).Format(xsDateTime)
	msgid := params.Id
	if msgid == "" {
		msgid = Id()
	}
	assertionID := params.Assertionid
	if assertionID == "" {
		assertionID = Id()
	}

	spEntityID := spmd.Query1(nil, `/md:EntityDescriptor/@entityID`)
	idpEntityID := idpmd.Query1(nil, `/md:EntityDescriptor/@entityID`)

	acs := authnrequest.Query1(nil, "@AssertionConsumerServiceURL")
	response.QueryDashP(nil, "./@ID", msgid, nil)
	response.QueryDashP(nil, "./@IssueInstant", issueInstant, nil)
	response.QueryDashP(nil, "./@InResponseTo", authnrequest.Query1(nil, "@ID"), nil)
	response.QueryDashP(nil, "./@Destination", acs, nil)
	response.QueryDashP(nil, "./saml:Issuer", idpEntityID, nil)

	assertion := response.Query(nil, "saml:Assertion")[0]
	response.QueryDashP(assertion, "@ID", assertionID, nil)
	response.QueryDashP(assertion, "@IssueInstant", assertionIssueInstant, nil)
	response.QueryDashP(assertion, "saml:Issuer", idpEntityID, nil)

	nameid := response.Query(assertion, "saml:Subject/saml:NameID")[0]
	response.QueryDashP(nameid, "@SPNameQualifier", spEntityID, nil)
	response.QueryDashP(nameid, "@Format", sourceResponse.Query1(nil, "//saml:NameID/@Format"), nil)
	response.QueryDashP(nameid, ".", sourceResponse.Query1(nil, "//saml:NameID"), nil)

	subjectconfirmationdata := response.Query(assertion, "saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData")[0]
	response.QueryDashP(subjectconfirmationdata, "@NotOnOrAfter", assertionNotOnOrAfter, nil)
	response.QueryDashP(subjectconfirmationdata, "@Recipient", acs, nil)
	response.QueryDashP(subjectconfirmationdata, "@InResponseTo", authnrequest.Query1(nil, "@ID"), nil)

	conditions := response.Query(assertion, "saml:Conditions")[0]
	response.QueryDashP(conditions, "@NotBefore", assertionIssueInstant, nil)
	response.QueryDashP(conditions, "@NotOnOrAfter", assertionNotOnOrAfter, nil)
	response.QueryDashP(conditions, "saml:AudienceRestriction/saml:Audience", spEntityID, nil)

	authstatement := response.Query(assertion, "saml:AuthnStatement")[0]
	response.QueryDashP(authstatement, "@AuthnInstant", assertionIssueInstant, nil)
	response.QueryDashP(authstatement, "@SessionNotOnOrAfter", sessionNotOnOrAfter, nil)
	response.QueryDashP(authstatement, "@SessionIndex", "missing", nil)
	response.QueryDashP(authstatement, "saml:AuthnContext/saml:AuthnContextClassRef", sourceResponse.Query1(nil, "//saml:AuthnContextClassRef"), nil)

	sourceResponse = NewXp([]byte(sourceResponse.Pp()))
	sourceAttributes := sourceResponse.Query(nil, `//saml:AttributeStatement/saml:Attribute`)
	destinationAttributes := response.Query(nil, `//saml:AttributeStatement`)[0]

	attrcache := map[string]*C.xmlNode{}
	for _, attr := range sourceAttributes {
		attrcache[attr.GetAttr("Name")] = attr
		attrcache[attr.GetAttr("FriendlyName")] = attr
	}

	//requestedAttributes := spmd.Query(nil, `./md:SPSSODescriptor/md:AttributeConsumingService[1]/md:RequestedAttribute[@isRequired=true()]`)
	requestedAttributes := spmd.Query(nil, `./md:SPSSODescriptor/md:AttributeConsumingService[1]/md:RequestedAttribute`)

	for _, requestedAttribute := range requestedAttributes {
		// for _, requestedAttribute := range sourceResponse.Query(nil, `//saml:Attribute`) {
		name := requestedAttribute.GetAttr("Name")
		friendlyname := requestedAttribute.GetAttr("FriendlyName")
		//nameFormat := requestedAttribute.GetAttr("NameFormat")
		//log.Println("requestedattribute:", name, nameFormat)
		// look for a requested attribute with the requested nameformat
		// TO-DO - xpath escape name and nameFormat
		// TO-Do - value filtering
		//attributes := sourceResponse.Query(sourceAttributes[0], `saml:Attribute[@Name="`+name+`" or @Name="`+friendlyname+`" or @FriendlyName="`+friendlyname+`"]`)
		//log.Println("src attrs", len(attributes), `saml:Attribute[@Name="`+name+`" or @Name="`+friendlyname+`" or @FriendlyName="`+friendlyname+`"]`)

		//attributes := sourceResponse.Query(sourceAttributes, `saml:Attribute[@Name="`+name+`"]`)
		attribute := attrcache[name]
		if attribute == nil {
			attribute = attrcache[friendlyname]
			if attribute == nil {
				continue
			}
		}
		//		for _, attribute := range sourceAttributes {
		newAttribute := C.xmlAddChild(destinationAttributes, C.xmlDocCopyNode(attribute, response.doc, 2))
		allowedValues := spmd.Query(requestedAttribute, `saml:AttributeValue`)
		allowedValuesMap := make(map[string]bool)
		for _, value := range allowedValues {
			allowedValuesMap[spmd.NodeGetContent(value)] = true
		}
		for _, valueNode := range sourceResponse.Query(attribute, `saml:AttributeValue`) {
			value := sourceResponse.NodeGetContent(valueNode)
			if len(allowedValues) == 0 || allowedValuesMap[value] {
				C.xmlAddChild(newAttribute, C.xmlDocCopyNode(valueNode, response.doc, 1))
			}
		}
		//		}
	}
	return
}

// Utility functions
func (t IdAndTiming) Refresh() IdAndTiming {
	t.Now = time.Now()
	return t
}

// Make a random id
func Id() (id string) {
	b := make([]byte, 21) // 168 bits - just over the 160 bit recomendation without base64 padding
	rand.Read(b)
	return "_" + hex.EncodeToString(b)
}

// Hash Perform a digest calculation using the given crypto.Hash
func Hash(h crypto.Hash, data string) []byte {
	digest := h.New()
	io.WriteString(digest, data)
	return digest.Sum(nil)
}

// Deflate utility that compresses a string using the flate algo
func Deflate(inflated string) []byte {
	var b bytes.Buffer
	w, _ := flate.NewWriter(&b, -1)
	w.Write([]byte(inflated))
	w.Close()
	return b.Bytes()
}

// Inflate utility that decompresses a string using the flate algo
func Inflate(deflated []byte) []byte {
	var b bytes.Buffer
	r := flate.NewReader(bytes.NewReader(deflated))
	b.ReadFrom(r)
	r.Close()
	return b.Bytes()
}

// Html2SAMLResponse extracts the SAMLResponse from a html document
func Html2SAMLResponse(html []byte) (samlresponse *Xp) {
	response := NewHtmlXp(html)
	samlbase64 := response.Query1(nil, `//input[@name="SAMLResponse"]/@value`)
	samlxml, _ := base64.StdEncoding.DecodeString(samlbase64)
	samlresponse = NewXp(samlxml)
	return
}

// Url2SAMLRequest extracts the SAMLRequest from an URL
func Url2SAMLRequest(url *url.URL, err error) (samlrequest *Xp) {
	query := url.Query()
	req, _ := base64.StdEncoding.DecodeString(query["SAMLRequest"][0])
	samlrequest = NewXp(Inflate(req))
	return
}

// SAMLRequest2Url creates a redirect URL from a saml request
func SAMLRequest2Url(samlrequest *Xp, privatekey, pw, algo string) (url *url.URL, err error) {
	req := base64.StdEncoding.EncodeToString(Deflate(samlrequest.X2s()))

	url, _ = url.Parse(samlrequest.Query1(nil, "@Destination"))
	q := url.Query()
	q.Set("SAMLRequest", req)

	if privatekey != "" {
		digest := Hash(algos[algo].algo, req)

		var signaturevalue []byte
		if strings.HasPrefix(privatekey, "hsm:") {
			signaturevalue, err = signGoEleven(digest, privatekey, algo)
		} else {
			signaturevalue, err = signGo(digest, privatekey, pw, algo)
		}
		signatureval := base64.StdEncoding.EncodeToString(signaturevalue)
		q.Set("SigAlg", algos[algo].signature)
		q.Set("Signature", signatureval)
	}

	url.RawQuery = q.Encode()
	return
}

// CpAndset
func CpAndSet(dest *C.xmlNode, doc, md *Xp, context *C.xmlNode, name, value string) {
	sourceNode := md.Query(context, `md:RequestedAttribute[@FriendlyName="`+name+`"]`)[0]
	d := doc.createElementNS("saml", "Attribute", dest, nil)
	for _, attr := range []string{"Name", "FriendlyName"} {
		d.SetAttr(attr, sourceNode.GetAttr(attr))
	}
	d.SetAttr("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
	doc.QueryDashP(d, `saml:AttributeValue`, value, nil)
}

func (xp *Xp) AttributeCanonicalDump() {
	attrsmap := map[string][]string{}
	keys := []string{}
	attrs := xp.Query(nil, "./saml:Assertion/saml:AttributeStatement/saml:Attribute")
	for _, attr := range attrs {
		values := []string{}
		for _, value := range xp.Query(attr, "saml:AttributeValue") {
			values = append(values, xp.NodeGetContent(value))
		}
		key := strings.TrimSpace(attr.GetAttr("Name") + " " + attr.GetAttr("NameFormat"))
		keys = append(keys, key)
		attrsmap[key] = values
	}

	sort.Strings(keys)
	for _, key := range keys {
		fmt.Println(key)
		values := attrsmap[key]
		sort.Strings(values)
		for _, value := range values {
			if value != "" {
				fmt.Print("    " + value)
			}
			fmt.Println()
		}
	}
}

func GetSAMLMsg(r *http.Request, key string, sendermdsource, memdsource Md, me *Xp) (xp, md, memd *Xp, err error) {
	var decryptedassertion *C.xmlNode
	request := key == "SAMLRequest"
	response := key == "SAMLResponse"
	location := "https://" + r.Host + r.URL.Path
	if request {
		memd, err = memdsource.MDQ(location)
		if err != nil {
			return
		}
	}

	r.ParseForm()
	redirect := r.URL.Query().Get(key) != ""
	post := r.PostForm.Get(key) != ""
	//postsimplesign := r.PostForm.Get("Signature") != ""

	msg := r.Form.Get(key)
	if msg == "" {
		err = fmt.Errorf("no %s found", key)
		return
	}
	xp, err = DecodeSAMLMsg(msg, redirect)
	if err != nil {
		return
	}
	issuer := xp.Query1(nil, "./saml:Issuer")
	if issuer == "" {
		err = fmt.Errorf("no issuer found in %s", key)
		return
	}
	md, err = sendermdsource.MDQ(issuer)
	if err != nil {
		return
	}
	destination := xp.Query1(nil, "./@Destination")
	if destination == "" {
		err = fmt.Errorf("no destination found in %s", key)
		return
	}
	if destination != location {
		err = fmt.Errorf("%s's destination is not here")
		return
	}
	_, err = xp.SchemaValidate(samlSchema)
	if err != nil {
		return
	}
	encryptedAssertions := xp.Query(nil, "./saml:EncryptedAssertion")
	if len(encryptedAssertions) == 1 {
		cert := me.Query1(nil, spCertQuery) // actual encryption key is always first
		var keyname string
		keyname, _, err = PublicKeyInfo(cert)
		if err != nil {
			return
		}
		var privatekey []byte
		privatekey, err = ioutil.ReadFile(certPath + keyname + ".key")
		if err != nil {
			return
		}
		var priv *rsa.PrivateKey
		block, _ := pem.Decode([]byte(privatekey))
		/*
		   if pw != "-" {
		       privbytes, _ := x509.DecryptPEMBlock(block, []byte(pw))
		       priv, _ = x509.ParsePKCS1PrivateKey(privbytes)
		   } else {
		       priv, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
		   }
		*/
		priv, _ = x509.ParsePKCS1PrivateKey(block.Bytes)

		decryptedassertion = xp.Decrypt(encryptedAssertions[0], priv)
		xp = NewXp([]byte(xp.X2s()))
		// repeat schemacheck
		_, err = xp.SchemaValidate(samlSchema)
		if err != nil {
			return
		}
	} else if len(encryptedAssertions) != 0 {
		err = fmt.Errorf("only 1 EncryptedAssertion allowed, %d found", len(encryptedAssertions))
	}

	if redirect {
		if response {
			err = errors.New("no suppport for redirect binding for responses")
			return
		}
	} else if post {
		if response {
			//no ds:Object in signatures
			certificates := md.Query(nil, IdpCertQuery)
			if len(certificates) == 0 {
				err = errors.New("no certificates found in metadata")
				return
			}
			signatures := xp.Query(nil, "(/samlp:Response[ds:Signature] | /samlp:Response/saml:Assertion[ds:Signature])")
			if decryptedassertion != nil {
				//signatures = append(signatures, decryptedassertion)
			}
			if len(signatures) == 0 {
				err = errors.New("Neither the assertion nor the response was signed.")
				return
			}
			verified := 0
			signerrors := []error{}
			for _, certificate := range certificates {
				var key *rsa.PublicKey
				_, key, err = PublicKeyInfo(md.NodeGetContent(certificate))

				if err != nil {
					return
				}

				for _, signature := range signatures {
					signerror := xp.VerifySignature(signature, key)
					if signerror != nil {
						signerrors = append(signerrors, signerror)
					} else {
						verified++
					}
				}
			}
			if verified == 0 || verified != len(signatures) {
				errorstring := ""
				delim := ""
				for _, e := range signerrors {
					errorstring += e.Error() + delim
					delim = ", "
				}
				err = fmt.Errorf("unable to validate signature: %s", errorstring)
				return
			}
		}
	} else {
		err = errors.New("could not find a supported binding")
	}
	if request {
		acs := xp.Query1(nil, "@AssertionConsumerServiceURL")
		validacs := len(md.Query(nil, "./md:SPSSODescriptor/md:AssertionConsumerService[@Location='"+acs+"']")) == 1
		if acs == "" || !validacs {
			//err = fmt.Errorf("AssertionConsumerServiceURL missing or not present in metadata: '%s'", acs)
			//return
		}
		subject := xp.Query1(nil, "@Subject")
		if subject != "" {
			err = fmt.Errorf("subject not allowed in %ss", key)
			return
		}
		nameidpolicy := xp.Query1(nil, "./samlp:NameIDPolicy/@Format")
		if nameidpolicy != "" && nameidpolicy != transient && nameidpolicy != persistent {
			err = fmt.Errorf("nameidpolicy format: %s is not supported")
			return
		}
		allowcreate := xp.Query1(nil, "./samlp:NameIDPolicy/@AllowCreate")
		if allowcreate != "true" {
			err = fmt.Errorf("only supported value for NameIDPolicy @AllowCreate is true, got: %s", allowcreate)
			return
		}
	}
	if response {
		// one minute skew allowed
		now := time.Now().Add(time.Duration(1) * time.Minute).UTC().Format("2006-01-02T15:04:05Z")
		checks := map[string]bool{
			// "/samlp:Response[1]/saml:Assertion[1]/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotBefore": true ,
			"/samlp:Response[1]/saml:Assertion[1]/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter": false,
			"/samlp:Response[1]/saml:Assertion[1]/saml:Conditions/@NotBefore":                                                       true,
			"/samlp:Response[1]/saml:Assertion[1]/saml:Conditions/@NotOnOrAfter":                                                    false,
			"/samlp:Response[1]/saml:Assertion[1]/saml:AuthnStatement/@SessionNotOnOrAfter":                                         false,
		}
		for q, i := range checks {
			samltime := xp.Query1(nil, q)
			cmp := samltime < now
			if samltime == "" || cmp != i {
				err = fmt.Errorf("timing problem: %s = '%s', now = %s", q, samltime, now)
				return
			}
		}
	}
	return
}

func DecodeSAMLMsg(msg string, deflate bool) (xp *Xp, err error) {
	bmsg, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return
	}
	if deflate {
		bmsg = Inflate(bmsg)
	}
	xp = NewXp(bmsg)
	return
}

func SignResponse(response *Xp, elementQuery string, md *Xp) (err error) {
	cert := md.Query1(nil, IdpCertQuery) // actual signing key is always first
	var keyname string
	keyname, _, err = PublicKeyInfo(cert)
	if err != nil {
		return
	}
	var privatekey []byte
	privatekey, err = ioutil.ReadFile(certPath + keyname + ".key")
	if err != nil {
		return
	}

	element := response.Query(nil, elementQuery)
	if len(element) != 1 {
		err = errors.New("did not find exactly one element to sign")
		return
	}
	err = response.Sign(element[0], string(privatekey), "-", cert, "sha1")
	return
}
