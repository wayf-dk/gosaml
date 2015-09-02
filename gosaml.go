// Package gosaml is a library for doing SAML stuff in Go.
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
#include <libxml2/libxml/xmlsave.h>
#include <libxml2/libxml/c14n.h>
#include <libxml2/libxml/xpath.h>
#include <libxml2/libxml/xpathInternals.h>
#include <libxml2/libxml/xmlmemory.h>
xmlNode* fetchNode(xmlNodeSet *nodeset, int index) {
    return nodeset->nodeTab[index];
}
*/
import "C"

import (
    "bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"io/ioutil"
//	"log"
	"regexp"
	"runtime"
	"strconv"
	"unsafe"
)

// Xp is a wrapper for the libxml2 xmlDoc and xmlXpathContext
type Xp struct {
	doc      *C.xmlDoc
	xpathCtx *C.xmlXPathContext
}

// NamespaceMap is namespace struct (in *C.char format) from ns prefix to urn/url
type namespaceMap struct {
	prefix *C.xmlChar
	ns_uri *C.xmlChar
}

// namespaces maps between a ns prefix and the urn/url
var namespaces map[string]namespaceMap

// exclc14nxpath is the xpath used for node based exclusive canonicalisation
var exclc14nxpath *C.xmlChar = (*C.xmlChar)(unsafe.Pointer(C.CString("(.//. | .//@* | .//namespace::*)")))

// m map of prefix to uri for namespaces
var m = map[string]string{
	"samlp":      "urn:oasis:names:tc:SAML:2.0:protocol",
	"saml":       "urn:oasis:names:tc:SAML:2.0:assertion",
	"shibmd":     "urn:mace:shibboleth:metadata:1.0",
	"md":         "urn:oasis:names:tc:SAML:2.0:metadata",
	"mdrpi":      "urn:oasis:names:tc:SAML:metadata:rpi",
	"mdui":       "urn:oasis:names:tc:SAML:metadata:ui",
	"mdattr":     "urn:oasis:names:tc:SAML:metadata:attribute",
	"idpdisc":    "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol",
	"init":       "urn:oasis:names:tc:SAML:profiles:SSO:request-init",
	"xsi":        "http://www.w3.org/2001/XMLSchema-instance",
	"xs":         "http://www.w3.org/2001/XMLSchema",
	"xsl":        "http://www.w3.org/1999/XSL/Transform",
	"xml":        "http://www.w3.org/XML/1998/namespace",
	"SOAP-ENV":   "http://schemas.xmlsoap.org/soap/envelope/",
	"ds":         "http://www.w3.org/2000/09/xmldsig#",
	"xenc":       "http://www.w3.org/2001/04/xmlenc#",
	"algsupport": "urn:oasis:names:tc:SAML:metadata:algsupport",
	"ukfedlabel": "http://ukfederation.org.uk/2006/11/label",
	"sdss":       "http://sdss.ac.uk/2006/06/WAYF",
	"wayf":       "http://wayf.dk/2014/08/wayf",
	"corto":      "http://corto.wayf.dk",
}

// algo xmlsec digest and signature algorith and their Go name
type algo struct {
	digest    string
	signature string
	algo      crypto.Hash
}

// algos from shorthand to xmlsec and golang defs of digest and signature algorithms
var algos = map[string]algo{
	"sha1":   algo{"http://www.w3.org/2000/09/xmldsig#sha1", "http://www.w3.org/2000/09/xmldsig#rsa-sha1", crypto.SHA1},
	"sha256": algo{"http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", crypto.SHA256},
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
		algos[a.digest] = algo{"", "", a.algo}
		algos[a.signature] = algo{"", "", a.algo}
	}
}

// GetMetaData - read a single entity xml metadata from a file
func GetMetaData(path string) *Xp {
	md, err := ioutil.ReadFile(path)
	if err != nil {
		return nil //, errors.New("no md available")
	}
	return New(md)
}

// Parse SAML xml to Xp object with doc and xpath with relevant namespaces registered
func New(xml []byte) *Xp {
	x := new(Xp)
	x.doc = C.xmlParseMemory((*C.char)(unsafe.Pointer(&xml[0])), C.int(len(xml)))
	x.xpathCtx = C.xmlXPathNewContext(x.doc)
	runtime.SetFinalizer(x, (*Xp).free)

	for _, ns := range namespaces {
		C.xmlXPathRegisterNs(x.xpathCtx, ns.prefix, ns.ns_uri)
	}
	return x
}

// Free the libxml2 allocated objects
func (xp *Xp) free() {
	C.xmlXPathFreeContext(xp.xpathCtx)
	xp.xpathCtx = nil
	C.xmlFreeDoc(xp.doc)
	xp.doc = nil
}

// C14n Canonicalise the node using the SAML specified exclusive method
// Very slow on large documents with node != nil
func (xp *Xp) c14n(node *C.xmlNode) string {
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

// Pp Dump the document with indentation - ie pretty print
func (xp *Xp) Pp() string {
	var buffer *C.xmlChar
	var size C.int
	C.xmlDocDumpFormatMemory(xp.doc, &buffer, &size, 1)
	defer C.free(unsafe.Pointer(buffer))
	p := (*C.char)(unsafe.Pointer(buffer))
	return C.GoString(p)
}

// Query Do a xpath query with the given context
// returns a slice of nodes
func (xp *Xp) Query(path string, context *C.xmlNode) (nodes []*C.xmlNode) {
	if context == nil {
		context = C.xmlDocGetRootElement(xp.doc)
	}
	C.xmlXPathSetContextNode(context, xp.xpathCtx)

    Cpath := unsafe.Pointer(C.CString(path))
	defer C.free(Cpath)
	xpathObj := C.xmlXPathEvalExpression((*C.xmlChar)(Cpath), xp.xpathCtx)

	if xpathObj == nil {
		return
	}
	defer C.xmlXPathFreeNodeSetList(xpathObj)

	// curtesy https://github.com/moovweb/gokogiri/blob/master/xpath/xpath.go#L164

	if nodesetPtr := xpathObj.nodesetval; nodesetPtr != nil {
		if nodesetSize := int(nodesetPtr.nodeNr); nodesetSize > 0 {
			nodes = make([]*C.xmlNode, nodesetSize)
			for i := 0; i < nodesetSize; i++ {
				nodes[i] = C.fetchNode(nodesetPtr, C.int(i))
			}
		}
	}
	return
}

// Q1 Utility function to get the content of the first node from an xpath query
// as a string
func (xp *Xp) Q1(path string, context *C.xmlNode) (res string) {
	nodes := xp.Query(path, context)
	if len(nodes) > 0 {
		content := C.xmlNodeGetContent(nodes[0])
		res = C.GoString((*C.char)(unsafe.Pointer(content)))
		C.free(unsafe.Pointer(content))
	}
	return
}

// nodeSetContent  Set the content of a node (or attribute)
func (xp *Xp) nodeSetContent(node *C.xmlNode, content string) {
	Ccontent := unsafe.Pointer(C.CString(content))
	C.xmlNodeSetContent(C.xmlNodePtr(node), (*C.xmlChar)(Ccontent))
	C.free(Ccontent)
}

// GetAttr gets the value of the non-namespaced attribute attr
func GetAttr(node *C.xmlNode, attr string) (res string) {
	Cattr := (*C.xmlChar)(unsafe.Pointer(C.CString(attr)))
	value := (*C.char)(unsafe.Pointer(C.xmlGetProp(node, Cattr)))
	C.free(unsafe.Pointer(Cattr))
	res = C.GoString(value)
	C.free(unsafe.Pointer(value))
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
    	buffer.WriteString("/")
    	buffer.WriteString(path[0][1])
	    path[0][1] = buffer.String()
	}

	for _, elements := range path {
		element := elements[1]
		nodes := xp.Query(element, context)
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
						existingelement := xp.Query(ns+":"+element+"["+strconv.Itoa(i)+"]", originalcontext)
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
		xp.nodeSetContent(context, html.EscapeString(data))
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

// Hash Perform a digest calculation using the given crypto.Hash
func hash(h crypto.Hash, data string) []byte {
	digest := h.New()
	io.WriteString(digest, data)
	return digest.Sum(nil)
}

// VerifySignature Verify a signature for the given context and public key
func (xp *Xp) VerifySignature(context *C.xmlNode, pub *rsa.PublicKey) (isvalid bool) {
	signature := xp.Query("ds:Signature[1]", context)[0]
	signatureValue := xp.Q1("ds:SignatureValue", signature)
	signedInfo := xp.Query("ds:SignedInfo", signature)[0]
	signedInfoC14n := xp.c14n(signedInfo)
	digestValue := xp.Q1("ds:Reference/ds:DigestValue", signedInfo)
	ID := xp.Q1("@ID", context)
	URI := xp.Q1("ds:Reference/@URI", signedInfo)
	isvalid = "#"+ID == URI

	digestMethod := xp.Q1("ds:Reference/ds:DigestMethod/@Algorithm", signedInfo)

	C.xmlUnlinkNode(signature)
	contextDigest := hash(algos[digestMethod].algo, xp.c14n(context))
	contextDigestValueComputed := base64.StdEncoding.EncodeToString(contextDigest)
	isvalid = isvalid && contextDigestValueComputed == digestValue

	signatureMethod := xp.Q1("ds:SignatureMethod/@Algorithm", signedInfo)
	signedInfoDigest := hash(algos[signatureMethod].algo, signedInfoC14n)
	ds, _ := base64.StdEncoding.DecodeString(signatureValue)
	err := rsa.VerifyPKCS1v15(pub, algos[signatureMethod].algo, signedInfoDigest[:], ds)
	isvalid = isvalid && err == nil
	return
}

// Sign the given context with the given private key
func (xp *Xp) Sign(context *C.xmlNode, priv *rsa.PrivateKey, algo string) (isvalid bool, err error) {
	contextHash := hash(algos[algo].algo, xp.c14n(context))
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

	id := xp.Q1("@ID", context)

	signedInfo := xp.QueryDashP(signature, `ds:Signature/ds:SignedInfo[1]`, "", nil)
	xp.QueryDashP(signedInfo, `ds:SignatureMethod[1]/@Algorithm`, algos[algo].signature, nil)
	xp.QueryDashP(signedInfo, `ds:Reference/@URI`, "#"+id, nil)
	xp.QueryDashP(signedInfo, `ds:Reference/ds:DigestMethod[1]/@Algorithm`, algos[algo].digest, nil)
	xp.QueryDashP(signedInfo, `ds:Reference/ds:DigestValue[1]`, contextDigest, nil)

	signedInfoC14n := xp.c14n(signedInfo)

	d := hash(algos[algo].algo, signedInfoC14n)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, algos[algo].algo, d)

	sigvalue := base64.StdEncoding.EncodeToString(sig)
	xp.QueryDashP(signature, `ds:Signature/ds:SignatureValue`, sigvalue, nil)
	return
}

// PublicKeysFromMD extract the public keys from certs - typically some ds:X509Certificate elements
func PublicKeysFromMD(certs []*C.xmlNode) (pub []*rsa.PublicKey) {
	re := regexp.MustCompile("\\s")
	pub = make([]*rsa.PublicKey, 0)
	for _, cert := range certs {
		content := C.xmlNodeGetContent(cert)
		res := C.GoString((*C.char)(unsafe.Pointer(content)))
		C.free(unsafe.Pointer(content))
		base64Data := re.ReplaceAllString(res, "")
		bytes := make([]byte, base64.StdEncoding.DecodedLen(len(base64Data)))
		n, err := base64.StdEncoding.Decode(bytes, []byte(base64Data))
		key := bytes[:n]
		re, err := x509.ParseCertificate(key)
		if err != nil {
			fmt.Println(err)
			return
		}
		pub = append(pub, re.PublicKey.(*rsa.PublicKey))
	}
	return
}
