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
	"crypto/tls"
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
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

const (
	xsDateTime = "2006-01-02T15:04:05Z"
)

// Xp is a wrapper for the libxml2 xmlDoc and xmlXpathContext
type Xp struct {
	doc      *C.xmlDoc
	xpathCtx *C.xmlXPathContext
	context  *C.xmlNode
}

type HtmlXp struct {
	doc      *C.xmlDoc
	xpathCtx *C.xmlXPathContext
}

// IdAndTiming is a type that allows to client to pass the ids and timing used when making
// new requests and responses - also use for fixed ids and timings when testing
type IdAndTiming struct {
	now                    time.Time
	slack, sessionduration time.Duration
	id, assertionid        string
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

// algo xmlsec digest and signature algorith and their Go name
type algo struct {
	digest    string
	signature string
	algo      crypto.Hash
	derprefix string
}

// algos from shorthand to xmlsec and golang defs of digest and signature algorithms
var algos = map[string]algo{
	"sha1":   algo{"http://www.w3.org/2000/09/xmldsig#sha1", "http://www.w3.org/2000/09/xmldsig#rsa-sha1", crypto.SHA1, "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14" },
	"sha256": algo{"http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", crypto.SHA256, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20" },
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
	x.doc = C.xmlParseMemory((*C.char)(unsafe.Pointer(&xml[0])), C.int(len(xml)))
	x.xpathCtx = C.xmlXPathNewContext(x.doc)
	runtime.SetFinalizer(x, (*Xp).free)

	for _, ns := range namespaces {
		C.xmlXPathRegisterNs(x.xpathCtx, ns.prefix, ns.ns_uri)
	}
	return x
}

// Make a copy of the Xp object - shares the document with the source, but allocates a new xmlXPathContext because
// they are not thread/gorutine safe as the context is set for each query call
// Only the document "owning" Xp releases the C level document
func (src *Xp) CpXp() *Xp {
	x := new(Xp)
	x.doc = src.doc
	x.xpathCtx = C.xmlXPathNewContext(x.doc)
	runtime.SetFinalizer(x, (*Xp).freexpathCtx)

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

// Free a xmlPathContext, but not the document
func (xp *Xp) freexpathCtx() {
	C.xmlXPathFreeContext(xp.xpathCtx)
	xp.xpathCtx = nil
	xp.doc = nil
}

/* Parse html object with doc - used in testing for "forwarding" samlresponses from html to http
   Disables error reporting - libxml2 complains about html5 elements
*/
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

// NewMetaData - read a single entity xml metadata from an MDQ server
// key is either en entityID or an endpoint - allows lookup entity by endpoints
// Currently only supported by the phph.wayf.dk/MDQ
func NewMD(mdq, feed, key string) *Xp {
	sha1key := hex.EncodeToString(hash(crypto.SHA1, key))
	url, _ := url.Parse(mdq + feed + "/entities/{sha1}" + sha1key)

	tr := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		Dial:               func(network, addr string) (net.Conn, error) { return net.Dial("tcp", addr) },
		DisableCompression: true,
	}
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return errors.New("redirect not supported") },
	}

	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	if resp.StatusCode != 200 {
		log.Fatalf("looking for: '%s' using: '%s' MDQ said: %s\n", key, url.String(), resp.Status)
	}
	md, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	return NewXp(md)
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
func (xp *Xp) Query(context *C.xmlNode, path string) (nodes []*C.xmlNode) {
	if context == nil {
		context = xp.context
	}
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

// nodeSetContent  Set the content of a node (or attribute)
func (xp *Xp) nodeSetContent(node *C.xmlNode, content string) {
	Ccontent := unsafe.Pointer(C.CString(content))
	C.xmlNodeSetContent(C.xmlNodePtr(node), (*C.xmlChar)(Ccontent))
	C.free(Ccontent)
}

// nodeGetContent  Set the content of a node (or attribute)
func (xp *Xp) nodeGetContent(node *C.xmlNode) (res string) {
	content := C.xmlNodeGetContent(node)
	res = C.GoString((*C.char)(unsafe.Pointer(content)))
	C.free(unsafe.Pointer(content))
	return
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

func id() (id string) {
	b := make([]byte, 21) // 168 bits - just over the 160 bit recomendation without base64 padding
	rand.Read(b)
	return "_" + hex.EncodeToString(b)
}

// VerifySignature Verify a signature for the given context and public key
func (xp *Xp) VerifySignature(context *C.xmlNode, pub *rsa.PublicKey) (isvalid bool) {
	signature := xp.Query(context, "ds:Signature[1]")[0]
	signatureValue := xp.Query1(signature, "ds:SignatureValue")
	signedInfo := xp.Query(signature, "ds:SignedInfo")[0]
	signedInfoC14n := xp.c14n(signedInfo)
	digestValue := xp.Query1(signedInfo, "ds:Reference/ds:DigestValue")
	ID := xp.Query1(context, "@ID")
	URI := xp.Query1(signedInfo, "ds:Reference/@URI")
	isvalid = "#"+ID == URI

	digestMethod := xp.Query1(signedInfo, "ds:Reference/ds:DigestMethod/@Algorithm")

	C.xmlUnlinkNode(signature)
	contextDigest := hash(algos[digestMethod].algo, xp.c14n(context))
	contextDigestValueComputed := base64.StdEncoding.EncodeToString(contextDigest)
	isvalid = isvalid && contextDigestValueComputed == digestValue

	signatureMethod := xp.Query1(signedInfo, "ds:SignatureMethod/@Algorithm")
	signedInfoDigest := hash(algos[signatureMethod].algo, signedInfoC14n)
	ds, _ := base64.StdEncoding.DecodeString(signatureValue)
	err := rsa.VerifyPKCS1v15(pub, algos[signatureMethod].algo, signedInfoDigest[:], ds)
	isvalid = isvalid && err == nil
	return
}

// Sign the given context with the given private key
func (xp *Xp) Sign(context *C.xmlNode, privatekey, pw, algo string) (derr error) {
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

	id := xp.Query1(context, "@ID")

	signedInfo := xp.QueryDashP(signature, `ds:Signature/ds:SignedInfo[1]`, "", nil)
	xp.QueryDashP(signedInfo, `ds:SignatureMethod[1]/@Algorithm`, algos[algo].signature, nil)
	xp.QueryDashP(signedInfo, `ds:Reference/@URI`, "#"+id, nil)
	xp.QueryDashP(signedInfo, `ds:Reference/ds:DigestMethod[1]/@Algorithm`, algos[algo].digest, nil)
	xp.QueryDashP(signedInfo, `ds:Reference/ds:DigestValue[1]`, contextDigest, nil)

	signedInfoC14n := xp.c14n(signedInfo)
	digest := hash(algos[algo].algo, signedInfoC14n)

    var signaturevalue []byte
	if strings.HasPrefix(privatekey, "hsm:") {
	    signaturevalue, _ = signGoEleven(digest, privatekey, algo)
	} else {
	    signaturevalue, _ = signGo(digest, privatekey, pw, algo)
	}
    signatureval := base64.StdEncoding.EncodeToString(signaturevalue)
    xp.QueryDashP(signature, `ds:Signature/ds:SignatureValue`, signatureval, nil)
	return
}

func signGo(digest []byte, privatekey, pw, algo string ) (signaturevalue []byte, err error) {
	var priv *rsa.PrivateKey
	block, _ := pem.Decode([]byte(privatekey))
	if pw != "" {
	    privbytes, _ := x509.DecryptPEMBlock(block, []byte(pw))
	    priv, _ = x509.ParsePKCS1PrivateKey(privbytes)
	} else {
		priv, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
    }
	signaturevalue, _ = rsa.SignPKCS1v15(rand.Reader, priv, algos[algo].algo, digest)
	return
}

func signGoEleven(digest []byte, privatekey, algo string ) (signaturevalue []byte, err error) {

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
	    Data: base64.StdEncoding.EncodeToString(append([]byte(algos[algo].derprefix), digest ...)),
	    Mech: "CKM_RSA_PKCS",
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

	issueInstant := params.now.Format(xsDateTime)
	msgid := params.id
	if msgid == "" {
		msgid = id()
	}

	request = NewXp(template)
	request.QueryDashP(nil, "./@ID", msgid, nil)
	request.QueryDashP(nil, "./@IssueInstant", issueInstant, nil)
	request.QueryDashP(nil, "./@Destination", idpmd.Query1(nil, `//md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location`), nil)
	request.QueryDashP(nil, "./@AssertionConsumerServiceURL", spmd.Query1(nil, `//md:AssertionConsumerService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"]/@Location`), nil)
	request.QueryDashP(nil, "./saml:Issuer", spmd.Query1(nil, `/md:EntityDescriptor/@entityID`), nil)
	return
}

/*  NewResponse - create a new response using the supplied metadata and resp. authnrequest and response for filling out the fields
    The response is primarily for the attributes, but other fields is eg. the AuthnContextClassRef is also drawn from it
*/
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
            <saml:NameID SPNameQualifier="https://birk.wayf.dk/birk.php/metadata.wayf.dk/PHPh-proxy"
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
        <saml:AttributeStatement>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`)

	response = NewXp(template)

	issueInstant := params.now.Format(xsDateTime)
	assertionIssueInstant := params.now.Format(xsDateTime)
	assertionNotOnOrAfter := params.now.Add(params.slack).Format(xsDateTime)
	sessionNotOnOrAfter := params.now.Add(params.sessionduration).Format(xsDateTime)
	msgid := params.id
	if msgid == "" {
		msgid = id()
	}
	assertionID := params.assertionid
	if assertionID == "" {
		assertionID = id()
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
	response.QueryDashP(nameid, "@Format", "NameID@Format", nil)
	response.QueryDashP(nameid, ".", "Subject", nil)

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
	response.QueryDashP(authstatement, "saml:AuthnContext/saml:AuthnContextClassRef", "missing", nil)

	requestedAttributes := spmd.Query(nil, `//md:RequestedAttribute[@isRequired="true"]`)
	sourceAttributes := sourceResponse.Query(nil, `//saml:AttributeStatement`)[0]
	destinationAttributes := response.Query(nil, `//saml:AttributeStatement`)[0]

	for _, requestedAttribute := range requestedAttributes {
		name := GetAttr(requestedAttribute, "Name")
		nameFormat := GetAttr(requestedAttribute, "NameFormat")
		// look for a requested attribute with the requested nameformat
		// TO-DO - xpath escape name and nameFormat
		// TO-Do - value filtering
		attributes := sourceResponse.Query(sourceAttributes, `saml:Attribute[@Name="`+name+`" and @NameFormat="`+nameFormat+`"]`)
		for _, attribute := range attributes {
			newAttribute := C.xmlAddChild(destinationAttributes, C.xmlDocCopyNode(attribute, response.doc, 2))
			allowedValues := spmd.Query(requestedAttribute, `saml:AttributeValue`)
			allowedValuesMap := make(map[string]bool)
			for _, value := range allowedValues {
				allowedValuesMap[spmd.nodeGetContent(value)] = true
			}
			for _, valueNode := range sourceResponse.Query(attribute, `saml:AttributeValue`) {
				value := sourceResponse.nodeGetContent(valueNode)
				if len(allowedValues) == 0 || allowedValuesMap[value] {
					C.xmlAddChild(newAttribute, C.xmlDocCopyNode(valueNode, response.doc, 1))
				}
			}
		}
	}
	return
}

