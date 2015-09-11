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
	return NewXp(md)
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
    return "_" + base64.StdEncoding.EncodeToString(b)
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

	id := xp.Query1(context, "@ID")

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

/*  NewAuthnRequest - create an AuthnRequest using the supplied metadata for setting the fields according to the following rules:
    - The Destination is the 1st SingleSignOnService with a redirect binding in the idpmetadata
    - The AssertionConsumerServiceURL is Location of the 1st ACS with a post binding in the spmetadata
    - The ProtocolBinding is post
    - The Issuer is the entityID ín the idpmetadata
    - The NameID defaults to transient
*/
func NewAuthnRequest(spmd *Xp, idpmd *Xp) (request *Xp) {
	template := []byte(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    Version="2.0"
                    ID="x"
                    IssueInstant="x"
                    Destination="x"
                    AssertionConsumerServiceURL="x"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    >
<saml:Issuer>x</saml:Issuer>
<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true" />
</samlp:AuthnRequest>`)

	request = NewXp(template)
	request.QueryDashP(nil, "./@ID", id(), nil)
	request.QueryDashP(nil, "./@IssueInstant", time.Now().Format(xsDateTime), nil)
	request.QueryDashP(nil, "./@Destination", idpmd.Query1(nil, `md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location`), nil)
	request.QueryDashP(nil, "./@AssertionConsumerURL", spmd.Query1(nil, `md:AssertionConsumerService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"]/@Location`), nil)
	request.QueryDashP(nil, "./saml:Issuer", spmd.Query1(nil, `/md:EntitiesDescriptor/md:EntityDescriptor/@entityID`), nil)
	return
}

/*  NewResponse - create a new response using the supplied metadata and resp. authnrequest and response for filling out the fields
    The response is primarily for the attributes, but other fields is eg. the AuthnContextClassRef is also drawn from it
*/
func NewResponse(idpmd, spmd, authnrequest, sourceResponse *Xp) (response *Xp) {
	template := []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                ID=""
                Version="2.0"
                IssueInstant=""
                InResponseTo=""
                Destination="https://phph.wayf.dk"
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
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:Signature>
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
	ID := id()
	now := time.Now().Format(xsDateTime)
    notOnOrAfter := time.Now().Add(5 * time.Minute).Format(xsDateTime)
    sessionNotOnOrAfter := time.Now().Add(5 * time.Hour).Format(xsDateTime)

    spEntityID :=spmd.Query1(nil, `/md:EntitiesDescriptor/md:EntityDescriptor/@entityID`)
    idpEntityID := idpmd.Query1(nil, `/md:EntitiesDescriptor/md:EntityDescriptor/@entityID`)

	response.QueryDashP(nil, "./@ID", ID, nil)
	response.QueryDashP(nil, "./@IssueInstant", now, nil)
	response.QueryDashP(nil, "./@InResponseTo", authnrequest.Query1(nil, "@ID"), nil)
	response.QueryDashP(nil, "./@Destination", authnrequest.Query1(nil, "@AssertionConsumerURL"), nil)
	response.QueryDashP(nil, "./saml:Issuer", idpEntityID, nil)

    assertion := response.Query(nil, "saml:Assertion")[0]
	response.QueryDashP(assertion, "@ID", id(), nil)
	response.QueryDashP(assertion, "@IssueInstant", now, nil)
	response.QueryDashP(assertion, "saml:Issuer", idpEntityID, nil)

    nameid := response.Query(assertion, "saml:Subject/saml:NameID")[0]
	response.QueryDashP(nameid, "@SPNameQualifier", spEntityID, nil)
	response.QueryDashP(nameid, "@Format", "NameID@Format", nil)
	response.QueryDashP(nameid, ".", "Subject", nil)

    subjectconfirmationdata := response.Query(assertion, "saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData")[0]
	response.QueryDashP(subjectconfirmationdata, "@NotOnOrAfter", now, nil)
	response.QueryDashP(subjectconfirmationdata, "@Recipient", spEntityID, nil)
	response.QueryDashP(subjectconfirmationdata, "@InResponseTo", authnrequest.Query1(nil, "@ID"), nil)

    conditions := response.Query(assertion, "saml:Conditions")[0]
	response.QueryDashP(conditions, "@NotBefore", now, nil)
	response.QueryDashP(conditions, "@NotOnOrAfter", notOnOrAfter, nil)
	response.QueryDashP(conditions, "saml:AudienceRestriction/saml:Audience", spEntityID, nil)

    authstatement := response.Query(assertion, "saml:AuthnStatement")[0]
	response.QueryDashP(authstatement, "@AuthnInstant", now, nil)
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
	    attributes := sourceResponse.Query(sourceAttributes, `saml:Attribute[@Name="` + name + `" and @NameFormat="` + nameFormat + `"]`)
	    for _, attribute := range attributes {
            newAttribute := C.xmlAddChild(destinationAttributes, C.xmlDocCopyNode(attribute, response.doc, 2))
            allowedValues := spmd.Query(requestedAttribute, `saml:AttributeValue`)
            allowedValuesMap := make(map[string]bool)
            for _, value :=  range allowedValues {
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

