package gosaml

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/goxml"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type Testparams struct {
	spmd, idpmd, hubmd, testidpmd *goxml.Xp
	cookiejar                     map[string]map[string]*http.Cookie
	idpentityID                   string
	usescope                      bool
	usedoubleproxy                bool
	resolv                        map[string]string
	initialrequest                *goxml.Xp
	newresponse                   *goxml.Xp
	resp                          *http.Response
	responsebody                  []byte
	err                           error
	logredirects                  bool
}

type (
	simplemd struct {
		entities map[string]*goxml.Xp
	}

	metadata struct {
		Hub, Internal, External string
	}
)

var (
	_  = log.Printf // For debugging; delete when done.
	wg sync.WaitGroup

	mdq                                                                                                    = "https://phph.wayf.dk/MDQ/"
	hub, external, internal                                                                                *simplemd // mddb
	spmetadata, idpmetadata, hubmetadata, encryptedAssertion, response, attributestat, testidpmetadata, testidpviabirkmetadata *goxml.Xp
	privatekey                                                                                             string
)

func SimplePrepareMD(file string) *simplemd {
	indextargets := []string{
		"./md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location",
		"./md:SPSSODescriptor/md:AssertionConsumerService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location",
	}

	index := simplemd{entities: make(map[string]*goxml.Xp)}
	x := goxml.NewXpFromFile(file)
	//ioutil.WriteFile(file, []byte(x.PP()), os.ModePerm)
	entities := x.Query(nil, "md:EntityDescriptor")

	for _, entity := range entities {
		newentity := goxml.NewXpFromNode(entity)
		entityID, _ := entity.(types.Element).GetAttribute("entityID")
		index.entities[entityID.Value()] = newentity
		for _, target := range indextargets {
			locations := newentity.Query(nil, target)
			for _, location := range locations {
				index.entities[location.NodeValue()] = newentity
			}
		}
	}
	return &index
}

func (m simplemd) MDQ(key string) (xp *goxml.Xp, err error) {
	xp = m.entities[key]
	if xp == nil {
		err = goxml.New("err:Metadata not found", "key:"+key)
	}
	return
}

func formatXML(file string) {
	metadata, _ := ioutil.ReadFile(file)
	x := goxml.NewXp(metadata)
	ioutil.WriteFile(file, []byte(x.PP()), os.ModePerm)
}

func TestMain(m *testing.M) {

	Config.NameIDFormats = []string{Transient, Persistent}
	Config.SamlSchema = "../goxml/schemas/saml-schema-protocol-2.0.xsd"
	Config.CertPath = ""

	TestTime = time.Unix(1136239445, 0) // Mon Jan 2 15:04:05 MST 2006 // 01/02 03:04:05PM '06 -0700
	TestId = "ID"
	TestAssertionId = "AssertionID"
	//	hub = SimplePrepareMD("testdata/hub.xml")
	//	internal = SimplePrepareMD("testdata/internal.xml")
	external = SimplePrepareMD("testdata/external.xml")

	//_, err := external.MDQ("https://sp.testshib.org/shibboleth-sp")

	spmetadata, _ = external.MDQ("https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth")
	idpmetadata, _ = external.MDQ("https://aai-logon.switch.ch/idp/shibboleth")

	//	spmetadata = goxml.NewXpFromFile("testdata/spmetadata.xml")   //goxml.NewXp(spmetadatxml)    // NewMD(mdq+"EDUGAIN", "https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth")
	//	idpmetadata = goxml.NewXpFromFile("testdata/idpmetadata.xml") //goxml.NewXp(idpmetadataxml) // NewMD(mdq+"EDUGAIN", "https://aai-logon.switch.ch/idp/shibboleth")
	//	hubmetadata = goxml.xpFrNewXpFromFileomFile("testdata/wayfmd.xml")
	response = goxml.NewXpFromFile("testdata/response.xml")
	encryptedAssertion = goxml.NewXpFromFile("testdata/encryptedAssertion.xml")

	attributestat = goxml.NewXpFromFile("testdata/attrstatement.xml")

	pkey, _ := ioutil.ReadFile("testdata/private.key.pem")
	privatekey = string(pkey)

	/*internal = md{entities: make(map[string]*goxml.Xp)}
	prepareMetadata(config.Metadata.Internal, &internal)
	external = md{entities: make(map[string]*goxml.Xp)}
	prepareMetadata(config.Metadata.External, &external)*/

	/*	fmt.Println("hub = ", hub)
		fmt.Println("internal = ", internal)
		fmt.Println("external = ", external)*/

	//Config.NameIDFormats = []string{Transient, Persistent}
	//spmetadata = goxml.NewXp(spmetadatxml)    // NewMD(mdq+"EDUGAIN", "https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth")
	//idpmetadata = goxml.NewXp(idpmetadataxml) // NewMD(mdq+"EDUGAIN", "https://aai-logon.switch.ch/idp/shibboleth")
	//wayfmetadata = NewMD(mdq, "wayf-hub-public", "https://wayf.wayf.dk")
	//hubmetadata = //goxml.NewXp(wayfmdxml)
	//	testidpmetadata = NewMD(mdq+"HUB-OPS", "https://this.is.not.a.valid.idp")
	//	testidpviabirkmetadata = NewMD(mdq+"BIRK-OPS", "https://birk.wayf.dk/birk.php/this.is.not.a.valid.idp")
	os.Exit(m.Run())
}

func ExampleMetadata() { //Previous Result // urn:oasis:names:tc:SAML:2.0:nameid-format:transient
	fmt.Println(idpmetadata.Query1(nil, "/md:EntityDescriptor/@entityID"))
	fmt.Println(idpmetadata.Query1(nil, "/md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat"))
	// Output:
	// https://aai-logon.switch.ch/idp/shibboleth
	// urn:mace:shibboleth:1.0:nameIdentifier
}

func ExampleSigningKeyNotFound() {
	destination := encryptedAssertion.Query1(nil, "@Destination")
	TestTime, _ = time.Parse(XsDateTime, encryptedAssertion.Query1(nil, "@IssueInstant"))
	data := url.Values{}
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(encryptedAssertion.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, _, _, _, err := ReceiveSAMLResponse(request, external, external)
	fmt.Println(err)
	// Output:
	// open fd666194364791ef937224223c7387f6b26368af.key: no such file or directory
}

func ExampleInvalidDestination() {
	destination := response.Query1(nil, "@Destination")
	response.QueryDashP(nil, "@Destination", "https://www.example.com", nil)
	data := url.Values{}
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(response.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, _, _, _, err := ReceiveSAMLResponse(request, external, external)
	fmt.Println(err)
	// Output:
	// destination: https://www.example.com is not here, here is https://wayfsp.wayf.dk/ss/module.php/saml/sp/saml2-acs.php/default-sp
}

func ExampleAuthnRequest() {
	request, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "")
	fmt.Print(request.Doc.Dump(false))
	// Output:
    // <?xml version="1.0" encoding="UTF-8"?>
    // <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ID="ID" IssueInstant="2014-07-17T01:01:48Z" Destination="https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO" AssertionConsumerServiceURL="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST">
    // <saml:Issuer>https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth</saml:Issuer>
    // <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/>
    // </samlp:AuthnRequest>
}

func ExampleResponse() {
	request, _ := NewAuthnRequest(nil, idpmetadata, spmetadata, "")
	newResponse := NewResponse(idpmetadata, spmetadata, request, response)
	fmt.Printf("%x\n", goxml.Hash(crypto.SHA1, newResponse.PP()))
	// Output:
	// 363b0708171e85031beab0fb22923b1f9dded823
}

func ExampleAttributeCanonicalDump() {
	AttributeCanonicalDump(os.Stdout, response)
	// Output:
	// cn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     Mads Freek Petersen
	// eduPersonAssurance urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     1
	// eduPersonEntitlement urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     https://wayf.dk/feedback/view
	//     https://wayf.dk/kanja/admin
	//     https://wayf.dk/orphanage/admin
	//     https://wayf.dk/vo/admin
	// eduPersonPrimaryAffiliation urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     member
	// eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     gikcaswid@orphanage.wayf.dk
	// eduPersonTargetedID urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     WAYF-DK-c5bc7e16bb6d28cb5a20b6aad84d1cba2df5c48f
	// gn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     Mads Freek
	// mail urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     freek@wayf.dk
	// organizationName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     WAYF Where Are You From
	// preferredLanguage urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     da
	// schacHomeOrganization urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     orphanage.wayf.dk
	// schacHomeOrganizationType urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     urn:mace:terena.org:schac:homeOrganizationType:int:NRENAffiliate
	// sn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     Petersen
}

func ExamplePublicKeyInfo() {
	cert := spmetadata.Query1(nil, encryptionCertQuery) // actual signing key is always first
	var keyname string
	keyname, _, err := PublicKeyInfo(cert)
	fmt.Println(err, keyname)
	// Output:
	// <nil> f8c19afa414fdc045779d20a63d2f46716fe71ff
}

func ExampleSAMLRequest2Url() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "")
	url, err := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	fmt.Println(url, err)
	// Output:
    // https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO?SAMLRequest=pJJBb9swDIXv%2FRWC7rbsoEALIU6RNShmoFuD2N1hN8VmagKy5JF00v37IU4yZJdcdpXI970HvvnTZ%2B%2FVHogxhkLnaaYVhCa2GD4K%2FV6%2FJI%2F6aXE3Z9f7wS5H6cIGfo3Aoj57H9hOH4UeKdjoGNkG1wNbaWy1%2FPZqZ2lmB4oSm%2Bj11crtDccMJBiDVj8u1mZHa%2Buz1BcMJ4e3VLanIbZf63qdrN%2BqWqtyVehypVXJPEIZWFyQQs%2By%2FD7JHpL8oc5ym%2BX2%2FvGnVitgweBkwnciA1tjnMPEx48YUj6gNF3adAbbwQwUd%2BjBHOkzs4EWCRoxVfWm1fIS5zkGHnugCmiPDbxvXq%2BERQi3o0CyRzgApc7hNSMI0A5aoMlQIsBiqg632%2BhBupQ5ntlT0PPJ7JSTFv8D4b%2BQubnWvJTiu%2BuhXK2jx%2Ba3eonUO7l9l%2BMLtsluGrVCLjBCEK2W3sfDM4ETKLTQCNos7k7Qf7u3uPsTAAD%2F%2Fw%3D%3D&RelayState=anton-banton <nil>
}

func ExampleUrl2SAMLRequest() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "")
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	xp, relayState := Url2SAMLRequest(url, nil)
	fmt.Printf("%t\n", newrequest.PP() == xp.PP())
	fmt.Println(relayState)
	// Output:
	// true
	// anton-banton
}

func ExampleDeflate() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "")
	req := base64.StdEncoding.EncodeToString(Deflate([]byte(newrequest.Doc.Dump(false))))
	fmt.Println(req)
	// Output:
    // pJJBb9swDIXv/RWC7rbsoEALIU6RNShmoFuD2N1hN8VmagKy5JF00v37IU4yZJdcdpXI970HvvnTZ+/VHogxhkLnaaYVhCa2GD4K/V6/JI/6aXE3Z9f7wS5H6cIGfo3Aoj57H9hOH4UeKdjoGNkG1wNbaWy1/PZqZ2lmB4oSm+j11crtDccMJBiDVj8u1mZHa+uz1BcMJ4e3VLanIbZf63qdrN+qWqtyVehypVXJPEIZWFyQQs+y/D7JHpL8oc5ym+X2/vGnVitgweBkwnciA1tjnMPEx48YUj6gNF3adAbbwQwUd+jBHOkzs4EWCRoxVfWm1fIS5zkGHnugCmiPDbxvXq+ERQi3o0CyRzgApc7hNSMI0A5aoMlQIsBiqg632+hBupQ5ntlT0PPJ7JSTFv8D4b+QubnWvJTiu+uhXK2jx+a3eonUO7l9l+MLtsluGrVCLjBCEK2W3sfDM4ETKLTQCNos7k7Qf7u3uPsTAAD//w==
}

func ExampleInflate() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "")
	req := Deflate([]byte(newrequest.Doc.Dump(false)))
	res := Inflate(req)
	fmt.Println(string(res))
	// Output:
    // <?xml version="1.0" encoding="UTF-8"?>
    // <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ID="ID" IssueInstant="2014-07-17T01:01:48Z" Destination="https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO" AssertionConsumerServiceURL="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST">
    // <saml:Issuer>https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth</saml:Issuer>
    // <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/>
    // </samlp:AuthnRequest>
}

func ExampleReceiveAuthnRequestPOST() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "")
	destination := newrequest.Query1(nil, "@Destination")
	//newrequest.QueryDashP(nil, "./saml:Issuer", "abc", nil)
	data := url.Values{}
	data.Set("SAMLRequest", base64.StdEncoding.EncodeToString([]byte(newrequest.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, _, _, _, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(err)
	// Output:
	// invalid binding used urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST
}

func ExampleNoAssertion() {
	destination := response.Query1(nil, "@Destination")
	TestTime, _ = time.Parse(XsDateTime, response.Query1(nil, "@IssueInstant"))
	data := url.Values{}
	response.QueryDashP(nil, "/saml:Assertion", " ", nil)
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(response.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, _, _, _, err := ReceiveSAMLResponse(request, external, external)
	//fmt.Println(xp.PP())
	fmt.Println(err)
	// Output:
	// ["cause:schema validation failed"]
}

func ExampleReceiveAuthnRequest() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "")
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, relayState, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(relayState)
	fmt.Println(err)
	// Output:
	// anton-banton
	// <nil>
}

func ExampleNameIDPolicy() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "")

	nameidpolicy := newrequest.Query(nil, "./samlp:NameIDPolicy")[0]
	newrequest.QueryDashP(nameidpolicy, "@Format", "anton-banton", nil)

	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)

	_, _, _, _, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(err)
	// Output:
	// nameidpolicy format: anton-banton is not supported
}

func ExampleReceiveAuthnRequestNoSubject() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "")

	nameidpolicy := newrequest.Query(nil, "./samlp:NameIDPolicy")[0]
	subject := newrequest.QueryDashP(nil, "./saml:Subject/saml:NameID", "mehran", nameidpolicy)

	newrequest.QueryDashP(subject, "@Format", "anton-banton", nil)
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)

	_, _, _, _, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(err)
	// Output:
	// subject not allowed in SAMLRequest
}

func ExampleProtocolCheck() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "")
	newrequest.Query(nil, "/samlp:AuthnRequest")[0].SetNodeName("PutRequest")
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, _, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(err)
	// Output:
	// ["cause:schema validation failed"]
}

func ExampleReceiveUnSignedResponse() {
	destination := response.Query1(nil, "@Destination")
	//response.QueryDashP(nil, "./saml:Assertion[1]/saml:Issuer/ds:Signature", "_4099d6da09c9a1d9fad7f", nil)
	TestTime, _ = time.Parse(XsDateTime, response.Query1(nil, "@IssueInstant"))
	data := url.Values{}
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(response.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	xp, _, _, _, err := ReceiveSAMLResponse(request, external, external)

	data1 := url.Values{} // Checking for unsigned Repsonse here //
	data1.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(xp.Doc.Dump(false))))
	request1 := httptest.NewRequest("POST", destination, strings.NewReader(data1.Encode()))
	request1.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, _, _, _, err = ReceiveSAMLResponse(request1, external, external)
	fmt.Println(err)
	// Output:
	// ["cause:schema validation failed"]
}

// When Content is Changed.
func ExampleCheckDigest() {
	destination := response.Query1(nil, "@Destination")
	response.QueryDashP(nil, "./saml:Assertion[1]/saml:Issuer", "_4099d6da09c9a1d9fad7f", nil)
	TestTime, _ = time.Parse(XsDateTime, response.Query1(nil, "@IssueInstant"))
	data := url.Values{}
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(response.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, _, _, _, err := ReceiveSAMLResponse(request, external, external)
	fmt.Println(err)
	// Output:
	// ["err:Metadata not found","key:https://www.example.com"]
}

func ExampleNoSAMLResponse() {
	destination := response.Query1(nil, "@Destination")
	data := url.Values{}
	data.Set("SAMLResponse", "")
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, _, _, _, err := ReceiveSAMLResponse(request, external, external)
	fmt.Println(err)
	// Output:
	// no SAMLRequest/SAMLResponse found
}

func ExampleNoIssuer() {
	destination := response.Query1(nil, "@Destination")
	response.QueryDashP(nil, "./saml:Issuer", "abc", nil)
	data := url.Values{}
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(response.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, _, _, _, err := ReceiveSAMLResponse(request, external, external)
	fmt.Println(err)
	// Output:
	// ["err:Metadata not found","key:abc"]
}

func ExampleNoDestination() {
	destination := response.Query1(nil, "@Destination")
	response.QueryDashP(nil, "@Destination", "abc", nil)
	data := url.Values{}
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(response.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, _, _, _, err := ReceiveSAMLResponse(request, external, external)
	fmt.Println(err)
	// Output:
	// ["err:Metadata not found","key:abc"]
}

func ExampleInvalidSchema() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "")
	newrequest.Query(nil, "/samlp:AuthnRequest")[0].SetNodeName("PutRequest")
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, _, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(err)
	// Output:
	// ["cause:schema validation failed"]
}

func ExampleInvalidTime() {
	//TestTime, _ = time.Parse("2006-Jan-02", "2013-Feb-03")
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "")
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	xp, _, _, _, _ := ReceiveAuthnRequest(request, external, external)
	xp.QueryDashP(nil, "@IssueInstant", "abc", nil)
	err := VerifyTiming(xp)
	fmt.Println(err)
	// Output:
	// parsing time "abc" as "2006-01-02T15:04:05Z": cannot parse "abc" as "2006"
}

func ExampleOutOfRangeTime() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "")
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)

	xp, _, _, _, _ := ReceiveAuthnRequest(request, external, external)
	xp.QueryDashP(nil, "@IssueInstant", "2014-13-22", nil)
	err := VerifyTiming(xp)
	fmt.Println(err)
	// Output:
	// parsing time "2014-13-22": month out of range
}

func ExampleNoTime() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "")
	newrequest.QueryDashP(nil, "@IssueInstant", "2014-12-22", nil)
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, _, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(err)
	// Output:
	// ["cause:schema validation failed"]
}

func ExampleNoTime2() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "")
	newrequest.QueryDashP(nil, "@IssueInstant", "2002-10-10T12:00:00-05:00", nil)
	url, _ := SAMLRequest2Url(newrequest, "", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, _, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(err)
	// Output:
	// parsing time "2002-10-10T12:00:00-05:00" as "2006-01-02T15:04:05Z": cannot parse "-05:00" as "Z"
}

func ExampleEncryptAndDecrypt() {
	request, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "")
	response := NewResponse(idpmetadata, spmetadata, request, response)
	fmt.Printf("%x\n", goxml.Hash(crypto.SHA1, response.PP()))
	// Output:
	// 74129b21c6f10cf0052fdb3225cf2e0cc9e73342
}
