package gosaml

import (
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/goxml"
	"io/ioutil"
	"log"
	"net"
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
	spmetadata, idpmetadata, hubmetadata, response, attributestat, testidpmetadata, testidpviabirkmetadata *goxml.Xp
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

func ExampleAuthnRequest() {
	spmd := spmetadata
	idpmd := idpmetadata

	request, _ := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, nil, spmd, idpmd, "")
	fmt.Print(request.Doc.Dump(false))
	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ID="ID" IssueInstant="0001-01-01T00:00:00Z" Destination="https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO" AssertionConsumerServiceURL="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST">
	// <saml:Issuer>https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth</saml:Issuer>
	// <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/>
	// </samlp:AuthnRequest>
}

func ExampleResponse() {
	request, _ := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, nil, idpmetadata, spmetadata, "")
	newResponse := NewResponse(IdAndTiming{time.Time{}, 4 * time.Minute, 4 * time.Hour, "ID", "AssertionID"}, idpmetadata, spmetadata, request, response)
	fmt.Printf("%x\n", goxml.Hash(crypto.SHA1, newResponse.PP()))
	// Output:
	// 0eaee2dd634cf11b8177fc3b75a3ef9d5365a46e
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
	newrequest, _ := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, nil, spmetadata, idpmetadata, "")
	url, err := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	fmt.Println(url, err)
	// Output:
	// https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO?SAMLRequest=pJJBb9swDIXv%2BRWC7rbcnAYhTpE1KGagW4PY3WE3xWZqArLkkXTS%2FfshSjJkl1wK8CSR73sP5OLxY%2FDqAMQYQ6kf8kIrCG3sMLyX%2Bq15zr7ox%2BVswW7wo11N0oct%2FJ6ARX0MPrBNH6WeKNjoGNkGNwBbaW29%2Bv5i53lhR4oS2%2Bj1zcj9CccMJBiDVj%2Bv1uYna5uL1FcMZ4f3VHbnJrbfmmaTbV7rRqtqXepqrVXFPEEVWFyQUhdF8ZClaorCpvql1RpYMDhJ%2BF5kZGuMc5j5%2BB5DzkeUts%2Fb3mA3mpHiHj2YE31uttAhQSumrl%2B1Wl3jPMXA0wBUAx2whbfty42wCOFuEsgOCEeg3Dm8ZQQB2kMHlAxlAiym7nG3ix6kz5njhZ2CXlZmU05afgbC%2FyALc6t5PYofboBqvYke2z%2FqOdLg5P5eTi%2FYZfvUaoVcYIQgWq28j8cnAidQaqEJtFnOztD%2Fb285%2BxsAAP%2F%2F&RelayState=anton-banton <nil>
}

func ExampleUrl2SAMLRequest() {
	newrequest, _ := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, nil, spmetadata, idpmetadata, "")
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	xp, relayState := Url2SAMLRequest(url, nil)
	fmt.Printf("%t\n", newrequest.PP() == xp.PP())
	fmt.Println(relayState)
	// Output:
	// true
	// anton-banton
}

func ExampleDeflate() {
	newrequest, _ := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, nil, spmetadata, idpmetadata, "")
	req := base64.StdEncoding.EncodeToString(Deflate([]byte(newrequest.Doc.Dump(false))))
	fmt.Println(req)
	// Output:
	// pJJBb9swDIXv+RWC7rbcnAYhTpE1KGagW4PY3WE3xWZqArLkkXTS/fshSjJkl1wK8CSR73sP5OLxY/DqAMQYQ6kf8kIrCG3sMLyX+q15zr7ox+VswW7wo11N0oct/J6ARX0MPrBNH6WeKNjoGNkGNwBbaW29+v5i53lhR4oS2+j1zcj9CccMJBiDVj+v1uYna5uL1FcMZ4f3VHbnJrbfmmaTbV7rRqtqXepqrVXFPEEVWFyQUhdF8ZClaorCpvql1RpYMDhJ+F5kZGuMc5j5+B5DzkeUts/b3mA3mpHiHj2YE31uttAhQSumrl+1Wl3jPMXA0wBUAx2whbfty42wCOFuEsgOCEeg3Dm8ZQQB2kMHlAxlAiym7nG3ix6kz5njhZ2CXlZmU05afgbC/yALc6t5PYofboBqvYke2z/qOdLg5P5eTi/YZfvUaoVcYIQgWq28j8cnAidQaqEJtFnOztD/b285+xsAAP//
}

func ExampleInflate() {
	newrequest, _ := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, nil, spmetadata, idpmetadata, "")
	req := Deflate([]byte(newrequest.Doc.Dump(false)))
	res := Inflate(req)
	fmt.Println(string(res))
	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ID="ID" IssueInstant="0001-01-01T00:00:00Z" Destination="https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO" AssertionConsumerServiceURL="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST">
	// <saml:Issuer>https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth</saml:Issuer>
	// <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/>
	// </samlp:AuthnRequest>
}

func ExampleReceiveAuthnRequestPOST() {
	TestTime, _ = time.Parse("2006-Jan-02", "2013-Feb-03")
	newrequest, _ := NewAuthnRequest(IdAndTiming{TestTime, 0, 0, "ID", ""}, nil, spmetadata, idpmetadata, "")
	destination := newrequest.Query1(nil, "@Destination")
	//newrequest.QueryDashP(nil, "./saml:Issuer", "abc", nil)
	data := url.Values{}
	data.Set("SAMLRequest", base64.StdEncoding.EncodeToString([]byte(newrequest.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	xp, _, _, _, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(err)
	fmt.Println(xp.PP())
	// Output:
	// invalid binding used urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST
	// <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
	//                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
	//                     Version="2.0"
	//                     ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	//                     ID="ID"
	//                     IssueInstant="2013-02-03T00:00:00Z"
	//                     Destination="https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO"
	//                     AssertionConsumerServiceURL="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST">
	//     <saml:Issuer>
	//      https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth
	//     </saml:Issuer>
	//     <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	//                         AllowCreate="true"/>
	// </samlp:AuthnRequest>
}

func ExampleReceiveAuthnRequest() {
	TestTime = time.Time{}
	newrequest, _ := NewAuthnRequest(IdAndTiming{}.Refresh(), nil, spmetadata, idpmetadata, "")
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, relayState, err := ReceiveAuthnRequest(request, external, external)
	//fmt.Println("XP = ", xp.PP())
	//fmt.Println("MD = ", md)
	//fmt.Println("MEMD = ", memd)
	fmt.Println(relayState)
	fmt.Println(err)
	// Output:
	// anton-banton
	// <nil>
}

func ExampleNameIDPolicy() {
	TestTime = time.Time{}
	newrequest, _ := NewAuthnRequest(IdAndTiming{time.Now(), 0, 0, "ID", ""}, nil, spmetadata, idpmetadata, "")

	nameidpolicy := newrequest.Query(nil, "./samlp:NameIDPolicy")[0]
	newrequest.QueryDashP(nameidpolicy, "@Format", "anton-banton", nil)

	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)

	_, _, _, relayState, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(relayState)
	fmt.Println(err)
	// Output:
	// anton-banton
	// nameidpolicy format: %!s(MISSING) is not supported
}

func ExampleReceiveAuthnRequestNoSubject() {
	TestTime = time.Time{}
	newrequest, _ := NewAuthnRequest(IdAndTiming{time.Now(), 0, 0, "ID", ""}, nil, spmetadata, idpmetadata, "")

	nameidpolicy := newrequest.Query(nil, "./samlp:NameIDPolicy")[0]
	subject := newrequest.QueryDashP(nil, "./saml:Subject/saml:NameID", "mehran", nameidpolicy)

	newrequest.QueryDashP(subject, "@Format", "anton-banton", nil)
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)

	_, _, _, relayState, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(relayState)
	fmt.Println(err)
	// Output:
	// anton-banton
	// subject not allowed in SAMLRequest
}

func ExampleProtocolCheck() {
	newrequest, _ := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, nil, spmetadata, idpmetadata, "")
	newrequest.Query(nil, "/samlp:AuthnRequest")[0].SetNodeName("PutRequest")
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, relayState, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(relayState)
	fmt.Println(err)
	// Output:
	// anton-banton
	// ["cause:schema validation failed"]
}

func ExampleReceiveUnSignedResponse() {
	destination := response.Query1(nil, "@Destination")
	//response.QueryDashP(nil, "./saml:Assertion[1]/saml:Issuer", "_4099d6da09c9a1d9fad7f", nil)
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
	// No signatures found
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
	// unable to validate signature: digest mismatch
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
	newrequest, _ := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, nil, spmetadata, idpmetadata, "")
	newrequest.Query(nil, "/samlp:AuthnRequest")[0].SetNodeName("PutRequest")
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, relayState, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(relayState)
	fmt.Println(err)
	// Output:
	// anton-banton
	// ["cause:schema validation failed"]
}

func ExampleInvalidTime() {
	TestTime = time.Time{}
	//TestTime, _ = time.Parse("2006-Jan-02", "2013-Feb-03")
	newrequest, _ := NewAuthnRequest(IdAndTiming{}.Refresh(), nil, spmetadata, idpmetadata, "")
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	xp, _, _, relayState, _ := ReceiveAuthnRequest(request, external, external)
	xp.QueryDashP(nil, "@IssueInstant", "abc", nil)
	err := VerifyTiming(xp)
	fmt.Println(relayState)
	fmt.Println(err)
	// Output:
	// anton-banton
	// parsing time "abc" as "2006-01-02T15:04:05Z": cannot parse "abc" as "2006"
}

func ExampleOutOfRangeTime() {
	TestTime = time.Time{}
	newrequest, _ := NewAuthnRequest(IdAndTiming{}.Refresh(), nil, spmetadata, idpmetadata, "")
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)

	xp, _, _, relayState, _ := ReceiveAuthnRequest(request, external, external)
	xp.QueryDashP(nil, "@IssueInstant", "2014-13-22", nil)
	err := VerifyTiming(xp)
	fmt.Println(relayState)
	fmt.Println(err)
	// Output:
	// anton-banton
	// parsing time "2014-13-22": month out of range
}

func ExampleNoTime() {
	newrequest, _ := NewAuthnRequest(IdAndTiming{}.Refresh(), nil, spmetadata, idpmetadata, "")
    newrequest.QueryDashP(nil, "@IssueInstant", "2014-13-22", nil)
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, relayState, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(relayState)
	fmt.Println(err)
	// Output:
	// anton-banton
	// ["cause:schema validation failed"]
}

func ExampleNoTime2() {
	newrequest, _ := NewAuthnRequest(IdAndTiming{}.Refresh(), nil, spmetadata, idpmetadata, "")
    newrequest.QueryDashP(nil, "@IssueInstant", "2002-10-10T12:00:00-05:00", nil)
	url, _ := SAMLRequest2Url(newrequest, "", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, relayState, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(relayState)
	fmt.Println(err)
	// Output:
	// parsing time "2002-10-10T12:00:00-05:00" as "2006-01-02T15:04:05Z": cannot parse "-05:00" as "Z"
}


func ExampleEncryptAndDecrypt() {
	request, _ := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, nil, spmetadata, idpmetadata, "")
	response := NewResponse(IdAndTiming{time.Time{}, 4 * time.Minute, 4 * time.Hour, "ID", "AssertionID"}, idpmetadata, spmetadata, request, response)
	//log.Println(response.PP())
	fmt.Printf("%x\n", goxml.Hash(crypto.SHA1, response.PP()))
	// Output:
	// 840326236b75462273d32c2ff70d1a9cc63ddadd
}

// Repeated her to avoid import cycle - need metadata to be able to test
// MDQclient - read some metadata from either a MDQ Server or a normal feed url.
// Key is either en entityID or Location - allows lookup entity by endpoints,
// this is currently only supported by the phph.wayf.dk/MDQ and is used by WAYF for mass virtual entity hosting
// in BIRK and KRIB. THE PHPh MDQ server only understands the sha1 encoded parameter and currently only
// understands request for 1 entity at a time.
// If key is "" the mdq string is used as a normal feed url.
func NewMD(mdq, key string) (mdxp *goxml.Xp) {
	var err error
	if key != "" {
		mdq = mdq + "/entities/{sha1}" + hex.EncodeToString(goxml.Hash(crypto.SHA1, key))
	}
	url, _ := url.Parse(mdq)
	log.Println("mdq", mdq)

	tr := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		Dial:               func(network, addr string) (net.Conn, error) { return net.Dial("tcp", addr) },
		DisableCompression: true,
	}
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return errors.New("redirect not supported") },
	}

	var req *http.Request
	if req, err = http.NewRequest("GET", url.String(), nil); err != nil {
		log.Fatal(err)
	}
	var resp *http.Response
	if resp, err = client.Do(req); err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode != 200 {
		if key == "" {
			key = mdq
		}
		err = fmt.Errorf("Metadata not found for entity: %s", key)
		//	    err = fmt.Errorf("looking for: '%s' using: '%s' MDQ said: %s\n", key, url.String(), resp.Status)
		log.Fatal(err)
	}
	var md []byte
	if md, err = ioutil.ReadAll(resp.Body); err != nil {
		log.Fatal(err)
	}

	mdxp = goxml.NewXp(md)
	return
}
