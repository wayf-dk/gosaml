package gosaml

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/goxml"
	"github.com/y0ssar1an/q"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"sort"
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
	_ = log.Printf // For debugging; delete when done.
	_ = q.Q

	wg                                                                                                                         sync.WaitGroup
	mdq                                                                                                                        = "https://phph.wayf.dk/MDQ/"
	hub, external, internal                                                                                                    *simplemd // mddb
	spmetadata, idpmetadata, hubmetadata, encryptedAssertion, response, attributestat, testidpmetadata, testidpviabirkmetadata *goxml.Xp
	privatekey                                                                                                                 string
	fixedTestTime                                                                                                              = time.Unix(1136239445, 0) // Mon Jan 2 15:04:05 MST 2006 // 01/02 03:04:05PM '06 -0700
	idPList                                                                                                                    []string
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
		err = goxml.NewWerror("err:Metadata not found", "key:"+key)
	}
	return
}

func formatXML(file string) {
	metadata, _ := ioutil.ReadFile(file)
	x := goxml.NewXp(metadata)
	ioutil.WriteFile(file, []byte(x.PP()), os.ModePerm)
}

func TestMain(m *testing.M) {
	Config.SamlSchema = "../goxml/schemas/saml-schema-protocol-2.0.xsd"
	Config.CertPath = ""

	TestTime = fixedTestTime
	TestId = "ID"
	TestAssertionId = "AssertionID"
	//	hub = SimplePrepareMD("testdata/hub.xml")
	//	internal = SimplePrepareMD("testdata/internal.xml")
	external = SimplePrepareMD("testdata/external.xml")

	//_, err := external.MDQ("https://sp.testshib.org/shibboleth-sp")

	spmetadata, _ = external.MDQ("https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth")
	idpmetadata, _ = external.MDQ("https://aai-logon.switch.ch/idp/shibboleth")

	//spmetadata = goxml.NewXpFromFile("testdata/spmetadata.xml")   //goxml.NewXp(spmetadatxml)    // NewMD(mdq+"EDUGAIN", "https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth")
	//idpmetadata = goxml.NewXpFromFile("testdata/idpmetadata.xml") //goxml.NewXp(idpmetadataxml) // NewMD(mdq+"EDUGAIN", "https://aai-logon.switch.ch/idp/shibboleth")
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

func ExampleGetPrivateKey() {
	pKey, err := GetPrivateKey(spmetadata)
	fmt.Println(pKey, err)
	// Output:
	// [] open f8c19afa414fdc045779d20a63d2f46716fe71ff.key: no such file or directory
}

func ExampleParseQueryRaw() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	rawValues := parseQueryRaw(request.URL.RawQuery)
	keys := make([]string, len(rawValues))

	i := 0
	for k := range rawValues {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Println(k, rawValues[k])
	}
	// Output:
	// RelayState [anton-banton]
	// SAMLRequest [pJJBj9owEIXv%2FArL98QhaqvKIqzoolUjbbuIZHvozTjDZiTHTj1j2P77agNU9FAue7Vn3vee5i3uXgcnDhAJg6%2FkPC%2BkAG9Dh%2F6lks%2FtQ%2FZZ3i1nCzKDG%2FUqce%2B38CsBsXgdnCc9fVQyRa%2BDISTtzQCk2epm9e1Rl3mhxxg42ODk1crtDUMEkTF4KX5crJVv1jZnqS%2FoTw5vqexOQ6S%2Ftu0m2zw1rRT1upL1WoqaKEHtiY3nSpZF8Skr5llRtmWpiw%2B6%2BPhTijUQozc84XvmkbRSxmDmwkvwOR2RbZ%2FbXmE3qjGGPTpQb%2FRSbaHDCJZV0zxJsbrEuQ%2Be0gCxgXhAC8%2Fbxyth5oi7xJAdEI4Qc2PwmuEZ4h46iJOhjIFYNT3udsEB9zlROLOnoOeT6SlnXL4HQn8hC3WteSnFdzNAvd4Eh%2Fa3eAhxMPz%2Fu8zz%2BfSCXbafRnXyNILFPUInxcq5cLyPYBgqyTGBVMvZCftv%2B5azPwEAAP%2F%2F]
}

func ExampleNewErrorResponse() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	response := NewErrorResponse(idpmetadata, spmetadata, newrequest, response)
	fmt.Printf("%x\n", sha1.Sum([]byte(response.PP())))
	// Output:
	// 2aed4a3085ceb58e1368a625b76eac7e4ac84c9d
}

func ExampleNewLogoutResponse() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	response := NewLogoutResponse(idpmetadata, spmetadata, newrequest, response)
	fmt.Printf("%x\n", sha1.Sum([]byte(response.PP())))
	// Output:
	// 0c1a15f1bc5d209e93d18dc095f03ae8ef101bec
}

func ExampleNewSLOInfo() {
	sloInfo := NewSLOInfo(response, spmetadata)
	fmt.Println(sloInfo)
	// Output:
	// &{https://wayf.wayf.dk WAYF-DK-c5bc7e16bb6d28cb5a20b6aad84d1cba2df5c48f -  https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth 2}
}

func xxExampleNewLogoutRequest() {
	sloInfo := NewSLOInfo(response, spmetadata)
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request1 := httptest.NewRequest("GET", url.String(), nil)
	//request1.Query(nil, "/samlp:AuthnRequest")[0].SetNodeName("LogoutRequest")
	request, _, _, _, _ := ReceiveLogoutMessage(request1, external, external, 1)
	request.Query(nil, "/samlp:AuthnRequest")[0].SetNodeName("LogoutRequest")
	res, err := NewLogoutRequest(spmetadata, idpmetadata, request, sloInfo, IdPRole)
	fmt.Println(res, err)
	// Output:
	// &{<?xml version="1.0" encoding="utf-8"?>
	// <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" IssueInstant="2006-01-02T22:04:05Z" ID="ID" Destination=""><saml:Issuer>https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth</saml:Issuer><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" SPNameQualifier="https://wayfsp.wayf.dk">WAYF-DK-c5bc7e16bb6d28cb5a20b6aad84d1cba2df5c48f</saml:NameID></samlp:LogoutRequest>
	//  0xc42025f588 <nil> false}

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
	_, _, _, _, err := ReceiveSAMLResponse(request, external, external, "https://"+request.Host+request.URL.Path)
	fmt.Println(err)
	// Output:
	// ["cause:open fd666194364791ef937224223c7387f6b26368af.key: no such file or directory"]
}

func ExampleUnsupportedEncryptionMethod() {
	Config.CertPath = "testdata/"
	destination := encryptedAssertion.Query1(nil, "@Destination")
	TestTime, _ = time.Parse(XsDateTime, encryptedAssertion.Query1(nil, "@IssueInstant"))
	data := url.Values{}
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(encryptedAssertion.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, _, _, _, err := ReceiveSAMLResponse(request, external, external, "https://"+request.Host+request.URL.Path)
	fmt.Println(err)
	fmt.Println(err.(goxml.Werror).FullError())
	// Output:
	// ["cause:encryption error"]
	// ["unsupported keyEncryptionMethod","keyEncryptionMethod: http://www.w3.org/2001/04/xmlenc#rsa-1_5","cause:encryption error"]

}

func ExampleInvalidDestination() {
	destination := response.Query1(nil, "@Destination")
	TestTime, _ = time.Parse(XsDateTime, response.Query1(nil, "@IssueInstant"))

	response.QueryDashP(nil, "@Destination", "https://www.example.com", nil)
	data := url.Values{}
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(response.Doc.Dump(false))))
	//for i := range [100]int{} {
	//	for _ = range [1000]int{} {
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, _, _, _, err := ReceiveSAMLResponse(request, external, external, "https://"+request.Host+request.URL.Path)
	//	}
	//	log.Println(i)
	//}
	//time.Sleep(1 * time.Minute)
	fmt.Println(err)
	// Output:
	// destination: https://www.example.com is not here, here is https://wayfsp.wayf.dk/ss/module.php/saml/sp/saml2-acs.php/default-sp
}

func ExampleAuthnRequest() {
	TestTime = fixedTestTime
	request, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	fmt.Print(request.Doc.Dump(false))
	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ID="ID" IssueInstant="2006-01-02T22:04:05Z" Destination="https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO" AssertionConsumerServiceURL="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST">
	// <saml:Issuer>https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth</saml:Issuer>
	// <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" AllowCreate="true"/>
	// </samlp:AuthnRequest>
}

func ExampleResponse() {
	TestTime = fixedTestTime
	request, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	newResponse := NewResponse(idpmetadata, spmetadata, request, response)
	assertion := newResponse.Query(nil, "saml:Assertion")[0]
	authstatement := newResponse.Query(assertion, "saml:AuthnStatement")[0]
	newResponse.QueryDashP(authstatement, "@SessionIndex", "1", nil)
	fmt.Printf("%x\n", sha1.Sum([]byte(newResponse.PP())))
	// Output:
	// 384160bc3b455052ad7db2f0a700a13142466c37
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
	cert := spmetadata.Query1(nil, "./md:SPSSODescriptor"+EncryptionCertQuery) // actual signing key is always first
	var keyname string
	keyname, _, err := PublicKeyInfo(cert)
	fmt.Println(err, keyname)
	// Output:
	// <nil> f8c19afa414fdc045779d20a63d2f46716fe71ff
}

func ExampleSAMLRequest2Url() {
	TestTime = fixedTestTime
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	url, err := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	fmt.Println(url, err)
	// Output:
	// https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO?SAMLRequest=pJJBj9owEIXv%2FArL98QhaqvKIqzoolUjbbuIZHvozTjDZiTHTj1j2P77agNU9FAue7Vn3vee5i3uXgcnDhAJg6%2FkPC%2BkAG9Dh%2F6lks%2FtQ%2FZZ3i1nCzKDG%2FUqce%2B38CsBsXgdnCc9fVQyRa%2BDISTtzQCk2epm9e1Rl3mhxxg42ODk1crtDUMEkTF4KX5crJVv1jZnqS%2FoTw5vqexOQ6S%2Ftu0m2zw1rRT1upL1WoqaKEHtiY3nSpZF8Skr5llRtmWpiw%2B6%2BPhTijUQozc84XvmkbRSxmDmwkvwOR2RbZ%2FbXmE3qjGGPTpQb%2FRSbaHDCJZV0zxJsbrEuQ%2Be0gCxgXhAC8%2Fbxyth5oi7xJAdEI4Qc2PwmuEZ4h46iJOhjIFYNT3udsEB9zlROLOnoOeT6SlnXL4HQn8hC3WteSnFdzNAvd4Eh%2Fa3eAhxMPz%2Fu8zz%2BfSCXbafRnXyNILFPUInxcq5cLyPYBgqyTGBVMvZCftv%2B5azPwEAAP%2F%2F&RelayState=anton-banton <nil>
}

func ExampleUrl2SAMLRequest() {
	TestTime = fixedTestTime
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	xp, relayState := Url2SAMLRequest(url, nil)
	fmt.Printf("%t\n", newrequest.PP() == xp.PP())
	fmt.Println(relayState)
	// Output:
	// true
	// anton-banton
}

func ExampleDeflate() {
	TestTime = fixedTestTime
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	req := base64.StdEncoding.EncodeToString(Deflate([]byte(newrequest.Doc.Dump(false))))
	fmt.Println(req)
	// Output:
	// pJJBj9owEIXv/ArL98QhaqvKIqzoolUjbbuIZHvozTjDZiTHTj1j2P77agNU9FAue7Vn3vee5i3uXgcnDhAJg6/kPC+kAG9Dh/6lks/tQ/ZZ3i1nCzKDG/Uqce+38CsBsXgdnCc9fVQyRa+DISTtzQCk2epm9e1Rl3mhxxg42ODk1crtDUMEkTF4KX5crJVv1jZnqS/oTw5vqexOQ6S/tu0m2zw1rRT1upL1WoqaKEHtiY3nSpZF8Skr5llRtmWpiw+6+PhTijUQozc84XvmkbRSxmDmwkvwOR2RbZ/bXmE3qjGGPTpQb/RSbaHDCJZV0zxJsbrEuQ+e0gCxgXhAC8/bxyth5oi7xJAdEI4Qc2PwmuEZ4h46iJOhjIFYNT3udsEB9zlROLOnoOeT6SlnXL4HQn8hC3WteSnFdzNAvd4Eh/a3eAhxMPz/u8zz+fSCXbafRnXyNILFPUInxcq5cLyPYBgqyTGBVMvZCftv+5azPwEAAP//
}

func ExampleInflate() {
	TestTime = fixedTestTime
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	req := Deflate([]byte(newrequest.Doc.Dump(false)))
	res := Inflate(req)
	fmt.Println(string(res))
	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ID="ID" IssueInstant="2006-01-02T22:04:05Z" Destination="https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO" AssertionConsumerServiceURL="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST">
	// <saml:Issuer>https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth</saml:Issuer>
	// <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" AllowCreate="true"/>
	// </samlp:AuthnRequest>

}

func ExampleReceiveAuthnRequestPOST() {
	TestTime = fixedTestTime
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	destination := newrequest.Query1(nil, "@Destination")
	//newrequest.QueryDashP(nil, "./saml:Issuer", "abc", nil)
	data := url.Values{}
	data.Set("SAMLRequest", base64.StdEncoding.EncodeToString([]byte(newrequest.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, _, _, _, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(err)
	// Output:
	// ["cause:No valid binding found in metadata"]
}

func ExampleNoAssertion() {
	destination := response.Query1(nil, "@Destination")
	TestTime, _ = time.Parse(XsDateTime, response.Query1(nil, "@IssueInstant"))
	data := url.Values{}
	response.QueryDashP(nil, "/saml:Assertion", " ", nil)
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(response.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, _, _, _, err := ReceiveSAMLResponse(request, external, external, "https://"+request.Host+request.URL.Path)
	//fmt.Println(xp.PP())
	fmt.Println(err)
	// Output:
	// ["cause:schema validation failed"]
}

func ExampleReceiveAuthnRequest() {
	TestTime = fixedTestTime
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, relayState, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(relayState)
	fmt.Println(err)
	// Output:
	// anton-banton
	// <nil>
}

func xTestPP(*testing.T) {
	for i := range [10]int{} {
		fmt.Println(i, spmetadata.Doc.Dump(true))
	}
}

func TestReceiveAuthnRequest(*testing.T) {
	TestTime = fixedTestTime
	i := 0
	for range [1]int{} {
		for range [1]int{} {
			//spmetadata, _ = external.MDQ("https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth")
			newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
			url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
			request := httptest.NewRequest("GET", url.String(), nil)
			_, _, _, _, _ = ReceiveAuthnRequest(request, external, external)
			i++
		}
		log.Println(i)
		runtime.GC()
	}
}

func ExampleLogoutMsgProtocolCheck() {
	TestTime = fixedTestTime
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, _, err := ReceiveLogoutMessage(request, external, external, 1)
	fmt.Println(err)
	// Output:
	// expected protocol(s) [LogoutRequest LogoutResponse] not found, got AuthnRequest
}

func ExampleNameIDPolicy() {
	TestTime = fixedTestTime
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)

	nameidpolicy := newrequest.Query(nil, "./samlp:NameIDPolicy")[0]
	newrequest.QueryDashP(nameidpolicy, "@Format", "anton-banton", nil)

	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)

	_, _, _, _, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(err)
	// Output:
	// nameidpolicy format: 'anton-banton' is not supported
}

func ExampleReceiveAuthnRequestNoSubject() {
	TestTime = fixedTestTime
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)

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
	TestTime = fixedTestTime
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	newrequest.Query(nil, "/samlp:AuthnRequest")[0].SetNodeName("PutRequest")
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, _, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(err)
	// Output:
	// ["cause:schema validation failed"]
}

func xTestReceiveResponse(*testing.T) {
	i := 0
	for range [1]int{} {
		for range [1]int{} {
			destination := response.Query1(nil, "@Destination")
			//response.QueryDashP(nil, "./saml:Assertion[1]/saml:Issuer/ds:Signature", "_4099d6da09c9a1d9fad7f", nil)
			TestTime, _ = time.Parse(XsDateTime, response.Query1(nil, "@IssueInstant"))
			data := url.Values{}
			data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(response.Doc.Dump(false))))
			request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
			request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			_, _, _, _, _ = ReceiveSAMLResponse(request, external, external, "https://"+request.Host+request.URL.Path)
			i++
		}
		log.Println(i)
		//runtime.GC()
	}
}

func ExampleReceiveUnSignedResponse() {
	response := goxml.NewXpFromFile("testdata/response.xml")
	destination := response.Query1(nil, "@Destination")
	TestTime, _ = time.Parse(XsDateTime, response.Query1(nil, "@IssueInstant"))
	data := url.Values{}
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(response.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	xp, _, _, _, _ := ReceiveSAMLResponse(request, external, external, "https://"+request.Host+request.URL.Path)
	data1 := url.Values{} // Checking for unsigned Response here //
	data1.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(xp.Doc.Dump(false))))
	request1 := httptest.NewRequest("POST", destination, strings.NewReader(data1.Encode()))
	request1.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, _, _, _, err := ReceiveSAMLResponse(request1, external, external, "https://"+request1.Host+request1.URL.Path)
	fmt.Println(err)
	fmt.Println(err.(goxml.Werror).FullError())
	// Output:
	// ["cause:encryption error"]
	// ["err:no signatures found","cause:encryption error"]
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
	_, _, _, _, err := ReceiveSAMLResponse(request, external, external, "https://"+request.Host+request.URL.Path)
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
	_, _, _, _, err := ReceiveSAMLResponse(request, external, external, "https://"+request.Host+request.URL.Path)
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

	_, _, _, _, err := ReceiveSAMLResponse(request, external, external, "https://"+request.Host+request.URL.Path)
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

	_, _, _, _, err := ReceiveSAMLResponse(request, external, external, "https://"+request.Host+request.URL.Path)
	fmt.Println(err)
	// Output:
	// ["err:Metadata not found","key:abc"]
}

func ExampleInvalidSchema() {
	TestTime = fixedTestTime
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	newrequest.Query(nil, "/samlp:AuthnRequest")[0].SetNodeName("PutRequest")
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, _, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(err)
	// Output:
	// ["cause:schema validation failed"]
}

func ExampleInvalidTime() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	xp, _, _, _, _ := ReceiveAuthnRequest(request, external, external)
	xp.QueryDashP(nil, "@IssueInstant", "abc", nil)
	req, err := VerifyTiming(xp)
	fmt.Println(req, err)
	// Output:
	// <nil> parsing time "abc" as "2006-01-02T15:04:05Z": cannot parse "abc" as "2006"
}

func ExampleOutOfRangeTime() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)

	xp, _, _, _, _ := ReceiveAuthnRequest(request, external, external)
	xp.QueryDashP(nil, "@IssueInstant", "2014-13-22", nil)
	req, err := VerifyTiming(xp)
	fmt.Println(req, err)
	// Output:
	// <nil> parsing time "2014-13-22": month out of range
}

func ExampleNoTime() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	newrequest.QueryDashP(nil, "@IssueInstant", "2014-12-22", nil)
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	req, _, _, _, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(req, err)
	// Output:
	// <nil> ["cause:schema validation failed"]
}

func ExampleNoTime2() {
	newrequest, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	newrequest.QueryDashP(nil, "@IssueInstant", "2002-10-10T12:00:00-05:00", nil)
	url, _ := SAMLRequest2Url(newrequest, "", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	req, _, _, _, err := ReceiveAuthnRequest(request, external, external)
	fmt.Println(req, err)
	// Output:
	// <nil> parsing time "2002-10-10T12:00:00-05:00" as "2006-01-02T15:04:05Z": cannot parse "-05:00" as "Z"
}

func ExampleEncryptAndDecrypt() {
	TestTime = fixedTestTime
	request, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, idPList)
	response := NewResponse(idpmetadata, spmetadata, request, response)
	assertion := response.Query(nil, "saml:Assertion")[0]
	authstatement := response.Query(assertion, "saml:AuthnStatement")[0]
	response.QueryDashP(authstatement, "@SessionIndex", "1", nil)
	fmt.Printf("%x\n", sha1.Sum([]byte(response.PP())))
	// Output:
	// 74b0fcedd0d455cf105e7ff574b81dac096e92df
}
