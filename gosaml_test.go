package gosaml

import (
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	//"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/goxml"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
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

var (
	_  = log.Printf // For debugging; delete when done.
	wg sync.WaitGroup

	mdq                                                                                     = "https://phph.wayf.dk/MDQ/"
	hub, external, internal                                                                 simplemd // mddb
	spmetadata, idpmetadata, hubmetadata, response, testidpmetadata, testidpviabirkmetadata *goxml.Xp
	privatekey                                                                              string
)

func xpFromFile(file string) (res *goxml.Xp) {
	xml, err := ioutil.ReadFile(file)
	if err != nil {
		log.Panic(err)
	}
	res = goxml.NewXp(string(xml))
	return
}

func TestMain(m *testing.M) {

	//Config.NameIDFormats = []string{Transient, Persistent}

	spmetadata = xpFromFile("testdata/spmetadata.xml")   //goxml.NewXp(spmetadatxml)    // NewMD(mdq+"EDUGAIN", "https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth")
	idpmetadata = xpFromFile("testdata/idpmetadata.xml") //goxml.NewXp(idpmetadataxml) // NewMD(mdq+"EDUGAIN", "https://aai-logon.switch.ch/idp/shibboleth")
	hubmetadata = xpFromFile("testdata/wayfmd.xml")
	response = xpFromFile("testdata/response.xml")

	pkey, _ := ioutil.ReadFile("testdata/private.key.pem")
	privatekey = string(pkey)

	hubmd, _ := ioutil.ReadFile("testdata/hub.xml")
	hub = simplemd{entities: make(map[string]*goxml.Xp)}
	SimplePrepareMD(string(hubmd), &hub)

	internalmd, _ := ioutil.ReadFile("testdata/internal.xml")
	internal = simplemd{entities: make(map[string]*goxml.Xp)}
	SimplePrepareMD(string(internalmd), &internal)

	externalmd, _ := ioutil.ReadFile("testdata/external.xml")
	external = simplemd{entities: make(map[string]*goxml.Xp)}
	SimplePrepareMD(string(externalmd), &external)

	/*internal = md{entities: make(map[string]*goxml.Xp)}
	prepareMetadata(config.Metadata.Internal, &internal)
	external = md{entities: make(map[string]*goxml.Xp)}
	prepareMetadata(config.Metadata.External, &external)*/

	fmt.Println("hub = ", hub)
	fmt.Println("internal = ", internal)
	fmt.Println("external = ", external)

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

	request := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, spmd, idpmd)
	fmt.Print(request.Doc.Dump(false))
	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="ID" IssueInstant="0001-01-01T00:00:00Z" Destination="https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO" AssertionConsumerServiceURL="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
	// <saml:Issuer>https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth</saml:Issuer>
	// <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/>
	// </samlp:AuthnRequest>
}

func ExampleResponse() {
	idpmd := idpmetadata
	spmd := spmetadata
	sourceResponse := response

	request := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, spmd, idpmd)
	response := NewResponse(IdAndTiming{time.Time{}, 4 * time.Minute, 4 * time.Hour, "ID", "AssertionID"}, idpmd, spmd, request, sourceResponse)
	fmt.Print(base64.StdEncoding.EncodeToString(goxml.Hash(crypto.SHA1, response.Doc.Dump(true))))
	// Output:
	// u8Lm3KAuBcX0q4VqX+qQYmF2OdY=
}

func ExampleAttributeCanonicalDump() {
	AttributeCanonicalDump(response)
	// Output:
	// x urn:oid:1.3.6.1.4.1.5923.1.1.1.6 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     gikcaswid@orphanage.wayf.dk
	//     only@thisone.example.com
}

func ExamplePublicKeyInfo() {
	cert := idpmetadata.Query1(nil, IdpCertQuery) // actual signing key is always first
	var keyname string
	keyname, _, err := PublicKeyInfo(cert)
	fmt.Println(err, keyname)
	// Output:
	// <nil> d0a82a5984107320a48d69b7dc80f085646593c0
}

func ExampleSAMLRequest2Url() {
	newrequest := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, spmetadata, idpmetadata)
	url, err := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	fmt.Println(url, err)
	// Output:
	// https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO?RelayState=anton-banton&SAMLRequest=pJJBi9swEIXv%2ByuM7ra8ORURZ0k3LA1suyH29tCbYk%2FWA7KUzoyT9t9XUZJiKORSGDBY8%2BZ9vJn506%2FBZUcgxuAr9ViUKgPfhg79R6Xem5f8k3paPMzZDu5glqP0fgs%2FR2DJotCzSQ%2BVGsmbYBnZeDsAG2lNvfz6amZFaQ4UJLTBqYnkvsIyA0kkUtn3G9rsjLZeVWq9il%2FmEdaexXqpVFmWj3mqpixNqh8qW0VI9FaSuhc5sNHaWsxd%2BAi%2B4BNK2xdtr7E76Mi4Rwf6jDDTW%2BiQoBVd128qW95onoPncQCqgY7Ywvv2dTJYhHA3CuRHhBNQEZ2mHl6A9tABJaBcIpyue9ztggPpC%2BZw9d681Y3KNtfMPqO%2FrOJeXLtLE5svTbPJ04DrykwKihb%2FQ8l%2FKed6OvN2FN8iz3q1CQ7b39lLoMHKfdzzH%2BzyfWo1QtYzgpcYtHPh9ExgBSolNILS0UX%2Fe3uLhz8BAAD%2F%2Fw%3D%3D <nil>
}

func ExampleUrl2SAMLRequest() {
	newrequest := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, spmetadata, idpmetadata)
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	xp, relayState := Url2SAMLRequest(url, nil)
	fmt.Print(base64.StdEncoding.EncodeToString(goxml.Hash(crypto.SHA1, xp.Doc.Dump(true))))
	fmt.Println(relayState)
	// Output:
	// 2ppRFusq6zuHfUZdRjqNZN6Dib8=pJJBi9swEIXv+yuM7ra8ORURZ0k3LA1suyH29tCbYk/WA7KUzoyT9t9XUZJiKORSGDBY8+Z9vJn506/BZUcgxuAr9ViUKgPfhg79R6Xem5f8k3paPMzZDu5glqP0fgs/R2DJotCzSQ+VGsmbYBnZeDsAG2lNvfz6amZFaQ4UJLTBqYnkvsIyA0kkUtn3G9rsjLZeVWq9il/mEdaexXqpVFmWj3mqpixNqh8qW0VI9FaSuhc5sNHaWsxd+Ai+4BNK2xdtr7E76Mi4Rwf6jDDTW+iQoBVd128qW95onoPncQCqgY7Ywvv2dTJYhHA3CuRHhBNQEZ2mHl6A9tABJaBcIpyue9ztggPpC+Zw9d681Y3KNtfMPqO/rOJeXLtLE5svTbPJ04DrykwKihb/Q8l/Ked6OvN2FN8iz3q1CQ7b39lLoMHKfdzzH+zyfWo1QtYzgpcYtHPh9ExgBSolNILS0UX/e3uLhz8BAAD//w==
}

func ExampleDeflate() {
	newrequest := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, spmetadata, idpmetadata)
	req := base64.StdEncoding.EncodeToString(Deflate(newrequest.Doc.Dump(false)))
	fmt.Println(req)
	// Output:
	// pJJBi9swEIXv+yuM7ra8ORURZ0k3LA1suyH29tCbYk/WA7KUzoyT9t9XUZJiKORSGDBY8+Z9vJn506/BZUcgxuAr9ViUKgPfhg79R6Xem5f8k3paPMzZDu5glqP0fgs/R2DJotCzSQ+VGsmbYBnZeDsAG2lNvfz6amZFaQ4UJLTBqYnkvsIyA0kkUtn3G9rsjLZeVWq9il/mEdaexXqpVFmWj3mqpixNqh8qW0VI9FaSuhc5sNHaWsxd+Ai+4BNK2xdtr7E76Mi4Rwf6jDDTW+iQoBVd128qW95onoPncQCqgY7Ywvv2dTJYhHA3CuRHhBNQEZ2mHl6A9tABJaBcIpyue9ztggPpC+Zw9d681Y3KNtfMPqO/rOJeXLtLE5svTbPJ04DrykwKihb/Q8l/Ked6OvN2FN8iz3q1CQ7b39lLoMHKfdzzH+zyfWo1QtYzgpcYtHPh9ExgBSolNILS0UX/e3uLhz8BAAD//w==
}

func ExampleInflate() {
	newrequest := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, spmetadata, idpmetadata)
	req := Deflate(newrequest.Doc.Dump(false))
	res := Inflate(req)
	fmt.Println(string(res))
	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="ID" IssueInstant="0001-01-01T00:00:00Z" Destination="https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO" AssertionConsumerServiceURL="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
	// <saml:Issuer>https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth</saml:Issuer>
	// <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/>
	// </samlp:AuthnRequest>
}

/*
func ExampleDecodeSAMLMsg() {
	newrequest := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, spmetadata, idpmetadata)
	url, _ := SAMLRequest2Url(newrequest, "anton-banton", "", "", "")
	request, err := http.NewRequest("GET", url.String(), nil)
	xp, md, memd, relayState, err := DecodeSAMLMsg(request, internal, hub, "SAMLRequest")
	fmt.Println("XP = ", xp)
	fmt.Println("MD = ", md)
	fmt.Println("MEMD = ", memd)
	fmt.Println("Relaystates = ", relayState)
	fmt.Println("Err = ", err)
	// Output:
	// https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO?RelayState=anton-banton&SAMLRequest=pJJBi9swEIXv%2ByuM7ra8ORURZ0k3LA1suyH29tCbYk%2FWA7KUzoyT9t9XUZJiKORSGDBY8%2BZ9vJn506%2FBZUcgxuAr9ViUKgPfhg79R6Xem5f8k3paPMzZDu5glqP0fgs%2FR2DJotCzSQ%2BVGsmbYBnZeDsAG2lNvfz6amZFaQ4UJLTBqYnkvsIyA0kkUtn3G9rsjLZeVWq9il%2FmEdaexXqpVFmWj3mqpixNqh8qW0VI9FaSuhc5sNHaWsxd%2BAi%2B4BNK2xdtr7E76Mi4Rwf6jDDTW%2BiQoBVd128qW95onoPncQCqgY7Ywvv2dTJYhHA3CuRHhBNQEZ2mHl6A9tABJaBcIpyue9ztggPpC%2BZw9d681Y3KNtfMPqO%2FrOJeXLtLE5svTbPJ04DrykwKihb%2FQ8l%2FKed6OvN2FN8iz3q1CQ7b39lLoMHKfdzzH%2BzyfWo1QtYzgpcYtHPh9ExgBSolNILS0UX%2Fe3uLhz8BAAD%2F%2Fw%3D%3D <nil>
}*/

func xExampleEncryptAndDecrypt() {
	idpmd := idpmetadata
	spmd := spmetadata

	//sourceResponse := response
	//request := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, spmd, idpmd)

	//sourceResponse := goxml.NewXp(response)
	request := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, spmd, idpmd)
	response := NewResponse(IdAndTiming{time.Time{}, 4 * time.Minute, 4 * time.Hour, "ID", "AssertionID"}, idpmd, spmd, request, response)
	fmt.Println(response)
	//assertion := response.Query(nil, "saml:Assertion[1]")[0]

	//pk := privatekey
	/*	ea := goxml.NewXp(`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:EncryptedAssertion>`)
		response.Encrypt(assertion.(types.Element), &privatekey.PublicKey, ea)

		assertion = response.Query(nil, "//saml:EncryptedAssertion")[0]
		//response.Decrypt(assertion.(types.Element), privatekey)
		fmt.Print(response.Doc.Dump(true))

	*/
	// Output:
	//<?xml version="1.0"?>
	//<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="ID" Version="2.0" IssueInstant="0001-01-01T00:00:00Z" InResponseTo="ID" Destination="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST">
	//     <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://aai-logon.switch.ch/idp/shibboleth</saml:Issuer>
	//     <samlp:Status>
	//         <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
	//     </samlp:Status>
	//     <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="AssertionID" IssueInstant="0001-01-01T00:00:00Z" Version="2.0">
	//         <saml:Issuer>https://aai-logon.switch.ch/idp/shibboleth</saml:Issuer>
	//         <saml:Subject>
	//             <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" SPNameQualifier="https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth">_6c41e4c164d64aee825cdecc23ca67187f4741f390</saml:NameID>
	//             <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
	//                 <saml:SubjectConfirmationData InResponseTo="ID" NotOnOrAfter="0001-01-01T00:04:00Z" Recipient="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST"/>
	//             </saml:SubjectConfirmation>
	//         </saml:Subject>
	//         <saml:Conditions NotBefore="0001-01-01T00:00:00Z" NotOnOrAfter="0001-01-01T00:04:00Z">
	//             <saml:AudienceRestriction>
	//                 <saml:Audience>https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth</saml:Audience>
	//             </saml:AudienceRestriction>
	//         </saml:Conditions>
	//         <saml:AuthnStatement AuthnInstant="0001-01-01T00:00:00Z" SessionIndex="missing" SessionNotOnOrAfter="0001-01-01T04:00:00Z">
	//             <saml:AuthnContext>
	//                 <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
	//             </saml:AuthnContext>
	//         </saml:AuthnStatement>
	//         <saml:AttributeStatement>
	//         <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">gikcaswid@orphanage.wayf.dk</saml:AttributeValue><saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">only@thisone.example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
	//     </saml:Assertion>
	//</samlp:Response>
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

	mdxp = goxml.NewXp(string(md))
	return
}
