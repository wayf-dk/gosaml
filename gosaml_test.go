package gosaml

import (
	"bufio"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/goxml"
	"golang.org/x/crypto/curve25519"
	"x.config"
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

	wg                                                               sync.WaitGroup
	mdq                                                              = "https://phph.wayf.dk/MDQ/"
	hub, external, internal                                          *simplemd // mddb
	spmetadata, idpmetadata, hubmetadata, encryptedAssertion         *goxml.Xp
	response, attributestat, testidpmetadata, testidpviabirkmetadata *goxml.Xp
	privatekey                                                       string
	fixedTestTime                                                    = time.Unix(1136239445, 0) // Mon Jan 2 15:04:05 MST 2006 // 01/02 03:04:05PM '06 -0700
	idPList                                                          []string
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
	config.Init()
	TestTime = fixedTestTime
	TestID = "ID"
	TestAssertionID = "AssertionID"
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

// Using Alice's keypair from rfc7748 as the key escrow's keypair and Bob's private key as the ephemeral private key
func ExampleNemLog() {
	peerPrivate, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	peerPublic, _ := hex.DecodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    ephemeralPrivate, _ := hex.DecodeString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    // ephemeralPublic is computed by the Init function

	l := NemLog
	l.name = "log/nemlog"
	l.peerPublic = peerPublic
	l.Init(ephemeralPrivate)
	l.writer.Write([]byte("\njust testing\n"))
	l.Finalize()

	nemLogFile, _ := os.Open(l.name + ".gzip")
	nemLogReader := bufio.NewReader(nemLogFile)
	tmp, _ := nemLogReader.ReadString('\n')
	ephemeralPub, _ := base64.StdEncoding.DecodeString(tmp) // trailing newline ignored
	sessionkey, _ := curve25519.X25519(peerPrivate, ephemeralPub)
	block, _ := aes.NewCipher(sessionkey)
	var iv [aes.BlockSize]byte // blank - we change key for every message
	stream := cipher.NewOFB(block, iv[:])
	nemLogDecryptedReader := &cipher.StreamReader{S: stream, R: nemLogReader}
	nemLogDecompressedReader, _ := gzip.NewReader(nemLogDecryptedReader)
	io.Copy(os.Stdout, nemLogDecompressedReader)

	// Output:
	// just testing
}

func ExampleGetPrivateKey() {
	pKey, _, err := GetPrivateKey(spmetadata, "md:SPSSODescriptor"+EncryptionCertQuery)
	fmt.Println(pKey, err)
	// Output:
	// [] ["cause:open f8c19afa414fdc045779d20a63d2f46716fe71ff.key: file does not exist"]
}

func ExampleParseQueryRaw() {
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	samlURL, _ := SAMLRequest2URL(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", samlURL.String(), nil)
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
	// SAMLRequest [pJJBj9owEIXv%2FArL98TZqK0qi7Cii1aNtO0iku2hN5MMm5EcO52ZAP33FQEqeuHSqz1v3jdvZv547L3aAzHGUOiHNNMKQhNbDO%2BFfqufk8%2F6cTGbs%2Bv9YJejdGEDv0ZgUcfeB7bTR6FHCjY6RrbB9cBWGlstv73YPM3sQFFiE72%2BkdxXOGYgwRi0%2BnFFy09o5arQ5UqrknmEMrC4IIXOs%2BxTkj0kWV7nuc0%2B2OzjT61WwILByaTuRAa2xjiHiY%2FvMaR8QGm6tOkMtoMZKO7Qgzkh5GYDLRI0YqrqVav1hf8LhnMs99C35yK2X%2Bt6naxfq1qr5XWcpxh47IEqoD028LZ5uSETIdyOAske4QCUOoe3kEGAdtACTRMlAiym6nC7jR6kS5njBX7yvKzMTkHR4n9M%2BK%2FJ3Nz2vB7Fd9dDuVpHj81v9Rypd3I%2FotMLtsluKrXDacEsEESrpffx8ETgBAotNII2i9nZ9d%2FjW8z%2BBAAA%2F%2F8%3D]
}

func ExampleNewErrorResponse() {
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	response := NewErrorResponse(idpmetadata, spmetadata, newrequest, response)
	fmt.Println(response.PP())
	// Output:
	// <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
	//                 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
	//                 xmlns:xs="http://www.w3.org/2001/XMLSchema"
	//                 Version="2.0"
	//                 ID="_KRiRsIAzohWB_xUsZrvb34lN_cVb"
	//                 IssueInstant="2022-05-05T11:06:40Z"
	//                 InResponseTo="ID"
	//                 Destination="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST">
	//     <saml:Issuer>
	//      https://aai-logon.switch.ch/idp/shibboleth
	//     </saml:Issuer>
	//     <samlp:Status>
	//         <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
	//     </samlp:Status>
	// </samlp:Response>
}

/*
func ExampleNewLogoutResponse() {
	newrequest, _,  _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	response, _, _ := NewLogoutResponse(idpmetadata, spmetadata, newrequest, IDPRole)
	fmt.Println(response.PP())
	// Output:
	// <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
	//                       xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
	//                       ID=""
	//                       Version="2.0"
	//                       IssueInstant=""
	//                       Destination=""
	//                       InResponseTo="">
	//     <saml:Issuer>
	//      https://wayf.wayf.dk
	//     </saml:Issuer>
	//     <samlp:Status>
	//         <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
	//     </samlp:Status>
	// </samlp:LogoutResponse>
}

func ExampleNewSLOInfo() {
	sloInfo := NewSLOInfo(response, "")
	fmt.Println(sloInfo)
	// Output:
	// &{https://wayf.wayf.dk WAYF-DK-c5bc7e16bb6d28cb5a20b6aad84d1cba2df5c48f https://wayfsp.wayf.dk   2}
}

func xxExampleNewLogoutRequest() {
	sloInfo := NewSLOInfo(response, "")
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	url, _ := SAMLRequest2URL(newrequest, "anton-banton", "", "", "")
	request1 := httptest.NewRequest("GET", url.String(), nil)
	//request1.Query(nil, "/samlp:AuthnRequest")[0].SetNodeName("LogoutRequest")
	request, _, _, _, _, _, _ := ReceiveLogoutMessage(request1, MdSets{external}, MdSets{external}, 1)
	request.Query(nil, "/samlp:AuthnRequest")[0].SetNodeName("LogoutRequest")
	res, _, err := NewLogoutRequest(spmetadata, sloInfo, IDPRole)
	fmt.Println(res, err)
	// Output:
	// &{<?xml version="1.0" encoding="utf-8"?>
	// <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" IssueInstant="2006-01-02T22:04:05Z" ID="ID" Destination=""><saml:Issuer>https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth</saml:Issuer><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" SPNameQualifier="https://wayfsp.wayf.dk">WAYF-DK-c5bc7e16bb6d28cb5a20b6aad84d1cba2df5c48f</saml:NameID></samlp:LogoutRequest>
	//  0xc42025f588 <nil> false}
}
*/

func ExampleMetadata() { //Previous Result // urn:oasis:names:tc:SAML:2.0:nameid-format:transient
	fmt.Println(idpmetadata.Query1(nil, "/md:EntityDescriptor/@entityID"))
	fmt.Println(idpmetadata.Query1(nil, "/md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat"))
	// Output:
	// https://aai-logon.switch.ch/idp/shibboleth
	// urn:mace:shibboleth:1.0:nameIdentifier
}

func xExampleSigningKeyNotFound() {
	destination := encryptedAssertion.Query1(nil, "@Destination")
	TestTime, _ = time.Parse(XsDateTime, encryptedAssertion.Query1(nil, "@IssueInstant"))
	data := url.Values{}
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(encryptedAssertion.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, _, _, _, _, _, err := ReceiveSAMLResponse(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path, nil)
	fmt.Println(err)
	// Output:
	// ["cause:open fd666194364791ef937224223c7387f6b26368af.key: file does not exist"]
}

func ExampleUnsupportedEncryptionMethod() {
	destination := encryptedAssertion.Query1(nil, "@Destination")
	TestTime, _ = time.Parse(XsDateTime, encryptedAssertion.Query1(nil, "@IssueInstant"))
	data := url.Values{}
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(encryptedAssertion.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, _, _, _, _, _, err := ReceiveSAMLResponse(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path, nil)
	fmt.Println(err)
	fmt.Println(err.(goxml.Werror).FullError())
	// Output:
	// ["cause:encryption error"]
	// ["unsupported keyEncryptionMethod","keyEncryptionMethod: http://www.w3.org/2001/04/xmlenc#rsa-1_5","cause:encryption error"]

}

func xExampleInvalidDestination() {
	destination := response.Query1(nil, "@Destination")
	TestTime, _ = time.Parse(XsDateTime, response.Query1(nil, "@IssueInstant"))

	//response.QueryDashP(nil, "@Destination", "https://www.example.com", nil)
	data := url.Values{}
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(response.Doc.Dump(false))))
	//for i := range [100]int{} {
	//	for _ = range [1000]int{} {
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, _, _, _, _, _, err := ReceiveSAMLResponse(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path, nil)
	fmt.Println(err)
	// Output:
	// destination: https://www.example.com is not here, here is https://wayfsp.wayf.dk/ss/module.php/saml/sp/saml2-acs.php/default-sp
}

func ExampleAuthnRequest() {
	TestTime = fixedTestTime
	request, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	fmt.Print(request.Doc.Dump(false))
	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="ID" IssueInstant="2006-01-02T22:04:05Z" Destination="https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST">
	// <saml:Issuer>https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth</saml:Issuer>
	// <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" AllowCreate="true"/>
	// </samlp:AuthnRequest>
}

func ExampleResponse() {
	TestTime = fixedTestTime
	request, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	newResponse := NewResponse(idpmetadata, spmetadata, request, response)
	assertion := newResponse.Query(nil, "saml:Assertion")[0]
	authstatement := newResponse.Query(assertion, "saml:AuthnStatement")[0]
	newResponse.QueryDashP(authstatement, "@SessionIndex", "1", nil)
	fmt.Println(newResponse.PP())
	// Output:
	// <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
	//                 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
	//                 xmlns:xs="http://www.w3.org/2001/XMLSchema"
	//                 Version="2.0"
	//                 ID="ID"
	//                 IssueInstant="2006-01-02T22:04:05Z"
	//                 InResponseTo="ID"
	//                 Destination="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST">
	//     <saml:Issuer>
	//      https://aai-logon.switch.ch/idp/shibboleth
	//     </saml:Issuer>
	//     <samlp:Status>
	//         <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
	//     </samlp:Status>
	//     <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
	//                     Version="2.0"
	//                     ID="AssertionID"
	//                     IssueInstant="2006-01-02T22:04:05Z">
	//         <saml:Issuer>
	//           https://aai-logon.switch.ch/idp/shibboleth
	//         </saml:Issuer>
	//         <saml:Subject>
	//             <saml:NameID SPNameQualifier="https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth"
	//                          Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
	//                __XeyPM1aN1dQJZStha76bug5Tqgn
	//             </saml:NameID>
	//             <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
	//                 <saml:SubjectConfirmationData NotOnOrAfter="2006-01-02T22:08:05Z"
	//                                               Recipient="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST"
	//                                               InResponseTo="ID"/>
	//             </saml:SubjectConfirmation>
	//         </saml:Subject>
	//         <saml:Conditions NotBefore="2006-01-02T22:04:05Z"
	//                          NotOnOrAfter="2006-01-02T22:08:05Z">
	//             <saml:AudienceRestriction>
	//                 <saml:Audience>
	//                     https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth
	//                 </saml:Audience>
	//             </saml:AudienceRestriction>
	//         </saml:Conditions>
	//         <saml:AuthnStatement AuthnInstant="2022-05-05T11:06:40Z"
	//                              SessionIndex="1"
	//                              SessionNotOnOrAfter="2022-05-05T15:06:40Z">
	//             <saml:AuthnContext>
	//                 <saml:AuthnContextClassRef/>
	//                 <saml:AuthenticatingAuthority>
	//                     https://orphanage.wayf.dk
	//                 </saml:AuthenticatingAuthority>
	//                 <saml:AuthenticatingAuthority>
	//                     https://wayf.wayf.dk
	//                 </saml:AuthenticatingAuthority>
	//             </saml:AuthnContext>
	//         </saml:AuthnStatement>
	//     </saml:Assertion>
	// </samlp:Response>
}

func ExampleAttributeCanonicalDump() {
	AttributeCanonicalDump(os.Stdout, response)
	// Output:
	// cn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     Mads Freek Petersen
	// eduPersonAffiliation urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     member
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
	// eduPersonScopedAffiliation urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     member@orphanage.wayf.dk
	// eduPersonTargetedID urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     WAYF-DK-a462971438f09f28b0cf806965a5b5461376815b
	// entryUUID urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     123-456-789
	// gn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     Mads Freek
	// isMemberOf urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     prefix:1:abc:infix:2:def:infix:3::hij:postfix:4
	//     role1:idp:example.com
	//     role1:idp:example.net
	//     role1:req:example.net
	//     role1:sp:
	//     role1:xxx:xxexample.net
	// mail urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     freek@wayf.dk
	// norEduPersonNIN urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     2408590123
	// organizationName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     WAYF Where Are You From
	// preferredLanguage urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     da
	// schacDateOfBirth urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     19590824
	// schacHomeOrganization urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     orphanage.wayf.dk
	// schacHomeOrganizationType urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     urn:mace:terena.org:schac:homeOrganizationType:int:NRENAffiliate
	// schacPersonalUniqueCode urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     urn:schac:personalUniqueCode:int:esi:wayf.dk:99924678
	// schacPersonalUniqueID urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408590123
	// schacYearOfBirth urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     1959
	// sn NameStandIn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     Petersenx
	// sn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
	//     Petersenx
}

func ExamplePublicKeyInfo() {
	cert := spmetadata.Query1(nil, "./md:SPSSODescriptor"+EncryptionCertQuery) // actual signing key is always first
	var keyname string
	keyname, _, err := PublicKeyInfo(cert)
	fmt.Println(err, keyname)
	// Output:
	// <nil> f8c19afa414fdc045779d20a63d2f46716fe71ff
}

func ExampleSAMLRequest2URL() {
	TestTime = fixedTestTime
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	url, err := SAMLRequest2URL(newrequest, "anton-banton", "", "", "")
	fmt.Println(url, err)
	// Output:
	// https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO?SAMLRequest=pJJBj9owEIXv%2FArL98TZqK0qi7Cii1aNtO0iku2hN5MMm5EcO52ZAP33FQEqeuHSqz1v3jdvZv547L3aAzHGUOiHNNMKQhNbDO%2BFfqufk8%2F6cTGbs%2Bv9YJejdGEDv0ZgUcfeB7bTR6FHCjY6RrbB9cBWGlstv73YPM3sQFFiE72%2BkdxXOGYgwRi0%2BnFFy09o5arQ5UqrknmEMrC4IIXOs%2BxTkj0kWV7nuc0%2B2OzjT61WwILByaTuRAa2xjiHiY%2FvMaR8QGm6tOkMtoMZKO7Qgzkh5GYDLRI0YqrqVav1hf8LhnMs99C35yK2X%2Bt6naxfq1qr5XWcpxh47IEqoD028LZ5uSETIdyOAske4QCUOoe3kEGAdtACTRMlAiym6nC7jR6kS5njBX7yvKzMTkHR4n9M%2BK%2FJ3Nz2vB7Fd9dDuVpHj81v9Rypd3I%2FotMLtsluKrXDacEsEESrpffx8ETgBAotNII2i9nZ9d%2FjW8z%2BBAAA%2F%2F8%3D&RelayState=anton-banton <nil>
}

func ExampleURL2SAMLRequest() {
	TestTime = fixedTestTime
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	url, _ := SAMLRequest2URL(newrequest, "anton-banton", "", "", "")
	xp, relayState := URL2SAMLRequest(url, nil)
	fmt.Printf("%t\n", newrequest.PP() == xp.PP())
	fmt.Println(relayState)
	// Output:
	// true
	// anton-banton
}

func ExampleDeflate() {
	TestTime = fixedTestTime
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	req := base64.StdEncoding.EncodeToString(Deflate([]byte(newrequest.Doc.Dump(false))))
	fmt.Println(req)
	// Output:
	// pJJBj9owEIXv/ArL98TZqK0qi7Cii1aNtO0iku2hN5MMm5EcO52ZAP33FQEqeuHSqz1v3jdvZv547L3aAzHGUOiHNNMKQhNbDO+Ffqufk8/6cTGbs+v9YJejdGEDv0ZgUcfeB7bTR6FHCjY6RrbB9cBWGlstv73YPM3sQFFiE72+kdxXOGYgwRi0+nFFy09o5arQ5UqrknmEMrC4IIXOs+xTkj0kWV7nuc0+2OzjT61WwILByaTuRAa2xjiHiY/vMaR8QGm6tOkMtoMZKO7Qgzkh5GYDLRI0YqrqVav1hf8LhnMs99C35yK2X+t6naxfq1qr5XWcpxh47IEqoD028LZ5uSETIdyOAske4QCUOoe3kEGAdtACTRMlAiym6nC7jR6kS5njBX7yvKzMTkHR4n9M+K/J3Nz2vB7Fd9dDuVpHj81v9Rypd3I/otMLtsluKrXDacEsEESrpffx8ETgBAotNII2i9nZ9d/jW8z+BAAA//8=

}

func ExampleInflate() {
	TestTime = fixedTestTime
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	req := Deflate([]byte(newrequest.Doc.Dump(false)))
	res := Inflate(req)
	fmt.Println(string(res))
	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="ID" IssueInstant="2006-01-02T22:04:05Z" Destination="https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST">
	// <saml:Issuer>https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth</saml:Issuer>
	// <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" AllowCreate="true"/>
	// </samlp:AuthnRequest>
}

func ExampleReceiveAuthnRequestPOST() {
	TestTime = fixedTestTime
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	destination := newrequest.Query1(nil, "@Destination")
	//newrequest.QueryDashP(nil, "./saml:Issuer", "abc", nil)
	data := url.Values{}
	data.Set("SAMLRequest", base64.StdEncoding.EncodeToString([]byte(newrequest.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, _, _, _, _, _, err := ReceiveAuthnRequest(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path)
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
	_, _, _, _, _, _, err := ReceiveSAMLResponse(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path, nil)
	fmt.Println(err)
	// Output:
	// ["cause:schema validation failed"]

	// [Element '{urn:oasis:names:tc:SAML:2.0:assertion}Assertion': Missing child element(s). Expected is ( {urn:oasis:names:tc:SAML:2.0:assertion}Issuer ).]
}

func ExampleReceiveAuthnRequest() {
	TestTime = fixedTestTime
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	url, _ := SAMLRequest2URL(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, relayState, _, _, err := ReceiveAuthnRequest(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path)
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
			newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
			url, _ := SAMLRequest2URL(newrequest, "anton-banton", "", "", "")
			request := httptest.NewRequest("GET", url.String(), nil)
			_, _, _, _, _, _, _ = ReceiveAuthnRequest(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path)
			i++
		}
	}
}

func ExampleLogoutMsgProtocolCheck() {
	TestTime = fixedTestTime
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	url, _ := SAMLRequest2URL(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, _, _, _, err := ReceiveLogoutMessage(request, MdSets{external}, MdSets{external}, 1)
	fmt.Println(err)
	// Output:
	// expected protocol(s) [LogoutRequest LogoutResponse] not found, got AuthnRequest
}

func ExampleNameIDPolicy() {
	TestTime = fixedTestTime
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)

	nameidpolicy := newrequest.Query(nil, "./samlp:NameIDPolicy")[0]
	newrequest.QueryDashP(nameidpolicy, "@Format", "anton-banton", nil)

	url, _ := SAMLRequest2URL(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)

	_, _, _, _, _, _, err := ReceiveAuthnRequest(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path)
	fmt.Println(err)
	// Output:
	// nameidpolicy format: 'anton-banton' is not supported
}

func ExampleReceiveAuthnRequestNoSubject() {
	TestTime = fixedTestTime
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	nameidpolicy := newrequest.Query(nil, "./samlp:NameIDPolicy")[0]
	subject := newrequest.QueryDashP(nil, "./saml:Subject/saml:NameID", "mehran", nameidpolicy)

	newrequest.QueryDashP(subject, "@Format", "anton-banton", nil)
	url, _ := SAMLRequest2URL(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)

	_, _, _, _, _, _, err := ReceiveAuthnRequest(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path)
	fmt.Println(err)
	// Output:
	// subject not allowed in SAMLRequest
}

func ExampleProtocolCheck() {
	TestTime = fixedTestTime
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	newrequest.Query(nil, "/samlp:AuthnRequest")[0].SetNodeName("PutRequest")
	url, _ := SAMLRequest2URL(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, _, _, _, err := ReceiveAuthnRequest(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path)
	fmt.Println(err)
	// Output:
	// ["cause:schema validation failed"]

	// [Element '{urn:oasis:names:tc:SAML:2.0:protocol}PutRequest': No matching global declaration available for the validation root.]
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
			_, _, _, _, _, _, _ = ReceiveSAMLResponse(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path, nil)
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
	xp, _, _, _, _, _, _ := ReceiveSAMLResponse(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path, nil)
	data1 := url.Values{} // Checking for unsigned Response here //
	data1.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(xp.Doc.Dump(false))))
	request1 := httptest.NewRequest("POST", destination, strings.NewReader(data1.Encode()))
	request1.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, _, _, _, _, _, err := ReceiveSAMLResponse(request1, MdSets{external}, MdSets{external}, "https://"+request1.Host+request1.URL.Path, nil)
	fmt.Println(err)
	//fmt.Println(err.(goxml.Werror).FullError())
	// Output:
	// ["cause:encryption error"]
	// ["err:no signatures found","cause:encryption error"]
}

// When Content is Changed.
func xExampleCheckDigest() {
	destination := response.Query1(nil, "@Destination")
	response.QueryDashP(nil, "./saml:Assertion[1]/saml:Issuer", "_4099d6da09c9a1d9fad7f", nil)
	TestTime, _ = time.Parse(XsDateTime, response.Query1(nil, "@IssueInstant"))
	data := url.Values{}
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(response.Doc.Dump(false))))
	request := httptest.NewRequest("POST", destination, strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, _, _, _, _, _, err := ReceiveSAMLResponse(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path, nil)
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
	_, _, _, _, _, _, err := ReceiveSAMLResponse(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path, nil)
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

	_, _, _, _, _, _, err := ReceiveSAMLResponse(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path, nil)
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

	_, _, _, _, _, _, err := ReceiveSAMLResponse(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path, nil)
	fmt.Println(err)
	// Output:
	// ["err:Metadata not found","key:abc"]
}

func ExampleInvalidSchema() {
	TestTime = fixedTestTime
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	newrequest.Query(nil, "/samlp:AuthnRequest")[0].SetNodeName("PutRequest")
	url, _ := SAMLRequest2URL(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	_, _, _, _, _, _, err := ReceiveAuthnRequest(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path)
	fmt.Println(err)
	// Output:
	// ["cause:schema validation failed"]

	// [Element '{urn:oasis:names:tc:SAML:2.0:protocol}PutRequest': No matching global declaration available for the validation root.]
}

func ExampleInvalidTime() {
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	url, _ := SAMLRequest2URL(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	xp, _, _, _, _, _, _ := ReceiveAuthnRequest(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path)
	xp.QueryDashP(nil, "@IssueInstant", "abc", nil)
	req, err := VerifyTiming(xp, true)
	fmt.Println(req, err)
	// Output:
	// <nil> parsing time "abc" as "2006-01-02T15:04:05Z": cannot parse "abc" as "2006"
}

func ExampleOutOfRangeTime() {
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	url, _ := SAMLRequest2URL(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)

	xp, _, _, _, _, _, _ := ReceiveAuthnRequest(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path)
	xp.QueryDashP(nil, "@IssueInstant", "2014-13-22", nil)
	req, err := VerifyTiming(xp, true)
	fmt.Println(req, err)
	// Output:
	// <nil> parsing time "2014-13-22": month out of range
}

func ExampleNoTime() {
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	newrequest.QueryDashP(nil, "@IssueInstant", "2014-12-22", nil)
	url, _ := SAMLRequest2URL(newrequest, "anton-banton", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	req, _, _, _, _, _, err := ReceiveAuthnRequest(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path)
	fmt.Println(req, err)
	// Output:
	// <nil> ["cause:schema validation failed"]

	// [Element '{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest', attribute 'IssueInstant': '2014-12-22' is not a valid value of the atomic type 'xs:dateTime'.]
}

func ExampleNoTime2() {
	newrequest, _, _ := NewAuthnRequest(nil, spmetadata, idpmetadata, "", idPList, "", false, 0, 0)
	newrequest.QueryDashP(nil, "@IssueInstant", "2002-10-10T12:00:00-05:00", nil)
	url, _ := SAMLRequest2URL(newrequest, "", "", "", "")
	request := httptest.NewRequest("GET", url.String(), nil)
	req, _, _, _, _, _, err := ReceiveAuthnRequest(request, MdSets{external}, MdSets{external}, "https://"+request.Host+request.URL.Path)
	fmt.Println(req, err)
	// Output:
	// <nil> parsing time "2002-10-10T12:00:00-05:00" as "2006-01-02T15:04:05Z": cannot parse "-05:00" as "Z"
}
