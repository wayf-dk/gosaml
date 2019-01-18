// Gosaml is a library for doing SAML stuff in Go.

package gosaml

import (
	"bytes"
	"compress/flate"
	//"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	//"github.com/wayf-dk/go-libxml2/clib"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/goxml"
	"github.com/y0ssar1an/q"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	_ = log.Printf // For debugging; delete when done.
	_ = q.Q
)

const (
	// IdPRole used to set the role as an IDP
	IdPRole = iota
	// SPRole used to set the role as an SP
	SPRole = iota
)

const (
	// SAMLSign for SAML signing
	SAMLSign = iota
	// WSFedSign for WS-Fed signing
	WSFedSign = iota
)

const (
	// XsDateTime Setting the Date Time
	XsDateTime = "2006-01-02T15:04:05Z"
	// SigningCertQuery refers to get the key from the metadata
	SigningCertQuery = `/md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`
	// EncryptionCertQuery refers to encryption key
	EncryptionCertQuery = `/md:KeyDescriptor[@use="encryption" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`
	// Transient refers to nameid format
	Transient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	// Persistent refers to nameid format
	Persistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	// X509 refers to nameid format
	X509 = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
	// Email refers to nameid format
	Email = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	// Unspecified refers to unspecified nameid format
	Unspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

	// REDIRECT refers to HTTP-Redirect
	REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	// POST refers to HTTP-POST
	POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	// SIMPLESIGN refers to HTTP-POST-SimpleSign
	SIMPLESIGN = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"
)

type (
	// Md Interface for metadata provider
	Md interface {
		MDQ(key string) (xp *goxml.Xp, err error)
	}
	// Conf refers to Configuration values for Schema and Certificates
	Conf struct {
		SamlSchema string
		CertPath   string
		LogPath    string
	}
	// SLOInfo refers to Single Logout information
	SLOInfo struct {
		//		IssuerID, NameID, SPNameQualifier, SessionIndex, DestinationID string
		Is, Na, Sp, Si, De string
		//		Format int
		Fo int
	}
)

var (
	// TestTime refers to global testing time
	TestTime time.Time
	// TestId for testing
	TestId string
	// TestAssertionId for testing
	TestAssertionId string
	// Roles refers to defining roles for SPs and IDPs
	Roles = []string{"md:IDPSSODescriptor", "md:SPSSODescriptor"}
	// Config initialisation
	Config = Conf{}
	// ACSError refers error information
	ACSError = errors.New("invalid AsssertionConsumerService or AsssertionConsumerServiceIndex")
	// NameIDList list of supported nameid formats
	NameIDList = []string{"", Transient, Persistent, X509, Email, Unspecified}
	// NameIDMap refers to mapping the nameid formats
	NameIDMap = map[string]int{"": 1, Transient: 1, Persistent: 2, X509: 3, Email: 4, Unspecified: 5} // Unspecified accepted but not sent upstream
	whitespace = regexp.MustCompile("\\s")
)

// DebugSetting for debugging cookies
func DebugSetting(r *http.Request, name string) string {
	cookie, err := r.Cookie("debug")
	if err == nil {
		vals, _ := url.ParseQuery(cookie.Value)
		return vals.Get(name)
	}
	return ""
}

// DumpFile is for logging requests and responses
func DumpFile(r *http.Request, xp *goxml.Xp) (logtag string) {
	msgType := xp.QueryString(nil, "local-name(/*)")
	logtag = dump(msgType, []byte(fmt.Sprintf("%s\n###\n%s", xp.PP(), goxml.NewWerror("").Stack(1))))
	return
}

func DumpFileIfTracing(r *http.Request, xp *goxml.Xp) (logtag string) {
	if DebugSetting(r, "trace") == "1" {
	    logtag = DumpFile(r, xp)
	}
	return
}

func dump(msgType string, blob []byte) (logtag string) {
	now := TestTime
	if now.IsZero() {
		now = time.Now()
	}
	logtag = now.Format("2006-01-02T15:04:05.0000000") // local time with microseconds
	if err := ioutil.WriteFile(fmt.Sprintf("log/%s-%s", logtag, msgType), blob, 0644); err != nil {
		//log.Panic(err)
	}
	return
}

// PublicKeyInfo extracts the keyname, publickey and cert (base64 DER - no PEM) from the given certificate.
// The keyname is computed from the public key corresponding to running this command: openssl x509 -modulus -noout -in <cert> | openssl sha1.
func PublicKeyInfo(cert string) (keyname string, publickey *rsa.PublicKey, err error) {
	// no pem so no pem.Decode
	key, err := base64.StdEncoding.DecodeString(whitespace.ReplaceAllString(cert, ""))
	pk, err := x509.ParseCertificate(key)
	if err != nil {
		return
	}
	publickey = pk.PublicKey.(*rsa.PublicKey)
	keyname = fmt.Sprintf("%x", sha1.Sum([]byte(fmt.Sprintf("Modulus=%X\n", publickey.N))))
	return
}

// GetPrivateKey extract the key from Metadata and builds a name and reads the key
func GetPrivateKey(md *goxml.Xp) (privatekey []byte, err error) {
	cert := md.Query1(nil, "./"+SigningCertQuery) // actual signing key is always first
	keyname, _, err := PublicKeyInfo(cert)
	if err != nil {
		return
	}

	privatekey, err = ioutil.ReadFile(Config.CertPath + keyname + ".key")
	if err != nil {
		return
	}
	return
}

// Id makes a random id
func Id() (id string) {
	b := make([]byte, 21) // 168 bits - just over the 160 bit recomendation without base64 padding
	rand.Read(b)
	return "_" + hex.EncodeToString(b)
}

// Deflate utility that compresses a string using the flate algo
func Deflate(inflated []byte) []byte {
	var b bytes.Buffer
	w, _ := flate.NewWriter(&b, -1)
	w.Write(inflated)
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
func Html2SAMLResponse(html []byte) (samlresponse *goxml.Xp, relayState string) {
	response := goxml.NewHtmlXp(html)
	samlbase64 := response.Query1(nil, `//input[@name="SAMLResponse"]/@value`)
	relayState = response.Query1(nil, `//input[@name="RelayState"]/@value`)
	samlxml, _ := base64.StdEncoding.DecodeString(samlbase64)
	samlresponse = goxml.NewXp(samlxml)
	return
}

// Url2SAMLRequest extracts the SAMLRequest from an URL
func Url2SAMLRequest(url *url.URL, err error) (samlrequest *goxml.Xp, relayState string) {
	query := url.Query()
	req, _ := base64.StdEncoding.DecodeString(query.Get("SAMLRequest"))
	relayState = query.Get("RelayState")
	samlrequest = goxml.NewXp(Inflate(req))
	return
}

// SAMLRequest2Url creates a redirect URL from a saml request
func SAMLRequest2Url(samlrequest *goxml.Xp, relayState, privatekey, pw, algo string) (destination *url.URL, err error) {
	var paramName string
	switch samlrequest.QueryString(nil, "local-name(/*)") {
	case "LogoutResponse":
		paramName = "SAMLResponse="
	default:
		paramName = "SAMLRequest="
	}

	req := base64.StdEncoding.EncodeToString(Deflate(samlrequest.Dump()))

	destination, _ = url.Parse(samlrequest.Query1(nil, "@Destination"))
	q := paramName + url.QueryEscape(req)
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}

	if privatekey != "" {
		q += "&SigAlg=" + url.QueryEscape(goxml.Algos[algo].Signature)

		digest := goxml.Hash(goxml.Algos[algo].Algo, q)

		var signaturevalue []byte
		signaturevalue, err = goxml.Sign(digest, []byte(privatekey), []byte(pw), algo)
		if err != nil {
			return
		}
		signatureval := base64.StdEncoding.EncodeToString(signaturevalue)
		q += "&Signature=" + url.QueryEscape(signatureval)
	}

	destination.RawQuery = q
	return
}

// AttributeCanonicalDump for canonical dump
func AttributeCanonicalDump(w io.Writer, xp *goxml.Xp) {
	attrsmap := map[string][]string{}
	keys := []string{}
	attrs := xp.Query(nil, "./saml:Assertion/saml:AttributeStatement/saml:Attribute")
	for _, attr := range attrs {
		values := []string{}
		for _, value := range xp.QueryMulti(attr, "saml:AttributeValue") {
			values = append(values, value)
		}
		name := xp.Query1(attr, "@Name") + " "
		friendlyName := xp.Query1(attr, "@FriendlyName") + " "
		nameFormat := xp.Query1(attr, "@NameFormat")
		if name == friendlyName {
			friendlyName = ""
		}
		key := strings.TrimSpace(friendlyName + name + nameFormat)
		keys = append(keys, key)
		attrsmap[key] = values
	}

	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintln(w, key)
		values := attrsmap[key]
		sort.Strings(values)
		for _, value := range values {
			if value != "" {
				fmt.Fprint(w, "    ")
				xml.EscapeText(w, bytes.TrimSpace([]byte(value)))
			}
			fmt.Fprintln(w)
		}
	}
}

// ReceiveAuthnRequest receives the authentication request
// Checks for Subject and  NameidPolicy(Persistent or Transient)
// Receives the metadatasets for resp. the sender and the receiver
// Returns metadata for the sender and the receiver
func ReceiveAuthnRequest(r *http.Request, issuerMdSet, destinationMdSet Md) (xp, issuerMd, destinationMd *goxml.Xp, relayState string, err error) {
	xp, issuerMd, destinationMd, relayState, err = DecodeSAMLMsg(r, issuerMdSet, destinationMdSet, IdPRole, []string{"AuthnRequest"}, "https://"+r.Host+r.URL.Path)
	if err != nil {
		return
	}
	subject := xp.Query1(nil, "./saml:Subject")
	if subject != "" {
		err = fmt.Errorf("subject not allowed in SAMLRequest")
		return
	}
	nameIDFormat := xp.Query1(nil, "./samlp:NameIDPolicy/@Format")
	if NameIDMap[nameIDFormat] == 0 {
		err = fmt.Errorf("nameidpolicy format: '%s' is not supported", nameIDFormat)
		return
	}

	if nameIDFormat == Transient {
	} else if nameIDFormat == Unspecified || nameIDFormat == "" {
		nameIDFormat = issuerMd.Query1(nil, "./md:SPSSODescriptor/md:NameIDFormat") // none ends up being Transient
	} else if inArray(nameIDFormat, issuerMd.QueryMulti(nil, "./md:SPSSODescriptor/md:NameIDFormat")) {
	} else {
		nameIDFormat = Transient
	}
	xp.QueryDashP(nil, "./samlp:NameIDPolicy/@Format", nameIDFormat, nil)

	/*
		allowcreate := xp.Query1(nil, "./samlp:NameIDPolicy/@AllowCreate")
		if allowcreate != "true" && allowcreate != "1" {
			err = fmt.Errorf("only supported value for NameIDPolicy @AllowCreate is true/1, got: %s", allowcreate)
			return
		}
	*/
	return
}

func inArray(item string, array []string) bool {
	for _, i := range array {
		if i == item {
			return true
		}
	}
	return false
}

// ReceiveSAMLResponse handles the SAML minutiae when receiving a SAMLResponse
// Currently the only supported binding is POST
// Receives the metadatasets for resp. the sender and the receiver
// Returns metadata for the sender and the receiver
func ReceiveSAMLResponse(r *http.Request, issuerMdSet, destinationMdSet Md, location string) (xp, issuerMd, destinationMd *goxml.Xp, relayState string, err error) {
	return DecodeSAMLMsg(r, issuerMdSet, destinationMdSet, SPRole, []string{"Response"}, location)
}

// ReceiveLogoutMessage receives the Logout Message
// Receives the metadatasets for resp. the sender and the receiver
// Returns metadata for the sender and the receiver
func ReceiveLogoutMessage(r *http.Request, issuerMdSet, destinationMdSet Md, role int) (xp, issuerMd, destinationMd *goxml.Xp, relayState string, err error) {
	return DecodeSAMLMsg(r, issuerMdSet, destinationMdSet, role, []string{"LogoutRequest", "LogoutResponse"}, "https://"+r.Host+r.URL.Path)
}

// DecodeSAMLMsg decodes the Request. Extracts Issuer, Destination
// Check for Protocol for example (AuthnRequest)
// Validates the schema
// Receives the metadatasets for resp. the sender and the receiver
// Returns metadata for the sender and the receiver
func DecodeSAMLMsg(r *http.Request, issuerMdSet, destinationMdSet Md, role int, protocols []string, location string) (xp, issuerMd, destinationMd *goxml.Xp, relayState string, err error) {
	defer r.Body.Close()
	r.ParseForm()
	method := r.Method

	if ok := method == "GET" || method == "POST"; !ok {
    	err = fmt.Errorf("unsupported http method used '%s'", method)
		return
	}

	relayState = r.Form.Get("RelayState")

	msg := r.Form.Get("SAMLRequest")
	if msg == "" {
		msg = r.Form.Get("SAMLResponse")
		if msg == "" {
			msg, relayState = wsfedRequest2samlRequest(r, issuerMdSet, destinationMdSet)
			if msg == "" {
				err = fmt.Errorf("no SAMLRequest/SAMLResponse found")
				return
			}
		}
	}

	bmsg, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return
	}
	if method == "GET" {
		bmsg = Inflate(bmsg)
	}

	tmpXp := goxml.NewXp(bmsg)

	DumpFileIfTracing(r, tmpXp)
	//log.Println("stack", goxml.New().Stack(1))
	_, err = tmpXp.SchemaValidate(Config.SamlSchema)
	if err != nil {
		dump("raw", bmsg)
		err = goxml.Wrap(err)
		return
	}

	protocol := tmpXp.QueryString(nil, "local-name(/*)")
	var protocolOK bool
	for _, expectedProtocol := range protocols {
		protocolOK = protocolOK || protocol == expectedProtocol
	}

	if !protocolOK {
		err = fmt.Errorf("expected protocol(s) %v not found, got %s", protocols, protocol)
		return
	}

	issuer := tmpXp.Query1(nil, "./saml:Issuer")
	if issuer == "" {
		err = fmt.Errorf("no issuer found in SAMLRequest/SAMLResponse")
		return
	}

	issuerMd, err = issuerMdSet.MDQ(issuer)
	if err != nil {
		return
	}

	destination := tmpXp.Query1(nil, "./@Destination")
	if destination == "" && protocols[0] != "AuthnRequest" {
		err = fmt.Errorf("no destination found in SAMLRequest/SAMLResponse")
		return
	}

	if destination != "" && destination != location {
		err = fmt.Errorf("destination: %s is not here, here is %s", destination, location)
		return
	}

	/*
	       if r.Host == "krib.wayf.dk" {
	           destination = "{sha1}"+strings.Split(r.URL.Path, "/")[1]
	       }
	   q.Q(r.URL.Path, destination)
	*/

	destinationMd, err = destinationMdSet.MDQ(location)
	if err != nil {
		return
	}

	if issuer == "https://eidasconnector.test.eid.digst.dk/idp" {
		destinationMd, err = destinationMdSet.MDQ("https://saml.eidas.wayf.dk")
		if err != nil {
			return
		}
	}

	xp, err = CheckSAMLMessage(r, tmpXp, issuerMd, destinationMd, role, location)
	if err != nil {
		err = goxml.Wrap(err)
		return
	}

	xp, err = checkDestinationAndACS(xp, issuerMd, destinationMd, role, location)
	if err != nil {
		return
	}

	xp, err = VerifyTiming(xp)
	if err != nil {
		return
	}
	return
}

// CheckSAMLMessage checks for Authentication Requests, Reponses and Logout Requests
// Checks for invalid Bindings. Check for Certificates. Verify Signatures
func CheckSAMLMessage(r *http.Request, xp, issuerMd, destinationMd *goxml.Xp, role int, location string) (validatedMessage *goxml.Xp, err error) {
	type protoCheckInfoStruct struct {
		minSignatures     int
		service           string
		signatureElements []string
		checks            []string
	}
	// add checks for xtra element on top level in tests - does schema checks handle that or should we do it here???
	protoChecks := map[string]protoCheckInfoStruct{
		"AuthnRequest": {
			minSignatures:     0,
			service:           "md:SingleSignOnService",
			signatureElements: []string{"/samlp:AuthnRequest[1]/ds:Signature[1]/..]", ""}},
		"Response": {
			minSignatures:     1,
			service:           "md:AssertionConsumerService",
			signatureElements: []string{"/samlp:Response[1]/ds:Signature[1]/..", "/samlp:Response[1]/saml:Assertion[1]/ds:Signature[1]/.."},
			checks:            []string{"count(/samlp:Response/saml:Assertion) = 1", "/samlp:Response/saml:Issuer = /samlp:Response/saml:Assertion/saml:Issuer"}},
		"LogoutRequest": {
			minSignatures:     0,
			service:           "md:SingleLogoutService",
			signatureElements: []string{"/samlp:LogoutRequest[1]/ds:Signature[1]/..", ""}},
		"LogoutResponse": {
			minSignatures:     0,
			service:           "md:SingleLogoutService",
			signatureElements: []string{"/samlp:LogoutResponse[1]/ds:Signature[1]/..", ""}},
	}

	protocol := xp.QueryString(nil, "local-name(/*)")

	bindings := map[string][]string{
		"GET":  {REDIRECT},
		"POST": {POST, SIMPLESIGN},
	}

	var usedBinding string
	validBinding := false

findbinding:
	for _, usedBinding = range bindings[r.Method] {
		for _, v := range destinationMd.QueryMulti(nil, `./`+Roles[role]+`/`+protoChecks[protocol].service+`[@Location=`+strconv.Quote(location)+`]/@Binding`) {
			validBinding = v == usedBinding
			if validBinding {
				break findbinding
			}
		}
	}

	if !validBinding || usedBinding == "" {
		err = errors.New("No valid binding found in metadata")
		return
	}

	if protoChecks[protocol].minSignatures <= 0 {
		return xp, nil
	}

	certificates := issuerMd.QueryMulti(nil, `./`+Roles[(role+1)%2]+SigningCertQuery) // the issuer's role

	if len(certificates) == 0 {
		err = errors.New("no certificates found in metadata")
		return
	}

	if usedBinding == REDIRECT {
		if _, ok := r.Form["SigAlg"]; !ok && protoChecks[protocol].minSignatures <= 0 {
			return xp, nil
		}
		rawValues := parseQueryRaw(r.URL.RawQuery)
		query := ""
		delim := ""
		for _, key := range []string{"SAMLRequest", "SAMLResponse", "RelayState", "SigAlg"} {
			if rw, ok := rawValues[key]; ok {
				query += delim + key + "=" + rw[0]
				delim = "&"
			}
		}

		sigAlg := r.Form.Get("SigAlg") // needed as decoded value
		if _, ok := goxml.Algos[sigAlg]; !ok {
			return nil, goxml.NewWerror("unsupported SigAlg", sigAlg)
		}
		digest := goxml.Hash(goxml.Algos[sigAlg].Algo, query)
		signature, _ := base64.StdEncoding.DecodeString(r.Form.Get("Signature"))
		verified := 0
		signerrors := []error{}
		for _, certificate := range certificates {
			var pub *rsa.PublicKey
			_, pub, err = PublicKeyInfo(certificate)

			if err != nil {
				return nil, goxml.Wrap(err)
			}
			signerror := rsa.VerifyPKCS1v15(pub, goxml.Algos[sigAlg].Algo, digest[:], signature)
			if signerror != nil {
				signerrors = append(signerrors, signerror)
			} else {
				verified++
				break
			}
		}
		if verified != 1 {
			errorstring := ""
			delim := ""
			for _, e := range signerrors {
				errorstring += e.Error() + delim
				delim = ", "
			}
			err = goxml.NewWerror("cause:unable to validate signature", errorstring)
			return
		}
		validatedMessage = xp
	}

	if usedBinding == POST {
		if query := protoChecks[protocol].signatureElements[0]; query != "" {
			signatures := xp.Query(nil, query)
			if len(signatures) == 1 {
				if err = VerifySign(xp, certificates, signatures[0]); err != nil {
					return
				}
				validatedMessage = xp
			}
		}
		if protocol == "Response" {
			encryptedAssertions := xp.Query(nil, "/samlp:Response/saml:EncryptedAssertion")
			if len(encryptedAssertions) == 1 {

				cert := destinationMd.Query1(nil, "./md:SPSSODescriptor"+EncryptionCertQuery) // actual encryption key is always first
				var keyname string
				keyname, _, err = PublicKeyInfo(cert)
				if err != nil {
					return nil, goxml.Wrap(err)
				}
				var privatekey []byte

				privatekey, err = ioutil.ReadFile(Config.CertPath + keyname + ".key")
				if err != nil {
					return nil, goxml.Wrap(err)
				}

				encryptedAssertion := encryptedAssertions[0]
				encryptedData := xp.Query(encryptedAssertion, "xenc:EncryptedData")[0]
				decryptedAssertion, err := xp.Decrypt(encryptedData.(types.Element), privatekey, []byte("-"))
				if err != nil {
					err = goxml.Wrap(err)
					err = goxml.PublicError(err.(goxml.Werror), "cause:encryption error") // hide the real problem from attacker
					return nil, err
				}

				decryptedAssertionElement, _ := decryptedAssertion.Doc.DocumentElement()
				decryptedAssertionElement = xp.CopyNode(decryptedAssertionElement, 1)
				_ = encryptedAssertion.AddPrevSibling(decryptedAssertionElement)
				goxml.RmElement(encryptedAssertion)

				// repeat schemacheck
				_, err = xp.SchemaValidate(Config.SamlSchema)
				if err != nil {
					err = goxml.Wrap(err)
					err = goxml.PublicError(err.(goxml.Werror), "cause:encryption error") // hide the real problem from attacker
					return nil, err
				}
			} else if len(encryptedAssertions) != 0 {
				err = fmt.Errorf("only 1 EncryptedAssertion allowed, %d found", len(encryptedAssertions))
			}
		}
		// Only Responses with an Assertion will have a second signatureElements query
		if query := protoChecks[protocol].signatureElements[1]; query != "" {
			signatures := xp.Query(nil, query)
			if len(signatures) == 1 {
				if err = VerifySign(xp, certificates, signatures[0]); err != nil {
					return nil, goxml.Wrap(err, "err:unable to validate signature")
				}
				//validatedMessage = xp
				// we trust the whole message if the first signature was validated

				if validatedMessage == nil {
					// replace with the validated assertion
					validatedMessage = goxml.NewXp(nil)
					shallowresponse := validatedMessage.CopyNode(xp.Query(nil, "/samlp:Response[1]")[0], 2)
					validatedMessage.Doc.SetDocumentElement(shallowresponse)
					validatedMessage.QueryDashP(nil, "./saml:Issuer", xp.Query1(nil, "/samlp:Response/saml:Issuer"), nil)
					validatedMessage.QueryDashP(nil, "./samlp:Status/samlp:StatusCode/@Value", xp.Query1(nil, "/samlp:Response/samlp:Status/samlp:StatusCode/@Value"), nil)
					shallowresponse.AddChild(validatedMessage.CopyNode(xp.Query(nil, "/samlp:Response[1]/saml:Assertion[1]")[0], 1))
				}
			}
		}
	}

	if usedBinding == SIMPLESIGN {
		return nil, goxml.NewWerror("err:SimpleSign not yet supported")
	}

	// if we don't have a validatedResponse by now we are toast
	if validatedMessage == nil {
		err = goxml.NewWerror("err:no signatures found")
		err = goxml.PublicError(err.(goxml.Werror), "cause:encryption error") // hide the real problem from attacker
		return nil, err
	}

	for _, check := range protoChecks[protocol].checks {
		if !validatedMessage.QueryBool(nil, check) {
			return nil, goxml.NewWerror("cause: check failed", "check: "+check)
		}
	}
	return
}

// checkDestinationAndACS checks for valid destination
// Returns Error Otherwise
func checkDestinationAndACS(message, issuerMd, destinationMd *goxml.Xp, role int, location string) (checkedMessage *goxml.Xp, err error) {
	var checkedDest string
	var acsIndex string
	mdRole := "./" + Roles[role]
	protocol := message.QueryString(nil, "local-name(/*)")
	switch protocol {
	case "AuthnRequest":
		acs := message.Query1(nil, "@AssertionConsumerServiceURL")
		if acs == "" {
			acsIndex := message.Query1(nil, "@AttributeConsumingServiceIndex")
			acs = issuerMd.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@Index=`+strconv.Quote(acsIndex)+`]/@Location`)
		}
		if acs == "" {
			acs = issuerMd.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@Binding="`+POST+`" and (@isDefault="true" or @isDefault!="false" or not(@isDefault))]/@Location`)
		}

		checkedAcs := issuerMd.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@Binding="`+POST+`" and @Location=`+strconv.Quote(acs)+`]/@index`)
		if checkedAcs == "" {
			return nil, goxml.Wrap(ACSError, "acs:"+acs, "acsindex:"+acsIndex)
		}

		// we now have a validated AssertionConsumerService - and Binding - let's put them into the request
		message.QueryDashP(nil, "@AssertionConsumerServiceURL", acs, nil)
		message.QueryDashP(nil, "@ProtocolBinding", POST, nil)
		message.QueryDashP(nil, "@AssertionConsumerServiceIndex", checkedAcs, nil)

		checkedDest = destinationMd.Query1(nil, `./md:IDPSSODescriptor/md:SingleSignOnService[@Binding="`+REDIRECT+`" and @Location=`+strconv.Quote(location)+`]/@Location`)
		if checkedDest == "" {
			checkedDest = destinationMd.Query1(nil, `./md:IDPSSODescriptor/md:SingleSignOnService[@Binding="`+POST+`" and @Location=`+strconv.Quote(location)+`]/@Location`)
		}
	case "LogoutRequest", "LogoutResponse":
		checkedDest = destinationMd.Query1(nil, mdRole+`/md:SingleLogoutService[@Binding="`+REDIRECT+`" and @Location=`+strconv.Quote(location)+`]/@Location`)
	case "Response":
		recipient := message.Query1(nil, "./saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient")

		if recipient == "" {
			err = fmt.Errorf("no receipient found in SubjectConfirmationData")
			return
		}

		if recipient != location {
			err = fmt.Errorf("response.Destination != SubjectConfirmationData.Recipient")
			return
		}

		issuer := message.Query1(nil, "./saml:Issuer") // already checked

		assertionIssuer := message.Query1(nil, "./saml:Assertion/saml:Issuer")
		if assertionIssuer == "" {
			err = fmt.Errorf("no issuer found in Assertion")
			return
		}

		if issuer != assertionIssuer {
			err = fmt.Errorf("response.Issuer != assertion.Issuer not supported")
			return
		}

		rInResponseTo := message.Query1(nil, "./@InResponseTo")
		aInResponseTo := message.Query1(nil, "./saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@InResponseTo")

		if rInResponseTo != aInResponseTo {
			return nil, goxml.NewWerror("cause:InResponseTo not the same in Response and Assertion")
		}
		checkedDest = destinationMd.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@Binding="`+POST+`" and @Location=`+strconv.Quote(location)+`]/@Location`)
	}
	if checkedDest == "" {
		return nil, goxml.NewWerror("Destination is not valid", "destination:"+location)
	}
	checkedMessage = message
	return
}

// parseQueryRaw from src/net/url/url.go - return raw query values - needed for checking signatures
func parseQueryRaw(query string) url.Values {
	m := make(url.Values)
	for query != "" {
		key := query
		if i := strings.IndexAny(key, "&"); i >= 0 {
			key, query = key[:i], key[i+1:]
		} else {
			query = ""
		}
		if key == "" {
			continue
		}
		value := ""
		if i := strings.Index(key, "="); i >= 0 {
			key, value = key[:i], key[i+1:]
		}
		m[key] = append(m[key], value)
	}
	return m
}

// VerifySign takes Certificate, signature and xp as an input
func VerifySign(xp *goxml.Xp, certificates []string, signature types.Node) (err error) {
	publicKeys := []*rsa.PublicKey{}
	for _, certificate := range certificates {
		var key *rsa.PublicKey
		_, key, err = PublicKeyInfo(certificate)
		if err != nil {
			return
		}
		publicKeys = append(publicKeys, key)
	}

	return xp.VerifySignature(signature, publicKeys)
}

// VerifyTiming verify the presence and value of timestamps
func VerifyTiming(xp *goxml.Xp) (verifiedXp *goxml.Xp, err error) {
	const timeskew = 90

	type timing struct {
		required     bool
		notonorafter bool
		notbefore    bool
	}

	now := TestTime
	if now.IsZero() {
		now = time.Now()
	}
	intervalstart := now.Add(-time.Duration(timeskew) * time.Second).UTC()
	intervalend := now.Add(time.Duration(timeskew) * time.Second).UTC()

	var checks map[string]timing

	protocol := xp.QueryString(nil, "local-name(/*)")
	switch protocol {
	case "AuthnRequest", "LogoutRequest", "LogoutResponse":
		checks = map[string]timing{
			"./@IssueInstant": {true, true, true},
		}
	case "Response":
		checks = map[string]timing{
			"/samlp:Response[1]/@IssueInstant": {true, true, true},
			//			"/samlp:Response[1]/saml:Assertion[1]/@IssueInstant":                                                                    timing{true, true, true},
			"/samlp:Response[1]/saml:Assertion[1]/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter": {false, true, false},
			"/samlp:Response[1]/saml:Assertion[1]/saml:Conditions/@NotBefore":                                                       {false, false, true},
			"/samlp:Response[1]/saml:Assertion[1]/saml:Conditions/@NotOnOrAfter":                                                    {false, true, false},
			//			"/samlp:Response[1]/saml:Assertion[1]/saml:AuthnStatement/@AuthnInstant":                                                timing{true, true, true},
			//			"/samlp:Response[1]/saml:Assertion[1]/saml:AuthnStatement/@SessionNotOnOrAfter":                                         timing{false, true, false},
		}
	}

	for q, t := range checks {
		xmltime := xp.Query1(nil, q)
		if t.required && xmltime == "" {
			err = fmt.Errorf("required timestamp: %s not present in: %s", q, protocol)
			return
		}
		if xmltime != "" {
			samltime, err := time.Parse(XsDateTime, xmltime)
			if err != nil {
				return nil, err
			}
			ok := true
			if t.notbefore {
				ok = ok && samltime.Before(intervalend)
			}
			if t.notonorafter {
				ok = ok && intervalstart.Before(samltime)
			}
			if !ok { // Only check if the time is actually there
				err = fmt.Errorf("timing problem: %s  %s < %s <= %s", q, intervalstart, samltime, intervalend)
				return nil, err
			}
		}
	}
	verifiedXp = xp
	return
}

// IdAndTiming for checking the validity
func IdAndTiming() (issueInstant, id, assertionId, assertionNotOnOrAfter, sessionNotOnOrAfter string) {
	now := TestTime
	if now.IsZero() {
		now = time.Now()
	}
	issueInstant = now.Format(XsDateTime)
	assertionNotOnOrAfter = now.Add(4 * time.Minute).Format(XsDateTime)
	sessionNotOnOrAfter = now.Add(4 * time.Hour).Format(XsDateTime)
	id = TestId
	if id == "" {
		id = Id()
	}
	assertionId = TestAssertionId
	if assertionId == "" {
		assertionId = Id()
	}
	return
}

// NewErrorResponse makes a new error response with Entityid, issuer, destination and returns the response
func NewErrorResponse(idpMd, spMd, authnrequest, sourceResponse *goxml.Xp) (response *goxml.Xp) {
	idpEntityID := idpMd.Query1(nil, `/md:EntityDescriptor/@entityID`)
	response = goxml.NewXpFromNode(sourceResponse.DocGetRootElement())
	response.QueryDashP(nil, "./@InResponseTo", authnrequest.Query1(nil, "@ID"), nil)
	response.QueryDashP(nil, "./@Destination", authnrequest.Query1(nil, "@AssertionConsumerServiceURL"), nil)
	response.QueryDashP(nil, "./saml:Issuer", idpEntityID, nil)
	response.Rm(nil, `./saml:Assertion`)
	return
}

// NewLogoutRequest makes a logout request with issuer destination ... and returns a NewRequest
func NewLogoutRequest(issuer, destination, sourceLogoutRequest *goxml.Xp, sloinfo *SLOInfo, role int) (request *goxml.Xp, err error) {
	template := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0"></samlp:LogoutRequest>`
	request = goxml.NewXpFromString(template)
	issueInstant, _, _, _, _ := IdAndTiming()

	slo := destination.Query1(nil, `./`+Roles[role]+`/md:SingleLogoutService[@Binding="`+REDIRECT+`"]/@Location`)
	if slo == "" {
		err = goxml.NewWerror("cause:no SingleLogoutService found", "entityID:"+destination.Query1(nil, "./@entityID"), "binding:"+REDIRECT)
	}
	request.QueryDashP(nil, "./@IssueInstant", issueInstant, nil)
	request.QueryDashP(nil, "./@ID", sourceLogoutRequest.Query1(nil, "@ID"), nil)
	request.QueryDashP(nil, "./@Destination", slo, nil)
	request.QueryDashP(nil, "./saml:Issuer", sloinfo.Is, nil)
	if sourceLogoutRequest.QueryBool(nil, "boolean(./samlp:Extensions/aslo:Asynchronous)") {
		request.QueryDashP(nil, "./samlp:Extensions/aslo:Asynchronous", "", nil)
	}

	request.QueryDashP(nil, "./saml:NameID/@Format", NameIDList[sloinfo.Fo], nil)
	if sloinfo.Sp != "" {
		request.QueryDashP(nil, "./saml:NameID/@SPNameQualifier", sloinfo.De, nil)
	}
	if sloinfo.Si != "" {
		request.QueryDashP(nil, "./samlp:SessionIndex", sloinfo.Si, nil)
	}
	request.QueryDashP(nil, "./saml:NameID", sloinfo.Na, nil)
	return
}

// NewLogoutResponse creates a Logout Response oon the basis of Logout request
func NewLogoutResponse(source, destination, request, sourceResponse *goxml.Xp) (response *goxml.Xp) {
	response = goxml.NewXpFromNode(sourceResponse.DocGetRootElement())
	response.QueryDashP(nil, "./@InResponseTo", request.Query1(nil, "@ID"), nil)
	slo := destination.Query1(nil, `.//md:SingleLogoutService[@Binding="`+REDIRECT+`"]/@Location`)
	response.QueryDashP(nil, "./@Destination", slo, nil)
	idpEntityID := source.Query1(nil, `/md:EntityDescriptor/@entityID`)
	response.QueryDashP(nil, "./saml:Issuer", idpEntityID, nil)
	return
}

// NewSLOInfo extract necessary Logout information
func NewSLOInfo(response, destination *goxml.Xp) *SLOInfo {
	spnq := response.Query1(nil, "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID/@SPNameQualifier")
	if spnq != "" {
		spnq = "-"
	}

	slo := &SLOInfo{Is: response.Query1(nil, "/samlp:Response/saml:Assertion/saml:Issuer"),
		Na: response.Query1(nil, "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID"),
		Fo: NameIDMap[response.Query1(nil, "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID/@Format")],
		Sp: spnq,
		Si: response.Query1(nil, "/samlp:Response/saml:Assertion/saml:AuthnStatement/@SessionIndex"),
		De: destination.Query1(nil, "@entityID")}
	return slo
}

// SignResponse signs the response with the given method.
// Returns an error if unable to sign.
func SignResponse(response *goxml.Xp, elementQuery string, md *goxml.Xp, signingMethod string, signFor int) (err error) {
	cert := md.Query1(nil, "md:IDPSSODescriptor"+SigningCertQuery) // actual signing key is always first
	var keyname string
	keyname, _, err = PublicKeyInfo(cert)
	if err != nil {
		return
	}
	var privatekey []byte
	privatekey, err = ioutil.ReadFile(Config.CertPath + keyname + ".key")
	if err != nil {
		return
	}

	element := response.Query(nil, elementQuery)
	if len(element) != 1 {
		err = errors.New("did not find exactly one element to sign")
		return
	}
	// Put signature before 2nd child - ie. after Issuer
	var before types.Node
	switch signFor {
	case SAMLSign:
		before = response.Query(element[0], "*[2]")[0]
	case WSFedSign:
		before = nil
	}

	err = response.Sign(element[0].(types.Element), before, privatekey, []byte("-"), cert, signingMethod)
	return
}

// NewAuthnRequest - create an AuthnRequest using the supplied metadata for setting the fields according to the following rules:
//  - The Destination is the 1st SingleSignOnService with a redirect binding in the idpmetadata
//  - The AssertionConsumerServiceURL is the Location of the 1st ACS with a post binding in the spmetadata
//  - The ProtocolBinding is post
//  - The Issuer is the entityID in the idpmetadata
//  - The NameID defaults to transient
func NewAuthnRequest(originalRequest, spMd, idpMd *goxml.Xp, idPList []string) (request *goxml.Xp, err error) {
	template := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    Version="2.0"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    >
<saml:Issuer>Issuer</saml:Issuer>
<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true" />
</samlp:AuthnRequest>`
	issueInstant, msgId, _, _, _ := IdAndTiming()

	request = goxml.NewXpFromString(template)
	request.QueryDashP(nil, "./@ID", msgId, nil)
	request.QueryDashP(nil, "./@IssueInstant", issueInstant, nil)
	request.QueryDashP(nil, "./@Destination", idpMd.Query1(nil, `./md:IDPSSODescriptor/md:SingleSignOnService[@Binding="`+REDIRECT+`"]/@Location`), nil)
	request.QueryDashP(nil, "./@AssertionConsumerServiceURL", spMd.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@Binding="`+POST+`"]/@Location`), nil)
	request.QueryDashP(nil, "./saml:Issuer", spMd.Query1(nil, `./@entityID`), nil)
	for _, providerID := range idPList {
		if providerID != "" {
			request.QueryDashP(nil, "./samlp:Scoping/samlp:IDPList/samlp:IDPEntry[0]/@ProviderID", providerID, nil)
		}
	}
	nameIDFormat := ""
	nameIDFormats := NameIDList

	if originalRequest != nil { // already checked for supported nameidformat
		switch originalRequest.Query1(nil, "./@ForceAuthn") {
		case "1", "true":
			request.QueryDashP(nil, "./@ForceAuthn", "true", nil)
		}
		switch originalRequest.Query1(nil, "./@IsPassive") {
		case "1", "true":
			request.QueryDashP(nil, "./@IsPassive", "true", nil)
		}
		//requesterID := originalRequest.Query1(nil, "./saml:Issuer")
		//request.QueryDashP(nil, "./samlp:Scoping/samlp:RequesterID", requesterID, nil)
		if nameIDPolicy := originalRequest.Query1(nil, "./samlp:NameIDPolicy/@Format"); nameIDPolicy != "" {
			nameIDFormats = append([]string{nameIDPolicy}, nameIDFormats...) // prioritize what the SP asked for
		}
	}

	for _, nameIDFormat = range nameIDFormats {
		if found := spMd.Query1(nil, "./md:SPSSODescriptor/md:NameIDFormat[.="+strconv.Quote(nameIDFormat)+"]") != ""; found {
			request.QueryDashP(nil, "./samlp:NameIDPolicy/@Format", nameIDFormat, nil)
			break
		}
	}

	request.QueryDashP(nil, "./samlp:NameIDPolicy/@Format", nameIDFormat, nil)
	return
}

// NewResponse - create a new response using the supplied metadata and resp. authnrequest and response for filling out the fields
// The response is primarily for the attributes, but other fields is eg. the AuthnContextClassRef is also drawn from it
func NewResponse(idpMd, spMd, authnrequest, sourceResponse *goxml.Xp) (response *goxml.Xp) {
	template := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema">
	<saml:Issuer></saml:Issuer>
	<samlp:Status>
		<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
	</samlp:Status>
	<saml:Assertion Version="2.0">
		<saml:Issuer></saml:Issuer>
		<saml:Subject>
			<saml:NameID></saml:NameID>
			<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
				<saml:SubjectConfirmationData/>
			</saml:SubjectConfirmation>
		</saml:Subject>
		<saml:Conditions>
			<saml:AudienceRestriction>
				<saml:Audience>
				</saml:Audience>
			</saml:AudienceRestriction>
		</saml:Conditions>
		<saml:AuthnStatement>
			<saml:AuthnContext>
				<saml:AuthnContextClassRef>
				</saml:AuthnContextClassRef>
			</saml:AuthnContext>
		</saml:AuthnStatement>
	</saml:Assertion>
</samlp:Response>
`
	response = goxml.NewXpFromString(template)

	issueInstant, msgId, assertionId, assertionNotOnOrAfter, sessionNotOnOrAfter := IdAndTiming()
	assertionIssueInstant := issueInstant

	spEntityID := spMd.Query1(nil, `/md:EntityDescriptor/@entityID`)
	idpEntityID := idpMd.Query1(nil, `/md:EntityDescriptor/@entityID`)

	acs := authnrequest.Query1(nil, "@AssertionConsumerServiceURL")
	response.QueryDashP(nil, "./@ID", msgId, nil)
	response.QueryDashP(nil, "./@IssueInstant", issueInstant, nil)
	response.QueryDashP(nil, "./@InResponseTo", authnrequest.Query1(nil, "@ID"), nil)
	response.QueryDashP(nil, "./@Destination", acs, nil)
	response.QueryDashP(nil, "./saml:Issuer", idpEntityID, nil)

	assertion := response.Query(nil, "saml:Assertion")[0]
	response.QueryDashP(assertion, "@ID", assertionId, nil)
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
	response.QueryDashP(authstatement, "@SessionIndex", Id(), nil)
	response.QueryDashP(authstatement, "@SessionNotOnOrAfter", sessionNotOnOrAfter, nil)
	//response.QueryDashP(authstatement, "@SessionIndex", "missing", nil)

	for _, aa := range sourceResponse.QueryMulti(nil, "//saml:AuthnContext/saml:AuthenticatingAuthority") {
		response.QueryDashP(authstatement, "saml:AuthnContext/saml:AuthenticatingAuthority[0]", aa, nil)
	}
	response.QueryDashP(authstatement, "saml:AuthnContext/saml:AuthenticatingAuthority[0]", sourceResponse.Query1(nil, "./saml:Issuer"), nil)
	response.QueryDashP(authstatement, "saml:AuthnContext/saml:AuthnContextClassRef", sourceResponse.Query1(nil, "//saml:AuthnContextClassRef"), nil)
	return
}

// wsfedRequest2samlRequest does the protocol translation from ws-fed to saml
func wsfedRequest2samlRequest(r *http.Request, issuerMdSet, destinationMdSet Md) (msg, relayState string) {
	if r.Form.Get("wa") == "wsignin1.0" {
		relayState = r.Form.Get("wctx")
		issuer := r.Form.Get("wtrealm")
		location := "https://" + r.Host + r.URL.Path
		destinationMd, err := destinationMdSet.MDQ(location)
		if err != nil {
			return
		}
		issuerMd, err := issuerMdSet.MDQ(issuer)
		if err != nil {
			return
		}
		samlrequest, _ := NewAuthnRequest(nil, issuerMd, destinationMd, nil)
		if wreply := r.Form.Get("wreply"); wreply != "" {
            samlrequest.QueryDashP(nil, "./@AssertionConsumerServiceURL", wreply, nil)
		}

        DumpFileIfTracing(r, samlrequest)
		msg = base64.StdEncoding.EncodeToString(Deflate(samlrequest.Dump()))
	}
	return
}

// NewWsFedResponse generates a Ws-fed response
func NewWsFedResponse(idpMd, spMd, sourceResponse *goxml.Xp) (response *goxml.Xp) {
	template := `<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:saml1="urn:oasis:names:tc:SAML:1.0:assertion">
	<t:Lifetime>
		<wsu:Created></wsu:Created>
		<wsu:Expires></wsu:Expires>
	</t:Lifetime>
	<wsp:AppliesTo><wsa:EndpointReference><wsa:Address></wsa:Address></wsa:EndpointReference></wsp:AppliesTo>
	<t:RequestedSecurityToken>
		<saml1:Assertion MajorVersion="1" MinorVersion="1">
			<saml1:Conditions>
				<saml1:AudienceRestrictionCondition><saml1:Audience></saml1:Audience></saml1:AudienceRestrictionCondition>
			</saml1:Conditions>
			<saml1:AttributeStatement>
				<saml1:Subject>
					<saml1:SubjectConfirmation>
						<saml1:ConfirmationMethod>
							urn:oasis:names:tc:saml1:1.0:cm:bearer
						</saml1:ConfirmationMethod>
					</saml1:SubjectConfirmation>
				</saml1:Subject>
			</saml1:AttributeStatement>
			<saml1:AuthenticationStatement>
				<saml1:Subject>
					<saml1:SubjectConfirmation>
						<saml1:ConfirmationMethod>
							urn:oasis:names:tc:SAML:1.0:cm:bearer
						</saml1:ConfirmationMethod>
					</saml1:SubjectConfirmation>
				</saml1:Subject>
			</saml1:AuthenticationStatement>
		</saml1:Assertion>
	</t:RequestedSecurityToken>
	<t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>
	<t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
	<t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>
</t:RequestSecurityTokenResponse>
`
	response = goxml.NewXpFromString(template)

	issueInstant, _, assertionId, assertionNotOnOrAfter, _ := IdAndTiming()
	assertionIssueInstant := issueInstant

	spEntityID := spMd.Query1(nil, `/md:EntityDescriptor/@entityID`)
	idpEntityID := idpMd.Query1(nil, `/md:EntityDescriptor/@entityID`)

	response.QueryDashP(nil, "./t:Lifetime/wsu:Created", issueInstant, nil)
	response.QueryDashP(nil, "./t:Lifetime/wsu:Expires", assertionNotOnOrAfter, nil)
	response.QueryDashP(nil, "./wsp:AppliesTo/wsa:EndpointReference/wsa:Address", spEntityID, nil)

	assertion := response.Query(nil, "t:RequestedSecurityToken/saml1:Assertion")[0]
	response.QueryDashP(assertion, "@AssertionID", assertionId, nil)
	response.QueryDashP(assertion, "@IssueInstant", assertionIssueInstant, nil)
	response.QueryDashP(assertion, "@Issuer", idpEntityID, nil)

	conditions := response.Query(assertion, "saml1:Conditions")[0]
	response.QueryDashP(conditions, "@NotBefore", assertionIssueInstant, nil)
	response.QueryDashP(conditions, "@NotOnOrAfter", assertionNotOnOrAfter, nil)
	response.QueryDashP(conditions, "saml1:AudienceRestrictionCondition/saml1:Audience", spEntityID, nil)

    nameIdentifierElement := sourceResponse.Query(nil, "./saml:Assertion/saml:Subject/saml:NameID")[0]
    nameIdentifier := sourceResponse.Query1(nameIdentifierElement, ".")
    nameIdFormat := sourceResponse.Query1(nameIdentifierElement, "./@Format")

	authstatement := response.Query(assertion, "saml1:AuthenticationStatement")[0]
	response.QueryDashP(authstatement, "@AuthenticationInstant", assertionIssueInstant, nil)
	//response.QueryDashP(authstatement, "@SessionNotOnOrAfter", sessionNotOnOrAfter, nil)
	//response.QueryDashP(authstatement, "@SessionIndex", "missing", nil)
	response.QueryDashP(authstatement, "saml1:Subject/saml1:NameIdentifier", nameIdentifier, nil)
	response.QueryDashP(authstatement, "saml1:Subject/saml1:NameIdentifier/@Format", nameIdFormat, nil)

	authContext := sourceResponse.Query1(nil, "./saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef")
    response.QueryDashP(authstatement, "./@AuthenticationMethod", authContext, nil)

	return
}
