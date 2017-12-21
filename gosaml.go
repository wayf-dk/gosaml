// Gosaml is a library for doing SAML stuff in Go.

package gosaml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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
	IdPRole = iota
	SPRole  = iota
)

const (
	XsDateTime          = "2006-01-02T15:04:05Z"
	signingCertQuery    = `/md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`
	encryptionCertQuery = `./md:SPSSODescriptor/md:KeyDescriptor[@use="encryption" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`

	Transient  = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	Persistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
)

type (
	// Interface for metadata provider
	Md interface {
		MDQ(key string) (xp *goxml.Xp, err error)
	}

	Conf struct {
		SamlSchema    string
		CertPath      string
		NameIDFormats []string
	}

	SLOInfo struct {
		EntityID, NameID, Format, SPNameQualifier, Issuer string
	}

	SLOInfoMap interface {
		GetSLOInfo(http.ResponseWriter, *http.Request, string) *SLOInfo
		PutSLOInfo(http.ResponseWriter, *http.Request, string, *SLOInfo)
	}
)

var (
	TestTime                time.Time
	TestId, TestAssertionId string
	Roles                   = []string{"md:IDPSSODescriptor", "md:SPSSODescriptor"}
	Config                  = Conf{}
	ACSError                = errors.New("invalid AsssertionConsumerService or AsssertionConsumerServiceIndex")
)

// PublicKeyInfo extracts the keyname, publickey and cert (base64 DER - no PEM) from the given certificate.
// The keyname is computed from the public key corresponding to running this command: openssl x509 -modulus -noout -in <cert> | openssl sha1.
func PublicKeyInfo(cert string) (keyname string, publickey *rsa.PublicKey, err error) {
	// no pem so no pem.Decode
	key, err := base64.StdEncoding.DecodeString(regexp.MustCompile("\\s").ReplaceAllString(cert, ""))
	pk, err := x509.ParseCertificate(key)
	if err != nil {
		return
	}
	publickey = pk.PublicKey.(*rsa.PublicKey)
	keyname = fmt.Sprintf("%x", goxml.Hash(crypto.SHA1, fmt.Sprintf("Modulus=%X\n", publickey.N)))
	return
}

// Make a random id
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

	req := base64.StdEncoding.EncodeToString(Deflate([]byte(samlrequest.Doc.Dump(false))))

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

func AttributeCanonicalDump(w io.Writer, xp *goxml.Xp) {
	attrsmap := map[string][]string{}
	keys := []string{}
	attrs := xp.Query(nil, "./saml:Assertion/saml:AttributeStatement/saml:Attribute")
	for _, attr := range attrs {
		values := []string{}
		for _, value := range xp.Query(attr, "saml:AttributeValue") {
			values = append(values, value.NodeValue())
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
				fmt.Fprint(w, "    "+strings.TrimSpace(value))
			}
			fmt.Fprintln(w)
		}
	}
}

func ReceiveAuthnRequest(r *http.Request, issuerMdSet, destinationMdSet Md) (xp, md, memd *goxml.Xp, relayState string, err error) {
	xp, md, memd, relayState, err = DecodeSAMLMsg(r, issuerMdSet, destinationMdSet, IdPRole, []string{"AuthnRequest"}, true)
	if err != nil {
		return
	}
	subject := xp.Query1(nil, "./saml:Subject")
	if subject != "" {
		err = fmt.Errorf("subject not allowed in SAMLRequest")
		return
	}
	nameidpolicy := xp.Query1(nil, "./samlp:NameIDPolicy/@Format")
	if nameidpolicy != "" && nameidpolicy != Transient && nameidpolicy != Persistent {
		err = fmt.Errorf("nameidpolicy format: %s is not supported", nameidpolicy)
		return
	}
	/*
		allowcreate := xp.Query1(nil, "./samlp:NameIDPolicy/@AllowCreate")
		if allowcreate != "true" && allowcreate != "1" {
			err = fmt.Errorf("only supported value for NameIDPolicy @AllowCreate is true/1, got: %s", allowcreate)
			return
		}
	*/
	return
}

// ReceiveSAMLResponse handles the SAML minutiae when receiving a SAMLResponse
// Currently the only supported binding is POST
// Receives the metadatasets for resp. the sender and the receiver
// For
// Returns metadata for the sender and the receiver
func ReceiveSAMLResponse(r *http.Request, issuerMdSet, destinationMdSet Md) (xp, md, memd *goxml.Xp, relayState string, err error) {
	xp, md, memd, relayState, err = DecodeSAMLMsg(r, issuerMdSet, destinationMdSet, SPRole, []string{"Response"}, true)
	if err != nil {
		return
	}
	return
}

func ReceiveLogoutMessage(r *http.Request, issuerMdSet, destinationMdSet Md, role int) (xp, md, memd *goxml.Xp, relayState string, err error) {
	xp, md, memd, relayState, err = DecodeSAMLMsg(r, issuerMdSet, destinationMdSet, role, []string{"LogoutRequest", "LogoutResponse"}, true)
	if err != nil {
		return
	}
	return
}

func DecodeSAMLMsg(r *http.Request, issuerMdSet, destinationMdSet Md, role int, protocols []string, checkDestination bool) (xp, issuerMd, destinationMd *goxml.Xp, relayState string, err error) {

	defer r.Body.Close()
	r.ParseForm()
	method := r.Method

	relayState = r.Form.Get("RelayState")

	msg := r.Form.Get("SAMLRequest")
	if msg == "" {
		msg = r.Form.Get("SAMLResponse")
		if msg == "" {
			err = fmt.Errorf("no SAMLRequest/SAMLResponse found")
			return
		}
	}

	bmsg, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return
	}
	if method == "GET" {
		bmsg = Inflate(bmsg)
	}

	xp = goxml.NewXp(bmsg)
	//log.Println("stack", goxml.New().Stack(1))
	//log.Println("DecodeSAMLMsg", xp.PP())
	_, err = xp.SchemaValidate(Config.SamlSchema)
	if err != nil {
		err = goxml.Wrap(err)
		//log.Println("schemaerrors", errs)
		//q.Q(xp.PP())
		return
	}

	protocol := xp.QueryString(nil, "local-name(/*)")
	var protocolOK bool
	for _, expectedProtocol := range protocols {
		protocolOK = protocolOK || protocol == expectedProtocol
	}

	if !protocolOK {
		err = fmt.Errorf("expected protocol(s) %v not found, got %s", protocols, protocol)
		return
	}

	issuer := xp.Query1(nil, "./saml:Issuer")
	if issuer == "" {
		err = fmt.Errorf("no issuer found in SAMLRequest/SAMLResponse")
		return
	}
	issuerMd, err = issuerMdSet.MDQ(issuer)
	if err != nil {
		return
	}

	destination := xp.Query1(nil, "./@Destination")
	if destination == "" {
		err = fmt.Errorf("no destination found in SAMLRequest/SAMLResponse")
		return
	}

	if checkDestination {
		location := "https://" + r.Host + r.URL.Path

		if destination != location {
			err = fmt.Errorf("destination: %s is not here, here is %s", destination, location)
			return
		}
	}

	destinationMd, err = destinationMdSet.MDQ(destination)
	if err != nil {
		return
	}

	err = CheckSAMLMessage(r, xp, issuerMd, destinationMd, role)

	return
}

func CheckSAMLMessage(r *http.Request, xp, md, memd *goxml.Xp, role int) (err error) {

	providedSignatures := 0

	// Look for Bindings for the destination in metadata
	// We don't check that we are the destination here - that should be done in the specific Functions,
	// otherwise we won't be able to let responses go to a test sp
	service := ""
	minSignatures := 1
	switch xp.QueryString(nil, "local-name(/*)") {
	case "LogoutRequest", "LogoutResponse":
		minSignatures = 0
		service = "md:SingleLogoutService"
	case "Response":
		service = "md:AssertionConsumerService"
	case "AuthnRequest":
		minSignatures = 0
		service = "md:SingleSignOnService"
	}

	bindings := map[string]string{
		"GET":  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		"POST": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
	}
	usedBinding := bindings[r.Method]

	checkSignatures := minSignatures > 0
	mdRole := Roles[role]
	destination := xp.Query1(nil, "./@Destination")

	validBinding := false
	for _, v := range memd.QueryMulti(nil, `./`+mdRole+`/`+service+`[@Location=`+strconv.Quote(destination)+`]/@Binding`) {
		validBinding = validBinding || v == usedBinding
	}

	if !validBinding || usedBinding == "" {
		err = errors.New("invalid binding used " + usedBinding)
		return
	}

	certificates := md.Query(nil, `./`+Roles[(role+1)%2]+signingCertQuery) // the issuer's role

	if len(certificates) == 0 {
		err = errors.New("no certificates found in metadata")
		return
	}

	if checkSignatures && usedBinding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" {
		sigAlg := ""
		rawValues := parseQueryRaw(r.URL.RawQuery)
		q := ""
		if _, ok := rawValues["SAMLRequest"]; ok {
			q += "SAMLRequest=" + rawValues["SAMLRequest"][0]
		}
		if _, ok := rawValues["SAMLResponse"]; ok {
			q += "SAMLResponse=" + rawValues["SAMLResponse"][0]
		}
		if _, ok := rawValues["RelayState"]; ok {
			q += "&RelayState=" + rawValues["RelayState"][0]
		}
		if _, ok := rawValues["SigAlg"]; ok {
			q += "&SigAlg=" + rawValues["SigAlg"][0]
			sigAlg = r.Form.Get("SigAlg") // needed as decoded value
		}

		digest := goxml.Hash(goxml.Algos[sigAlg].Algo, q)

		verified := 0
		signerrors := []error{}
		for _, certificate := range certificates {
			var pub *rsa.PublicKey
			_, pub, err = PublicKeyInfo(certificate.NodeValue())

			if err != nil {
				return
			}
			signature, _ := base64.StdEncoding.DecodeString(r.Form.Get("Signature"))
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
			err = fmt.Errorf("unable to validate signature: %s", errorstring)
			return
		}
	}

	if usedBinding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" {
		if checkSignatures {
			signatures := xp.Query(nil, "/samlp:Response[1]/ds:Signature[1]/..")
			if len(signatures) == 1 {
				providedSignatures++
				if err = VerifySign(xp, certificates, signatures); err != nil {
					return
				}
			}
		}
		encryptedAssertions := xp.Query(nil, "/samlp:Response/saml:EncryptedAssertion")
		if len(encryptedAssertions) == 1 {

			cert := memd.Query1(nil, encryptionCertQuery) // actual encryption key is always first
			var keyname string
			keyname, _, err = PublicKeyInfo(cert)
			if err != nil {
				return
			}
			var privatekey []byte

			privatekey, err = ioutil.ReadFile(Config.CertPath + keyname + ".key")
			if err != nil {
				return goxml.Wrap(err)
			}

			encryptedAssertion := encryptedAssertions[0]
			encryptedData := xp.Query(encryptedAssertion, "xenc:EncryptedData")[0]
			decryptedAssertion, err := xp.Decrypt(encryptedData.(types.Element), privatekey)
			if err != nil {
				return err
			}

			decryptedAssertionElement, _ := decryptedAssertion.Doc.DocumentElement()
			decryptedAssertionElement = xp.CopyNode(decryptedAssertionElement, 1)
			_ = encryptedAssertion.AddPrevSibling(decryptedAssertionElement)
			parent, _ := encryptedAssertion.ParentNode()
			parent.RemoveChild(encryptedAssertion)

			// repeat schemacheck
			_, err = xp.SchemaValidate(Config.SamlSchema)
			if err != nil {
				return err
			}
		} else if len(encryptedAssertions) != 0 {
			err = fmt.Errorf("only 1 EncryptedAssertion allowed, %d found", len(encryptedAssertions))
		}

		//no ds:Object in signatures
		if checkSignatures {
			signatures := xp.Query(nil, "/samlp:Response[1]/saml:Assertion[1]/ds:Signature[1]/..")
			if len(signatures) == 1 {
				providedSignatures++
				if err = VerifySign(xp, certificates, signatures); err != nil {
					return
				}
			}
		}
	}

	if providedSignatures < minSignatures {
		err = fmt.Errorf("No signatures found")
		return
	}

	err = checkDestinationAndACS(xp, md, memd, role)
	if err != nil {
		return
	}

	err = VerifyTiming(xp)
	if err != nil {
		return
	}

	return
}

// ReceiveAuthnRequest handles the SAML minutiae when receiving a SAMLRequest
// Supports POST and Redirect bindings
// Receives the metadatasets for resp. the sender and the receiver
// Returns metadata for the sender and the receiver
func checkDestinationAndACS(message, issuer, destination *goxml.Xp, role int) (err error) {
	var checkedDest string
	var acsIndex string
	dest := message.Query1(nil, "./@Destination")
	mdRole := "./" + Roles[role]
	protocol := message.QueryString(nil, "local-name(/*)")
	switch protocol {
	case "AuthnRequest":
		acs := message.Query1(nil, "@AssertionConsumerServiceURL")
		if acs == "" {
			acsIndex := message.Query1(nil, "@AttributeConsumingServiceIndex")
			acs = issuer.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@Index=`+strconv.Quote(acsIndex)+`]/@Location`)
		}

		checkedAcs := issuer.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" and @Location=`+strconv.Quote(acs)+`]/@Location`)
		if checkedAcs == "" {
			return goxml.Wrap(ACSError, "acs:"+acs, "acsindex:"+acsIndex)
		}
		checkedDest = destination.Query1(nil, `./md:IDPSSODescriptor/md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" and @Location=`+strconv.Quote(dest)+`]/@Location`)
		if checkedDest == "" {
			checkedDest = destination.Query1(nil, `./md:IDPSSODescriptor/md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" and @Location=`+strconv.Quote(dest)+`]/@Location`)
		}
	case "LogoutRequest":
		checkedDest = destination.Query1(nil, mdRole+`/md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" and @Location=`+strconv.Quote(dest)+`]/@Location`)
	case "LogoutResponse":
		checkedDest = destination.Query1(nil, mdRole+`/md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" and @Location=`+strconv.Quote(dest)+`]/@Location`)
	case "Response":
		checkedDest = destination.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" and @Location=`+strconv.Quote(dest)+`]/@Location`)
	}
	if checkedDest == "" {
		err = fmt.Errorf("Destination: %s is not valid", dest)
	}
	return
}

/**
  From src/net/url/url.go - return raw query values - needed for checking signatures

*/
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

// Function to verify Signature
// Takes Certificate, signature and xp as an input
func VerifySign(xp *goxml.Xp, certificates, signatures types.NodeList) (err error) {
	verified := 0
	signerrors := []error{}
	for _, certificate := range certificates {

		var key *rsa.PublicKey
		_, key, err = PublicKeyInfo(certificate.NodeValue())

		if err != nil {
			return
		}

		for _, signature := range signatures {
			signerror := xp.VerifySignature(signature.(types.Element), key)
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
	return
}

/**
  Verify the presence and value of timestamps
*/
func VerifyTiming(xp *goxml.Xp) (err error) {
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
			"./@IssueInstant": timing{true, true, true},
		}
	case "Response":
		checks = map[string]timing{
			"/samlp:Response[1]/@IssueInstant":                                                                                      timing{true, true, true},
//			"/samlp:Response[1]/saml:Assertion[1]/@IssueInstant":                                                                    timing{true, true, true},
			"/samlp:Response[1]/saml:Assertion[1]/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter": timing{false, true, false},
			"/samlp:Response[1]/saml:Assertion[1]/saml:Conditions/@NotBefore":                                                       timing{false, false, true},
			"/samlp:Response[1]/saml:Assertion[1]/saml:Conditions/@NotOnOrAfter":                                                    timing{false, true, false},
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
				return err
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
				return err
			}
		}
	}
	return
}

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

func NewErrorResponse(idpmd, spmd, authnrequest, sourceResponse *goxml.Xp) (response *goxml.Xp) {
	idpEntityID := idpmd.Query1(nil, `/md:EntityDescriptor/@entityID`)
	response = goxml.NewXpFromNode(*sourceResponse.DocGetRootElement())
	acs := authnrequest.Query1(nil, "@AssertionConsumerServiceURL")
	response.QueryDashP(nil, "./@InResponseTo", authnrequest.Query1(nil, "@ID"), nil)
	response.QueryDashP(nil, "./@Destination", acs, nil)
	response.QueryDashP(nil, "./saml:Issuer", idpEntityID, nil)
	return
}

func NewLogoutRequest(issuer, destination, sourceLogoutRequest *goxml.Xp, sloinfo *SLOInfo) (request *goxml.Xp) {
	template := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0"></samlp:LogoutRequest>`
	request = goxml.NewXpFromString(template)
	issueInstant, _, _, _, _ := IdAndTiming()

	slo := destination.Query1(nil, `/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location`)
	request.QueryDashP(nil, "./@IssueInstant", issueInstant, nil)
	request.QueryDashP(nil, "./@ID", sourceLogoutRequest.Query1(nil, "@ID"), nil)
	request.QueryDashP(nil, "./@Destination", slo, nil)
	request.QueryDashP(nil, "./saml:Issuer", sloinfo.Issuer, nil)
	request.QueryDashP(nil, "./saml:NameID/@Format", sloinfo.Format, nil)
	request.QueryDashP(nil, "./saml:NameID/@SPNameQualifier", sloinfo.SPNameQualifier, nil)
	request.QueryDashP(nil, "./saml:NameID", sloinfo.NameID, nil)
	return
}

func NewLogoutResponse(source, destination, request, sourceResponse *goxml.Xp) (response *goxml.Xp) {
	response = goxml.NewXpFromNode(*sourceResponse.DocGetRootElement())
	response.QueryDashP(nil, "./@InResponseTo", request.Query1(nil, "@ID"), nil)
	slo := destination.Query1(nil, `.//md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location`)
	response.QueryDashP(nil, "./@Destination", slo, nil)
	idpEntityID := source.Query1(nil, `/md:EntityDescriptor/@entityID`)
	response.QueryDashP(nil, "./saml:Issuer", idpEntityID, nil)
	return
}

func NewSLOInfo(response, destination *goxml.Xp) *SLOInfo {
	entityID := response.Query1(nil, "/samlp:Response/saml:Assertion/saml:Issuer")
	nameID := response.Query1(nil, "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID")
	format := response.Query1(nil, "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID/@Format")
	spnamequalifier := response.Query1(nil, "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID/@SPNameQualifier")
	issuer := destination.Query1(nil, "@entityID")
	return &SLOInfo{NameID: nameID, EntityID: entityID, Format: format, SPNameQualifier: spnamequalifier, Issuer: issuer}
}

func NameIDHash(xp *goxml.Xp, tag string) string {
	nameID := xp.Query1(nil, "//saml:NameID")
	format := xp.Query1(nil, "//saml:NameID/@Format")
	spNameQualifier := xp.Query1(nil, "//saml:NameID/@SPNameQualifier")
	return fmt.Sprintf("%x", goxml.Hash(crypto.SHA1, tag+"#"+nameID+"#"+format+"#"+spNameQualifier))
}

func SignResponse(response *goxml.Xp, elementQuery string, md *goxml.Xp) (err error) {
	cert := md.Query1(nil, "md:IDPSSODescriptor"+signingCertQuery) // actual signing key is always first
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
	before := response.Query(element[0], "*[2]")[0]
	err = response.Sign(element[0].(types.Element), before.(types.Element), privatekey, []byte("-"), cert, "sha1")
	return
}

/*  NewAuthnRequest - create an AuthnRequest using the supplied metadata for setting the fields according to the following rules:
    - The Destination is the 1st SingleSignOnService with a redirect binding in the idpmetadata
    - The AssertionConsumerServiceURL is the Location of the 1st ACS with a post binding in the spmetadata
    - The ProtocolBinding is post
    - The Issuer is the entityID ín the idpmetadata
    - The NameID defaults to transient
*/
func NewAuthnRequest(originalRequest, spmd, idpmd *goxml.Xp, providerID string) (request *goxml.Xp, err error) {
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
	request.QueryDashP(nil, "./@Destination", idpmd.Query1(nil, `//md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location`), nil)
	request.QueryDashP(nil, "./@AssertionConsumerServiceURL", spmd.Query1(nil, `//md:AssertionConsumerService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"]/@Location`), nil)
	request.QueryDashP(nil, "./saml:Issuer", spmd.Query1(nil, `/md:EntityDescriptor/@entityID`), nil)
	if providerID != "" {
		request.QueryDashP(nil, "./samlp:Scoping/samlp:IDPList/samlp:IDPEntry/@ProviderID", providerID, nil)
	}
	found := false
	nameIDFormat := ""
	nameIDFormats := Config.NameIDFormats

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
			nameIDFormats = append([]string{nameIDPolicy}, nameIDFormats...)
		}
	}

	for _, nameIDFormat = range nameIDFormats {
		if found = idpmd.Query1(nil, "./md:IDPSSODescriptor/md:NameIDFormat[.='"+nameIDFormat+"']") != ""; found {
			break
		}
	}
	if !found {
		err = errors.New("no supported NameID format")
		return
	}

    nameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
	request.QueryDashP(nil, "./samlp:NameIDPolicy/@Format", nameIDFormat, nil)
	return
}

/**
  NewResponse - create a new response using the supplied metadata and resp. authnrequest and response for filling out the fields
  The response is primarily for the attributes, but other fields is eg. the AuthnContextClassRef is also drawn from it
*/
func NewResponse(idpmd, spmd, authnrequest, sourceResponse *goxml.Xp) (response *goxml.Xp) {
	template := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema">
	<saml:Issuer></saml:Issuer>
	<samlp:Status>
		<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
	</samlp:Status>
	<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">
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

	spEntityID := spmd.Query1(nil, `/md:EntityDescriptor/@entityID`)
	idpEntityID := idpmd.Query1(nil, `/md:EntityDescriptor/@entityID`)

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
	response.QueryDashP(authstatement, "@SessionNotOnOrAfter", sessionNotOnOrAfter, nil)
	//response.QueryDashP(authstatement, "@SessionIndex", "missing", nil)

	response.QueryDashP(authstatement, "saml:AuthnContext/saml:AuthenticatingAuthority", sourceResponse.Query1(nil, "./saml:Issuer"), nil)
	response.QueryDashP(authstatement, "saml:AuthnContext/saml:AuthnContextClassRef", sourceResponse.Query1(nil, "//saml:AuthnContextClassRef"), nil)

	//sourceResponse = goxml.NewXpFromString(sourceResponse.Doc.Dump(true))
	sourceAttributes := sourceResponse.Query(nil, `//saml:AttributeStatement/saml:Attribute`)

	attrcache := map[string]types.Element{}
	for _, attr := range sourceAttributes {
		name, _ := attr.(types.Element).GetAttribute("Name")
		friendlyname, _ := attr.(types.Element).GetAttribute("FriendlyName")
		attrcache[name.Value()] = attr.(types.Element)
		if friendlyname != nil {
			attrcache[friendlyname.Value()] = attr.(types.Element)
		}
	}

	requestedAttributes := spmd.Query(nil, `./md:SPSSODescriptor/md:AttributeConsumingService[1]/md:RequestedAttribute`)

	destinationAttributes := response.QueryDashP(nil, `/saml:Assertion/saml:AttributeStatement`, "", nil) // only if there are actually some requested attributes
	for _, requestedAttribute := range requestedAttributes {

		name, _ := requestedAttribute.(types.Element).GetAttribute("Name")
		attribute := attrcache[name.Value()]
		if attribute == nil {
			friendlyname, _ := requestedAttribute.(types.Element).GetAttribute("FriendlyName")
			attribute = attrcache[friendlyname.Value()]
			if attribute == nil {
				continue
			}
		}
		newAttribute := response.CopyNode(attribute, 2)
		destinationAttributes.AddChild(newAttribute)
		allowedValues := spmd.Query(requestedAttribute, `saml:AttributeValue`)
		allowedValuesMap := make(map[string]bool)
		for _, value := range allowedValues {
			allowedValuesMap[value.NodeValue()] = true
		}
		for _, valueNode := range sourceResponse.Query(attribute, `saml:AttributeValue`) {
			value := valueNode.NodeValue()
			if len(allowedValues) == 0 || allowedValuesMap[value] {
				valueNode := response.CopyNode(valueNode, 1)
				newAttribute.AddChild(valueNode)
			}
		}
	}
	return
}
