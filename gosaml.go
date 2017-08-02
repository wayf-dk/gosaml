// Gosaml is a library for doing SAML stuff in Go.

package gosaml

import "C"

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"github.com/lestrrat/go-libxml2/types"
    "github.com/wayf-dk/goxml"
)

var _ = log.Printf // For debugging; delete when done.

const (
	xsDateTime   = "2006-01-02T15:04:05Z"
	IdpCertQuery = `./md:IDPSSODescriptor/md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`
	spCertQuery  = `./md:SPSSODescriptor/md:KeyDescriptor[@use="encryption" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`
	samlSchema   = "/home/mz/src/github.com/wayf-dk/gosaml/schemas/saml-schema-protocol-2.0.xsd"
	certPath     = "/etc/ssl/wayf/signing/"

	basic      = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	uri        = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	transient  = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	persistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
)

// Xp is a wrapper for the libxml2 xmlDoc and xmlXpathContext
// master is a pointer to the original struct with the shared
// xmlDoc so that is never gets deallocated before any copies
type (
	Md interface {
		MDQ(key string) (xp *goxml.Xp, err error)
	}

	// IdAndTiming is a type that allows to client to pass the ids and timing used when making
	// new requests and responses - also used for fixed ids and timings when testing
	IdAndTiming struct {
		Now                    time.Time
		Slack, Sessionduration time.Duration
		Id, Assertionid        string
	}
)

// namespaces maps between a ns prefix and the urn/url
var metadatacache = make(map[string]*goxml.Xp)

// PublicKeyInfo extracts the keyname, publickey and cert (base64 DER - no PEM) from the give certificate.
// The keyname is computed from the public key corresponding to running this command: openssl x509 -modulus -noout -in <cert> | openssl sha1.
func PublicKeyInfo(cert string) (keyname string, publickey *rsa.PublicKey, err error) {
	// no pem so no pem.Decode
	key, err := base64.StdEncoding.DecodeString(regexp.MustCompile("\\s").ReplaceAllString(cert, ""))
	pk, err := x509.ParseCertificate(key)
	if err != nil {
		return
	}
	publickey = pk.PublicKey.(*rsa.PublicKey)
	keyname = fmt.Sprintf("%x", sha1.Sum([]byte(fmt.Sprintf("Modulus=%X\n", publickey.N))))
	return
}

/*  NewAuthnRequest - create an AuthnRequest using the supplied metadata for setting the fields according to the following rules:
    - The Destination is the 1st SingleSignOnService with a redirect binding in the idpmetadata
    - The AssertionConsumerServiceURL is Location of the 1st ACS with a post binding in the spmetadata
    - The ProtocolBinding is post
    - The Issuer is the entityID ín the idpmetadata
    - The NameID defaults to transient
*/
func NewAuthnRequest(params IdAndTiming, spmd *goxml.Xp, idpmd *goxml.Xp) (request *goxml.Xp) {
	template := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
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
</samlp:AuthnRequest>`

	issueInstant := params.Now.Format(xsDateTime)
	msgid := params.Id
	if msgid == "" {
		msgid = Id()
	}

	request = goxml.NewXp(template)
	request.QueryDashP(nil, "./@ID", msgid, nil)
	request.QueryDashP(nil, "./@IssueInstant", issueInstant, nil)
	request.QueryDashP(nil, "./@Destination", idpmd.Query1(nil, `//md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location`), nil)
	request.QueryDashP(nil, "./@AssertionConsumerServiceURL", spmd.Query1(nil, `//md:AssertionConsumerService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"]/@Location`), nil)
	request.QueryDashP(nil, "./saml:Issuer", spmd.Query1(nil, `/md:EntityDescriptor/@entityID`), nil)
	return
}

// Utility functions
func (t IdAndTiming) Refresh() IdAndTiming {
	t.Now = time.Now()
	return t
}

// Make a random id
func Id() (id string) {
	b := make([]byte, 21) // 168 bits - just over the 160 bit recomendation without base64 padding
	rand.Read(b)
	return "_" + hex.EncodeToString(b)
}

// Deflate utility that compresses a string using the flate algo
func Deflate(inflated string) []byte {
	var b bytes.Buffer
	w, _ := flate.NewWriter(&b, -1)
	w.Write([]byte(inflated))
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
func Html2SAMLResponse(html []byte) (samlresponse *goxml.Xp) {
	response := goxml.NewHtmlXp(string(html))
	samlbase64 := response.Query1(nil, `//input[@name="SAMLResponse"]/@value`)
	samlxml, _ := base64.StdEncoding.DecodeString(samlbase64)
	samlresponse = goxml.NewXp(string(samlxml))
	return
}

// Url2SAMLRequest extracts the SAMLRequest from an URL
func Url2SAMLRequest(url *url.URL, err error) (samlrequest *goxml.Xp) {
	query := url.Query()
	req, _ := base64.StdEncoding.DecodeString(query["SAMLRequest"][0])
	samlrequest = goxml.NewXp(string(Inflate(req)))
	return
}

// SAMLRequest2Url creates a redirect URL from a saml request
func SAMLRequest2Url(samlrequest *goxml.Xp, privatekey, pw, algo string) (url *url.URL, err error) {
	req := base64.StdEncoding.EncodeToString(Deflate(samlrequest.Doc.Dump(false)))

	url, _ = url.Parse(samlrequest.Query1(nil, "@Destination"))
	q := url.Query()
	q.Set("SAMLRequest", req)

	if privatekey != "" {
		digest := goxml.Hash(goxml.Algos[algo].Algo, req)

		var signaturevalue []byte
		if strings.HasPrefix(privatekey, "hsm:") {
			signaturevalue, err = goxml.SignGoEleven(digest, privatekey, algo)
		} else {
			signaturevalue, err = goxml.SignGo(digest, privatekey, pw, algo)
		}
		signatureval := base64.StdEncoding.EncodeToString(signaturevalue)
		q.Set("SigAlg", goxml.Algos[algo].Signature)
		q.Set("Signature", signatureval)
	}

	url.RawQuery = q.Encode()
	return
}

// CpAndset
func CpAndSet(dest types.Element, doc, md *goxml.Xp, context types.Element, name, value string) {
	sourceNode := md.Query(context, `md:RequestedAttribute[@FriendlyName="`+name+`"]`)[0].(types.Element)
	d, _ := doc.Doc.CreateElementNS(goxml.Namespaces["saml"], "sank;Attribute")
    dest.AddChild(d)
	for _, attr := range []string{"Name", "FriendlyName"} {
	    attribute, _ := sourceNode.GetAttribute(attr)
		d.SetAttribute(attr, attribute.Value())
	}
	d.SetAttribute("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
	doc.QueryDashP(d, `saml:AttributeValue`, value, nil)
}

func AttributeCanonicalDump(xp *goxml.Xp) {
	attrsmap := map[string][]string{}
	keys := []string{}
	attrs := xp.Query(nil, "./saml:Assertion/saml:AttributeStatement/saml:Attribute")
	for _, attr := range attrs {
		values := []string{}
		for _, value := range xp.Query(attr, "saml:AttributeValue") {
			values = append(values, value.NodeValue())
		}
		nameattr, _ := attr.(types.Element).GetAttribute("Name")
		nameformatattr, _ := attr.(types.Element).GetAttribute("NameFormat")
		key := strings.TrimSpace(nameattr.Value() + " " + nameformatattr.Value())
		keys = append(keys, key)
		attrsmap[key] = values
	}

	sort.Strings(keys)
	for _, key := range keys {
		fmt.Println(key)
		values := attrsmap[key]
		sort.Strings(values)
		for _, value := range values {
			if value != "" {
				fmt.Print("    " + value)
			}
			fmt.Println()
		}
	}
}

func GetSAMLMsg(r *http.Request, key string, sendermdsource, memdsource Md, me *goxml.Xp) (xp, md, memd *goxml.Xp, err error) {
	var decryptedassertion types.Element
	request := key == "SAMLRequest"
	response := key == "SAMLResponse"
	location := "https://" + r.Host + r.URL.Path
	if request {
		memd, err = memdsource.MDQ(location)
		if err != nil {
			return
		}
	}

	r.ParseForm()
	redirect := r.URL.Query().Get(key) != ""
	post := r.PostForm.Get(key) != ""
	//postsimplesign := r.PostForm.Get("Signature") != ""

	msg := r.Form.Get(key)
	if msg == "" {
		err = fmt.Errorf("no %s found", key)
		return
	}
	xp, err = DecodeSAMLMsg(msg, redirect)
	if err != nil {
		return
	}
	issuer := xp.Query1(nil, "./saml:Issuer")
	if issuer == "" {
		err = fmt.Errorf("no issuer found in %s", key)
		return
	}
	md, err = sendermdsource.MDQ(issuer)
	if err != nil {
		return
	}
	destination := xp.Query1(nil, "./@Destination")
	if destination == "" {
		err = fmt.Errorf("no destination found in %s", key)
		return
	}
	if destination != location {
		err = fmt.Errorf("%s's destination is not here")
		return
	}
	encryptedAssertions := xp.Query(nil, "./saml:EncryptedAssertion")
	if len(encryptedAssertions) == 1 {
		cert := me.Query1(nil, spCertQuery) // actual encryption key is always first
		var keyname string
		keyname, _, err = PublicKeyInfo(cert)
		if err != nil {
			return
		}
		var privatekey []byte
		privatekey, err = ioutil.ReadFile(certPath + keyname + ".key")
		if err != nil {
			return
		}

		block, _ := pem.Decode([]byte(privatekey))
		/*
		   if pw != "-" {
		       privbytes, _ := x509.DecryptPEMBlock(block, []byte(pw))
		       priv, _ = x509.ParsePKCS1PrivateKey(privbytes)
		   } else {
		       priv, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
		   }
		*/
		priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

		xp.Decrypt(encryptedAssertions[0].(types.Element), priv)
		xp = goxml.NewXp(xp.Doc.Dump(false))
		// repeat schemacheck
		_, err = xp.SchemaValidate(samlSchema)
		if err != nil {
			return
		}
	} else if len(encryptedAssertions) != 0 {
		err = fmt.Errorf("only 1 EncryptedAssertion allowed, %d found", len(encryptedAssertions))
	}

	if redirect {
		if response {
			err = errors.New("no suppport for redirect binding for responses")
			return
		}
	} else if post {
		if response {
			//no ds:Object in signatures
			certificates := md.Query(nil, IdpCertQuery)
			if len(certificates) == 0 {
				err = errors.New("no certificates found in metadata")
				return
			}
			signatures := xp.Query(nil, "(/samlp:Response[ds:Signature] | /samlp:Response/saml:Assertion[ds:Signature])")
			if decryptedassertion != nil {
				//signatures = append(signatures, decryptedassertion)
			}
			if len(signatures) == 0 {
				err = errors.New("Neither the assertion nor the response was signed.")
				return
			}
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
		}
	} else {
		err = errors.New("could not find a supported binding")
	}
	if request {
		acs := xp.Query1(nil, "@AssertionConsumerServiceURL")
		validacs := len(md.Query(nil, "./md:SPSSODescriptor/md:AssertionConsumerService[@Location='"+acs+"']")) == 1
		log.Println("acs", acs, validacs)
		if acs == "" || !validacs {
			err = fmt.Errorf("AssertionConsumerServiceURL missing or not present in metadata: '%s'", acs)
			return
		}
		subject := xp.Query1(nil, "@Subject")
		if subject != "" {
			err = fmt.Errorf("subject not allowed in %ss", key)
			return
		}
		nameidpolicy := xp.Query1(nil, "./samlp:NameIDPolicy/@Format")
		if nameidpolicy != "" && nameidpolicy != transient && nameidpolicy != persistent {
			err = fmt.Errorf("nameidpolicy format: %s is not supported")
			return
		}
		allowcreate := xp.Query1(nil, "./samlp:NameIDPolicy/@AllowCreate")
		if allowcreate != "true" {
			err = fmt.Errorf("only supported value for NameIDPolicy @AllowCreate is true, got: %s", allowcreate)
			return
		}
	}
	if response {
		// one minute skew allowed
		now := time.Now().Add(time.Duration(1) * time.Minute).UTC().Format("2006-01-02T15:04:05Z")
		checks := map[string]bool{
			// "/samlp:Response[1]/saml:Assertion[1]/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotBefore": true ,
			"/samlp:Response[1]/saml:Assertion[1]/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter": false,
			"/samlp:Response[1]/saml:Assertion[1]/saml:Conditions/@NotBefore":                                                       true,
			"/samlp:Response[1]/saml:Assertion[1]/saml:Conditions/@NotOnOrAfter":                                                    false,
			"/samlp:Response[1]/saml:Assertion[1]/saml:AuthnStatement/@SessionNotOnOrAfter":                                         false,
		}
		for q, i := range checks {
			samltime := xp.Query1(nil, q)
			cmp := samltime < now
			if samltime == "" || cmp != i {
				err = fmt.Errorf("timing problem: %s = '%s', now = %s", q, samltime, now)
				return
			}
		}
	}
	return
}

func DecodeSAMLMsg(msg string, deflate bool) (xp *goxml.Xp, err error) {
	bmsg, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return
	}
	if deflate {
		bmsg = Inflate(bmsg)
	}
	xp = goxml.NewXp(string(bmsg))
	_, err = xp.SchemaValidate(samlSchema)
	// go thing - actually returns err from schemavalidate ...
	return
}

func SignResponse(response *goxml.Xp, elementQuery string, md *goxml.Xp) (err error) {
	cert := md.Query1(nil, IdpCertQuery) // actual signing key is always first
	var keyname string
	keyname, _, err = PublicKeyInfo(cert)
	if err != nil {
		return
	}
	var privatekey []byte
	privatekey, err = ioutil.ReadFile(certPath + keyname + ".key")
	if err != nil {
		return
	}

	element := response.Query(nil, elementQuery)
	if len(element) != 1 {
		err = errors.New("did not find exactly one element to sign")
		return
	}
	err = response.Sign(element[0].(types.Element), string(privatekey), "-", cert, "sha1")
	return
}

/**
   NewResponse - create a new response using the supplied metadata and resp. authnrequest and response for filling out the fields
   The response is primarily for the attributes, but other fields is eg. the AuthnContextClassRef is also drawn from it
*/

func NewResponse(params IdAndTiming, idpmd, spmd, authnrequest, sourceResponse *goxml.Xp) (response *goxml.Xp) {
	template := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
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
            <saml:NameID SPNameQualifier=""
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
        <saml:AttributeStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema">
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`

	response = goxml.NewXp(template)

	issueInstant := params.Now.Format(xsDateTime)
	assertionIssueInstant := params.Now.Format(xsDateTime)
	assertionNotOnOrAfter := params.Now.Add(params.Slack).Format(xsDateTime)
	sessionNotOnOrAfter := params.Now.Add(params.Sessionduration).Format(xsDateTime)
	msgid := params.Id
	if msgid == "" {
		msgid = Id()
	}
	assertionID := params.Assertionid
	if assertionID == "" {
		assertionID = Id()
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
	response.QueryDashP(authstatement, "@SessionIndex", "missing", nil)
	response.QueryDashP(authstatement, "saml:AuthnContext/saml:AuthnContextClassRef", sourceResponse.Query1(nil, "//saml:AuthnContextClassRef"), nil)

	sourceResponse = goxml.NewXp(sourceResponse.Doc.Dump(true))
	sourceAttributes := sourceResponse.Query(nil, `//saml:AttributeStatement/saml:Attribute`)
	destinationAttributes := response.Query(nil, `//saml:AttributeStatement`)[0]

	attrcache := map[string]types.Element{}
	for _, attr := range sourceAttributes {
	    name, _ := attr.(types.Element).GetAttribute("Name")
	    friendlyname, _ := attr.(types.Element).GetAttribute("FriendlyName")
		attrcache[name.Value()] = attr.(types.Element)
		if friendlyname != nil {
    		attrcache[friendlyname.Value()] = attr.(types.Element)
    	}
	}

	//requestedAttributes := spmd.Query(nil, `./md:SPSSODescriptor/md:AttributeConsumingService[1]/md:RequestedAttribute[@isRequired=true()]`)
	requestedAttributes := spmd.Query(nil, `./md:SPSSODescriptor/md:AttributeConsumingService[1]/md:RequestedAttribute`)

	for _, requestedAttribute := range requestedAttributes {
		// for _, requestedAttribute := range sourceResponse.Query(nil, `//saml:Attribute`) {
		name, _ := requestedAttribute.(types.Element).GetAttribute("Name")
		friendlyname, _ := requestedAttribute.(types.Element).GetAttribute("FriendlyName")
		//nameFormat := requestedAttribute.GetAttr("NameFormat")
		//log.Println("requestedattribute:", name, nameFormat)
		// look for a requested attribute with the requested nameformat
		// TO-DO - xpath escape name and nameFormat
		// TO-Do - value filtering
		//attributes := sourceResponse.Query(sourceAttributes[0], `saml:Attribute[@Name="`+name+`" or @Name="`+friendlyname+`" or @FriendlyName="`+friendlyname+`"]`)
		//log.Println("src attrs", len(attributes), `saml:Attribute[@Name="`+name+`" or @Name="`+friendlyname+`" or @FriendlyName="`+friendlyname+`"]`)

		//attributes := sourceResponse.Query(sourceAttributes, `saml:Attribute[@Name="`+name+`"]`)
		attribute := attrcache[name.Value()]
		if attribute == nil {
			attribute = attrcache[friendlyname.Value()]
			if attribute == nil {
				continue
			}
		}
		//		for _, attribute := range sourceAttributes {
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
				newAttribute.AddChild(response.CopyNode(valueNode, 1))
			}
		}
		//		}
	}
	return
}
