// Gosaml is a library for doing SAML stuff in Go.

package gosaml

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"html/template"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/goxml"
	"golang.org/x/crypto/curve25519"
	"x.config"
)

var (
	_ = log.Printf // For debugging; delete when done.
)

const (
	// IDPRole used to set the role as an IDP
	IDPRole = iota
	// SPRole used to set the role as an SP
	SPRole
)

const (
	// SAMLSign for SAML signing
	SAMLSign = iota
	// WSFedSign for WS-Fed signing
	WSFedSign
)

const (
	// XsDateTime Setting the Date Time
	XsDateTime = "2006-01-02T15:04:05Z"
	// SigningCertQuery refers to get the key from the metadata
	SigningCertQuery = `/md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`
	// EncryptionCertQuery refers to encryption key
	EncryptionCertQuery = `/md:KeyDescriptor[@use="encryption" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`
	SPEnc               = "md:SPSSODescriptor" + EncryptionCertQuery
	IdPEnc              = "md:IDPSODescriptor" + EncryptionCertQuery
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
	// Allowed slack for timingchecks
	timeskew = 90
)

type (
	// SamlRequest - compact representation of a request across the hub
	SamlRequest struct {
		Nonce, RequestID, SP, IDP, VirtualIDP, WAYFSP, AssertionConsumerIndex, Protocol, IDPProtocol string
		NameIDFormat, SPIndex, HubBirkIndex                                                          uint8
	}

	// Md Interface for metadata provider
	Md interface {
		MDQ(key string) (xp *goxml.Xp, err error)
	}

	// MdSets slice of Md sets - for searching one MD at at time and remembering the index
	MdSets []Md

	// SLOInfo refers to Single Logout information
	SLOInfo struct {
		IDP, SP, NameID, SPNameQualifier, SessionIndex, ID, Protocol string
		NameIDFormat, HubRole, SLOStatus                             uint8
		SLOSupport, Async                                            bool
	}

	SLOInfoList []SLOInfo

	// Formdata for passing parameters to display template
	Formdata struct {
		AcsURL                                   template.URL
		Acs, Samlresponse, Samlrequest, Id_token string
		RelayState, SigAlg, Signature            string
		Protocol                                 string
		SLOStatus                                string
		Ard                                      template.JS
		Initial                                  bool
	}

	// Hm - HMac struct
	Hm struct {
		TTL  int64
		Hash func() hash.Hash
		Key  []byte
	}

	nemLog struct {
		lock       sync.Mutex
		file       *os.File
		crypt      *cipher.StreamWriter
		writer     *gzip.Writer
		hash       hash.Hash
		name       string
		counter    int
		slot       int64
		peerPublic []byte
	}
)

var (
	// TestTime refers to global testing time
	TestTime, ZeroTime time.Time
	// TestID for testing
	TestID string
	// TestAssertionID for testing
	TestAssertionID string
	// Roles refers to defining roles for SPs and IDPs
	Roles = []string{"md:IDPSSODescriptor", "md:SPSSODescriptor"}
	// ErrorACS refers error information
	ErrorACS = errors.New("AsssertionConsumerService, AsssertionConsumerServiceIndex, ProtocolBinding combination not found in metadata")
	// NameIDList list of supported nameid formats
	NameIDList = []string{"", Transient, Persistent, X509, Email, Unspecified}
	// NameIDMap refers to mapping the nameid formats
	NameIDMap  = map[string]uint8{"": 1, Transient: 1, Persistent: 2, X509: 3, Email: 4, Unspecified: 5} // Unspecified accepted but not sent upstream
	whitespace = regexp.MustCompile("\\s")
	// PostForm -
	PostForm *template.Template
	// AuthnRequestCookie - shortlived hmaced timelimited data
	AuthnRequestCookie *Hm
	// B2I map for marshalling bool to uint
	B2I             = map[bool]byte{false: 0, true: 1}
	privatekeyLock  sync.RWMutex
	privatekeyCache = map[string]crypto.PrivateKey{}
	NemLog          = &nemLog{}
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

func DebugSettingWithDefault(r *http.Request, name, def string) (res string) {
	res = DebugSetting(r, name)
	if res == "" {
		res = def
	}
	return
}

// DumpFile is for logging requests and responses
func DumpFile(r *http.Request, xp *goxml.Xp) (logtag string) {
	msgType := xp.QueryString(nil, "local-name(/*)")
	logtag = dump(msgType, []byte(fmt.Sprintf("%s\n###\n%s", xp.PP(), goxml.NewWerror("").Stack(1))))
	return
}

// DumpFileIfTracing - check trace flag and and dump if set
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

func (l *nemLog) Write(p []byte) (n int, err error) {
	l.counter += len(p)
	l.hash.Write(p)
	return l.file.Write(p)
}

func (l *nemLog) Init(slot int64) {
	var err error

	hostname, _ := os.Hostname()
	l.slot = slot
	l.name = fmt.Sprintf(config.NemLogNameFormat, hostname, time.Now().Format("2006-01-02T15:04:05.0000000"))
	l.peerPublic, err = base64.StdEncoding.DecodeString(config.NemlogPublic)
	if err != nil {
		config.Logger.Fatalln(err)
	}
	ephemeralPriv := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, ephemeralPriv[:])
	if err != nil {
		config.Logger.Fatalln(err)
	}

	if l.file, err = os.Create(l.name + ".gzip"); err != nil {
		config.Logger.Fatalln(err)
	}

	l.hash = sha512.New()

	var cb cipher.Block
	var iv [aes.BlockSize]byte // blank is ok if key is new every time

	ephemeralPub, err := curve25519.X25519(ephemeralPriv, curve25519.Basepoint)
	if err != nil {
		config.Logger.Fatalln(err)
	}

	sessionkey, err := curve25519.X25519(ephemeralPriv, l.peerPublic)
	if err != nil {
		config.Logger.Fatalln(err)
	}

	if _, err = l.Write([]byte(base64.StdEncoding.EncodeToString(ephemeralPub[:]) + "\n")); err != nil {
		config.Logger.Fatalln(err)
	}

	if cb, err = aes.NewCipher(sessionkey[:]); err != nil {
		config.Logger.Fatalln(err)
	}

	l.crypt = &cipher.StreamWriter{
		S: cipher.NewOFB(cb, iv[:]),
		W: l,
	}

	if l.writer, err = gzip.NewWriterLevel(l.crypt, gzip.BestCompression); err != nil {
		config.Logger.Fatalln(err)
	}
}

func (l *nemLog) Finalize() {
	if l.writer != nil {
		l.writer.Close()
		l.crypt.Close()
		l.file.Close()
		l.writer = nil
		l.counter = 0

		if err := ioutil.WriteFile(l.name+".digest", []byte(fmt.Sprintf("%x %s.gzip\n", l.hash.Sum(nil), l.name)), 0644); err != nil {
			config.Logger.Panic(err)
		}
	}
}

func (l *nemLog) Log(msg, idpMd *goxml.Xp, id string) {
	entityID := idpMd.Query1(nil, `/md:EntityDescriptor/@entityID`)
	if !config.NemLoginRelated[entityID] {
		return
	}
	l.lock.Lock()
	defer l.lock.Unlock()
	slot := time.Now().Unix() / config.NemLogSlotGranularity
	if l.counter >= config.NemLogMaxSize || (l.slot != slot && l.slot != 0) {
		l.Finalize()
	}
	if l.writer == nil {
		l.Init(slot)
	}
	if _, err := l.writer.Write([]byte("\n" + id + "\n")); err != nil {
		config.Logger.Fatalln(err)
	}
	if _, err := l.writer.Write([]byte(msg.PP())); err != nil {
		config.Logger.Fatalln(err)
	}
	return
}

// PublicKeyInfo extracts the keyname, publickey and cert (base64 DER - no PEM) from the given certificate.
// The keyname is computed from the public key corresponding to running this command: openssl x509 -modulus -noout -in <cert> | openssl sha1.
func PublicKeyInfo(cert string) (keyname string, publickey crypto.PublicKey, err error) {
	// no pem so no pem.Decode
	key, err := base64.StdEncoding.DecodeString(whitespace.ReplaceAllString(cert, ""))
	crt, err := x509.ParseCertificate(key)
	if err == nil {
		publickey = crt.PublicKey
	} else {
		publickey, err = x509.ParsePKIXPublicKey(key)
		if err != nil {
			err = goxml.Wrap(err)
			return
		}
	}
	switch pk := publickey.(type) {
	case *rsa.PublicKey:
		keyname = fmt.Sprintf("%x", sha1.Sum([]byte(fmt.Sprintf("Modulus=%X\n", pk.N))))
	case ed25519.PublicKey:
		keyname = fmt.Sprintf("%x", sha1.Sum([]byte(fmt.Sprintf("%X", pk))))
	default:
		panic("unknown type of public key")
	}
	return
}

func PublicKeyInfoByMethod(certs []string, keyType x509.PublicKeyAlgorithm) (keynames, crts []string, publickeys []crypto.PublicKey, err error) {
	for _, cert := range certs {
		var ok bool
		name, publickey, _ := PublicKeyInfo(cert)
		switch publickey.(type) {
		case *rsa.PublicKey:
			ok = keyType == x509.RSA
		case ed25519.PublicKey:
			ok = keyType == x509.Ed25519
		}
		if ok {
			keynames = append(keynames, name)
			publickeys = append(publickeys, publickey)
			crts = append(crts, cert)
		}
	}
	return
}

// GetPrivateKey extract the key from Metadata and builds a name and reads the key
func GetPrivateKey(md *goxml.Xp, path string) (privatekey crypto.PrivateKey, cert string, err error) {
	cert = md.Query1(nil, path)
	keyname, _, err := PublicKeyInfo(cert)
	if err != nil {
		return
	}
	privatekey, err = getPrivateKeyByName(keyname, "")
	return
}

func GetPrivateKeyByMethodWithPW(md *goxml.Xp, path string, keyType x509.PublicKeyAlgorithm, pw string) (privatekey crypto.PrivateKey, cert string, err error) {
	certs := md.QueryMulti(nil, path)
	names, crts, _, _ := PublicKeyInfoByMethod(certs, keyType)
	if len(names) == 0 {
		err = fmt.Errorf("No keys found: %d", keyType)
		return
	}

	privatekey, err = getPrivateKeyByName(names[0], pw)
	cert = crts[0]
	return
}

func GetPrivateKeyByMethod(md *goxml.Xp, path string, keyType x509.PublicKeyAlgorithm) (privatekey crypto.PrivateKey, cert string, err error) {
	return GetPrivateKeyByMethodWithPW(md, path, keyType, "")
}

func getPrivateKeyByName(keyname, pw string) (privatekey crypto.PrivateKey, err error) {
	privatekeyLock.RLock()
	privatekey, ok := privatekeyCache[keyname]
	privatekeyLock.RUnlock()
	if ok {
		return
	}

	pkpem, err := fs.ReadFile(config.PrivateKeys, keyname+".key")
	if err != nil {
		err = goxml.Wrap(err)
		return
	}

	if bytes.HasPrefix(pkpem, []byte("hsm:")) {
		privatekey = goxml.HSMKey(pkpem)
	} else {
		privatekey, err = Pem2PrivateKey(pkpem, pw)
		if err != nil {
			return nil, goxml.Wrap(err)
		}
	}

	privatekeyLock.Lock()
	privatekeyCache[keyname] = privatekey
	privatekeyLock.Unlock()
	return
}

// Pem2PrivateKey converts a PEM encoded private key with an optional password to a *rsa.PrivateKey
func Pem2PrivateKey(privatekeypem []byte, pw string) (pk crypto.PrivateKey, err error) {
	block, _ := pem.Decode(privatekeypem) // not used rest
	derbytes := block.Bytes
	if pw != "" {
		if derbytes, err = x509.DecryptPEMBlock(block, []byte(pw)); err != nil {
			return nil, goxml.Wrap(err)
		}
	}
	if pk, err = x509.ParsePKCS1PrivateKey(derbytes); err != nil {
		if pk, err = x509.ParsePKCS8PrivateKey(derbytes); err != nil {
			return nil, goxml.Wrap(err)
		}
	}
	return
}

// ID makes a random id
func ID() (id string) {
	b := make([]byte, 21) // 168 bits - just over the 160 bit recomendation without base64 padding
	rand.Read(b)
	return "_" + base64.RawURLEncoding.EncodeToString(b)
}

// IDHash to create hash of the id
func IDHash(data string) string {
	return fmt.Sprintf("%.5x", sha1.Sum([]byte(data)))
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

// HTML2SAMLResponse extracts the SAMLResponse from a HTML document
func HTML2SAMLResponse(html []byte) (samlresponse *goxml.Xp, relayState string, action *url.URL) {
	response := goxml.NewHTMLXp(html)
	action, _ = url.Parse(response.Query1(nil, `//form/@action`))
	samlbase64 := response.Query1(nil, `//input[@name="SAMLResponse"]/@value`)
	if samlbase64 != "" {
		relayState = response.Query1(nil, `//input[@name="RelayState"]/@value`)
		samlxml, _ := base64.StdEncoding.DecodeString(samlbase64)
		samlresponse = goxml.NewXp(samlxml)
		return
	}
	samlxml := response.Query1(nil, `//input[@name="wresult"]/@value`)
	if samlxml != "" {
		samlresponse = goxml.NewXp([]byte(samlxml))
		relayState = response.Query1(nil, `//input[@name="wctx"]/@value`)
		return
	}
	return
}

// URL2SAMLRequest extracts the SAMLRequest from an URL
func URL2SAMLRequest(url *url.URL, err error) (samlrequest *goxml.Xp, relayState string) {
	query := url.Query()
	req, _ := base64.StdEncoding.DecodeString(query.Get("SAMLRequest"))
	relayState = query.Get("RelayState")
	samlrequest = goxml.NewXp(Inflate(req))
	return
}

// SAMLRequest2URL creates a redirect URL from a saml request
func SAMLRequest2URL(samlrequest *goxml.Xp, relayState string, privatekey crypto.PrivateKey, algo string) (destination *url.URL, err error) {
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

	if privatekey != nil {
		q += "&SigAlg=" + url.QueryEscape(config.CryptoMethods[algo].SigningMethod)

		digest := goxml.Hash(config.CryptoMethods[algo].Hash, q)

		var signaturevalue []byte
		signaturevalue, err = goxml.Sign(digest, privatekey, algo)
		if err != nil {
			return
		}
		signatureval := base64.StdEncoding.EncodeToString(signaturevalue)
		q += "&Signature=" + url.QueryEscape(signatureval)
	}

	destination.RawQuery = q
	return
}

func SAMLRequest2OIDCRequest(samlrequest *goxml.Xp, relayState, flow string, idpMD *goxml.Xp) (destination *url.URL, err error) {
	destination, err = url.Parse(samlrequest.Query1(nil, "@Destination"))
	if err != nil {
		return
	}

	client_id := samlrequest.Query1(nil, "./saml:Issuer")
	params := url.Values{}
	params.Set("scope", "openid")
	params.Set("response_type", flow) // code id_token
	params.Set("client_id", client_id)
	params.Set("redirect_uri", samlrequest.Query1(nil, "@AssertionConsumerServiceURL"))
	params.Set("response_mode", "form_post")
	params.Set("audience", client_id)
	params.Set("nonce", samlrequest.Query1(nil, "@ID"))
	params.Set("state", relayState)
	if samlrequest.QueryXMLBool(nil, "@ForceAuthn") {
		params.Set("prompt", "login")
	}

	if requesterIDs := samlrequest.QueryMulti(nil, "samlp:Scoping/samlp:RequesterID"); len(requesterIDs) > 0 {
		params.Set("requester_id", strings.Join(requesterIDs, ","))
	}
	//    params.Set("acr_values", "")
	destination.RawQuery = params.Encode()
	return
}

// AttributeCanonicalDump for canonical dump
func AttributeCanonicalDump(w io.Writer, xp *goxml.Xp) {
	attrsmap := map[string][]string{}
	keys := []string{}
	attrs := xp.Query(nil, "./saml:Assertion/saml:AttributeStatement/saml:Attribute | ./t:RequestedSecurityToken/saml1:Assertion/saml1:AttributeStatement/saml1:Attribute")
	for _, attr := range attrs {
		values := []string{}
		for _, value := range xp.QueryMulti(attr, "saml:AttributeValue | saml1:AttributeValue") {
			values = append(values, value)
		}
		name := xp.Query1(attr, "@Name | @AttributeName") + " "
		friendlyName := xp.Query1(attr, "@FriendlyName") + " "
		nameFormat := xp.Query1(attr, "@NameFormat | @AttributeNamespace")
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
func ReceiveAuthnRequest(r *http.Request, issuerMdSets, destinationMdSets MdSets, location string) (xp, issuerMd, destinationMd *goxml.Xp, relayState string, issuerIndex, destinationIndex uint8, err error) {
	xp, issuerMd, destinationMd, relayState, issuerIndex, destinationIndex, err = DecodeSAMLMsg(r, issuerMdSets, destinationMdSets, IDPRole, []string{"AuthnRequest"}, location, nil)
	if err != nil {
		return
	}
	nameIDFormat := xp.Query1(nil, "./samlp:NameIDPolicy/@Format")
	if NameIDMap[nameIDFormat] == 0 {
		err = fmt.Errorf("nameidpolicy format: '%s' is not supported", nameIDFormat)
		return
	}

	if nameIDFormat == Unspecified || nameIDFormat == "" {
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

// FindInMetadataSets - find an entity in a list of MD sets and return it and the index
func FindInMetadataSets(metadataSets MdSets, key string) (md *goxml.Xp, index uint8, err error) {
	for i := range metadataSets {
		index = uint8(i)
		md, err = metadataSets[index].MDQ(key)
		if err == nil { // if we don't get md not found the last error is as good as the first
			return
		}
	}
	return
}

// ReceiveSAMLResponse handles the SAML minutiae when receiving a SAMLResponse
// Currently the only supported binding is POST
// Receives the metadatasets for resp. the sender and the receiver
// Returns metadata for the sender and the receiver
func ReceiveSAMLResponse(r *http.Request, issuerMdSets, destinationMdSets MdSets, location string, xtraCerts []string) (xp, issuerMd, destinationMd *goxml.Xp, relayState string, issuerIndex, destinationIndex uint8, err error) {
	return DecodeSAMLMsg(r, issuerMdSets, destinationMdSets, SPRole, []string{"Response"}, location, xtraCerts)
}

// ReceiveLogoutMessage receives the Logout Message
// Receives the metadatasets for resp. the sender and the receiver
// Returns metadata for the sender and the receiver
func ReceiveLogoutMessage(r *http.Request, issuerMdSets, destinationMdSets MdSets, role int) (xp, issuerMd, destinationMd *goxml.Xp, relayState string, issuerIndex, destinationIndex uint8, err error) {
	return DecodeSAMLMsg(r, issuerMdSets, destinationMdSets, role, []string{"LogoutRequest", "LogoutResponse"}, "https://"+r.Host+r.URL.Path, nil)
}

// DecodeSAMLMsg decodes the Request. Extracts Issuer, Destination
// Check for Protocol for example (AuthnRequest)
// Validates the schema
// Receives the metadatasets for resp. the sender and the receiver
// Returns metadata for the sender and the receiver
func DecodeSAMLMsg(r *http.Request, issuerMdSets, destinationMdSets MdSets, role int, protocols []string, location string, xtraCerts []string) (xp, issuerMd, destinationMd *goxml.Xp, relayState string, issuerIndex, destinationIndex uint8, err error) {
	defer r.Body.Close()
	r.ParseForm()

	destinationMd, destinationIndex, err = FindInMetadataSets(destinationMdSets, location)
	if err != nil {
		return
	}

	var signed bool
	switch {
	case r.Form.Get("id_token") != "":
		xp, relayState, issuerMd, issuerIndex, signed, err = handleOIDCResponse(r, issuerMdSets, destinationMd, location)
		if err != nil {
			return
		}
		xp.QueryDashP(nil, "@Flow", "id_token", nil)
	default:
		method := r.Method
		if ok := method == "GET" || method == "POST"; !ok {
			err = fmt.Errorf("unsupported http method used '%s'", method)
			return
		}

		relayState = r.Form.Get("RelayState")

		var bmsg []byte
		msg := r.Form.Get("SAMLRequest") + r.Form.Get("SAMLResponse") // never both at the same time
		if msg != "" {
			bmsg, err = base64.StdEncoding.DecodeString(msg)
			if err != nil {
				return
			}
			if method == "GET" {
				bmsg = Inflate(bmsg)
			}
			xp = goxml.NewXp(bmsg)
		} else {
			xp, relayState, err = request2samlRequest(r, issuerMdSets, destinationMdSets, location)
			if err != nil {
				return
			}
		}
		DumpFileIfTracing(r, xp)
		//log.Println("stack", goxml.New().Stack(1))
		err = xp.SchemaValidate()
		if err != nil {
			dump("raw", bmsg)
			err = goxml.Wrap(err)
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

		// PHPH can't currently handle entities with both SP and IdP roles, so if a request comes in from an IdP map it to it's twin SP
		if sp := config.IdP2SPMappping[issuer]; sp != "" && protocol == "AuthnRequest" {
			issuer = sp
			xp.QueryDashP(nil, "./saml:Issuer", issuer, nil)
		}

		issuerMd, issuerIndex, err = FindInMetadataSets(issuerMdSets, issuer)
		if err != nil {
			return
		}

		xp, signed, err = CheckSAMLMessage(r, xp, issuerMd, destinationMd, role, location, xtraCerts)
		if err != nil {
			err = goxml.Wrap(err)
			return
		}

	}

	if signed { // Bindings 3.4.5.2 Security Considerations and 3.5.5.2 Security Considerations
		destination := xp.Query1(nil, "./@Destination")
		if destination == "" {
			err = fmt.Errorf("no destination found in SAMLRequest/SAMLResponse")
			return
		}
		if destination != location && !strings.HasPrefix(destination, location+"?") { // ignore params ...
			err = fmt.Errorf("destination: %s is not here, here is %s", destination, location)
			return
		}
	}

	xp, err = checkDestinationAndACS(xp, issuerMd, destinationMd, role, location)
	if err != nil {
		return
	}

	xp, err = VerifyTiming(xp, signed)
	if err != nil {
		return
	}
	return
}

// CheckSAMLMessage checks for Authentication Requests, Reponses and Logout Requests
// Checks for invalid Bindings. Check for Certificates. Verify Signatures
func CheckSAMLMessage(r *http.Request, xp, issuerMd, destinationMd *goxml.Xp, role int, location string, xtraCerts []string) (validatedMessage *goxml.Xp, signed bool, err error) {
	type protoCheckInfoStruct struct {
		minSignatures     int
		service           string
		signatureElements []string
		checks            []string
	}

	protocol := xp.QueryString(nil, "local-name(/*)")
	authnRequestChecks := 0
	if protocol == "AuthnRequest" && destinationMd.QueryXMLBool(nil, "./md:IDPSSODescriptor/@WantAuthnRequestsSigned") {
		authnRequestChecks = 1
	}

	// add checks for xtra element on top level in tests - does schema checks handle that or should we do it here???
	protoChecks := map[string]protoCheckInfoStruct{
		"AuthnRequest": {
			minSignatures:     authnRequestChecks,
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

	bindings := map[string][]string{
		"GET":  {REDIRECT},
		"POST": {POST},
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

	// the check for SigAlg is mostly for testing. If checking is not enforced by metadata the Signature and SigAlg can just be removed
	if protoChecks[protocol].minSignatures <= 0 {
		return xp, false, nil
	}

	certificates := issuerMd.QueryMulti(nil, `./`+Roles[(role+1)%2]+SigningCertQuery) // the issuer's role
	certificates = append(certificates, xtraCerts...)

	if len(certificates) == 0 {
		err = errors.New("no certificates found in metadata")
		return
	}

	switch usedBinding {
	case REDIRECT:
		{
			if err = checkRedirect(parseQueryRaw(r.URL.RawQuery), certificates); err == nil {
				validatedMessage = xp
			} else if query := protoChecks[protocol].signatureElements[0]; query != "" {
				signatures := xp.Query(nil, query)
				if len(signatures) == 1 {
					if err = VerifySign(xp, certificates, signatures[0]); err != nil {
						return
					}
					validatedMessage = xp
				}
			}
		}
	case POST:
		{
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
					privatekey, _, err := GetPrivateKeyByMethod(destinationMd, "md:SPSSODescriptor"+EncryptionCertQuery, x509.RSA)
					if err != nil {
						return nil, false, goxml.Wrap(err)
					}

					signatures := xp.Query(nil, "/samlp:Response[1]/ds:Signature[1]/..")
					if len(signatures) == 1 {
						if err = VerifySign(xp, certificates, signatures[0]); err != nil {
							return nil, false, goxml.Wrap(err, "err:unable to validate signature")
						}
					}

					encryptedAssertion := encryptedAssertions[0]
					err = xp.Decrypt(encryptedAssertion.(types.Element), privatekey)
					if err != nil {
						err = goxml.Wrap(err)
						err = goxml.PublicError(err.(goxml.Werror), "cause:encryption error") // hide the real problem from attacker
						return nil, false, err
					}

					validatedMessage = xp

					// repeat schemacheck
					err = xp.SchemaValidate()
					if err != nil {
						err = goxml.Wrap(err)
						err = goxml.PublicError(err.(goxml.Werror), "cause:encryption error") // hide the real problem from attacker
						return nil, false, err
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
						return nil, false, goxml.Wrap(err, "err:unable to validate signature")
					}
					validatedMessage = xp
				}
			}
		}
	}

	// if we don't have a validatedResponse by now we are toast
	if validatedMessage == nil {
		err = goxml.NewWerror("err:no signatures found")
		err = goxml.PublicError(err.(goxml.Werror), "cause:encryption error") // hide the real problem from attacker
		return nil, false, err
	}

	for _, check := range protoChecks[protocol].checks {
		if !validatedMessage.QueryBool(nil, check) {
			return nil, false, goxml.NewWerror("cause: check failed", "check: "+check)
		}
	}
	signed = validatedMessage != nil
	return
}

func checkRedirect(params url.Values, certificates []string) (err error) {
	signed, delim := "", ""

	for _, key := range []string{"SAMLRequest", "RelayState", "SigAlg"} {
		if rw, ok := params[key]; ok {
			val := rw[0]
			signed += delim + key + "=" + val
			delim = "&"
		}
	}

	sig, _ := url.QueryUnescape(params.Get("Signature"))
	signature, _ := base64.StdEncoding.DecodeString(sig)
	sigAlg, _ := url.QueryUnescape(params.Get("SigAlg")) // need to unescape here because the signature uses the escaped value

	if _, ok := goxml.SigningMethods[sigAlg]; !ok {
		return goxml.NewWerror("unsupported SigAlg", sigAlg)
	}
	digest := goxml.Hash(goxml.SigningMethods[sigAlg].Hash, signed)
	verified := 0
	signerrors := []error{}

	_, _, pubs, err := PublicKeyInfoByMethod(certificates, goxml.SigningMethods[sigAlg].Type)
	if err != nil {
		return goxml.Wrap(err)
	}

	for _, pub := range pubs {
		signerror := goxml.Verify(pub, goxml.SigningMethods[sigAlg].Hash, digest[:], signature)
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
		acs := message.Query1(nil, "@AssertionConsumerServiceURL") // either index or ACSURL + Binding
		binding := message.Query1(nil, "@ProtocolBinding")
		if binding == "" {
			binding = POST
		}
		if acs == "" {
			acsIndex := message.Query1(nil, "@AssertionConsumerServiceIndex")
			acs = issuerMd.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@index=`+strconv.Quote(acsIndex)+`]/@Location`)
		}
		if acs == "" {
			acs = issuerMd.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@Binding=`+strconv.Quote(binding)+` and (@isDefault="true" or @isDefault!="false" or not(@isDefault))]/@Location`)
		}

		checkedAcs := issuerMd.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@Binding=`+strconv.Quote(binding)+` and @Location=`+strconv.Quote(acs)+`]/@index`)
		if checkedAcs == "" {
			checkedAcs = issuerMd.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@Binding=`+strconv.Quote(POST)+` and @Location=`+strconv.Quote(acs)+`]/@index`)
			if checkedAcs == "" {
				return nil, goxml.Wrap(ErrorACS, "acs:"+acs, "acsindex:"+acsIndex, "binding:"+binding)
			}
		}

		// we now have a validated AssertionConsumerService - and Binding - let's put them into the request
		message.QueryDashP(nil, "@AssertionConsumerServiceURL", acs, nil)
		message.QueryDashP(nil, "@ProtocolBinding", binding, nil)
		message.QueryDashP(nil, "@AssertionConsumerServiceIndex", checkedAcs, nil) // used in the compressed request - we will be able to get Binding and ACSURL from the index

		checkedDest = destinationMd.Query1(nil, `./md:IDPSSODescriptor/md:SingleSignOnService[@Binding="`+REDIRECT+`" and @Location=`+strconv.Quote(location)+`]/@Location`)
		if checkedDest == "" {
			checkedDest = destinationMd.Query1(nil, `./md:IDPSSODescriptor/md:SingleSignOnService[@Binding="`+POST+`" and @Location=`+strconv.Quote(location)+`]/@Location`)
		}
	case "LogoutRequest", "LogoutResponse":
		checkedDest = destinationMd.Query1(nil, mdRole+`/md:SingleLogoutService[@Location=`+strconv.Quote(location)+`]/@Location`)
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
	publicKeys := []crypto.PublicKey{}
	for _, certificate := range certificates {
		var key crypto.PublicKey
		_, key, err = PublicKeyInfo(certificate)
		if err != nil {
			return
		}
		publicKeys = append(publicKeys, key)
	}

	return xp.VerifySignature(signature, publicKeys)
}

// VerifyTiming verify the presence and value of timestamps
func VerifyTiming(xp *goxml.Xp, signed bool) (verifiedXp *goxml.Xp, err error) {
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
			"./@IssueInstant": {signed, signed, signed}, // used signed here because Mind The Gab requests uses client side timing and we can not count on that being precise
		}
	case "Response":
		checks = map[string]timing{
			"/samlp:Response[1]/@IssueInstant":                   {true, true, true},
			"/samlp:Response[1]/saml:Assertion[1]/@IssueInstant": {true, true, true},
			"/samlp:Response[1]/saml:Assertion[1]/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter": {false, true, false},
			"/samlp:Response[1]/saml:Assertion[1]/saml:Conditions/@NotBefore":                                                       {false, false, true},
			"/samlp:Response[1]/saml:Assertion[1]/saml:Conditions/@NotOnOrAfter":                                                    {false, true, false},
			//			"/samlp:Response[1]/saml:Assertion[1]/saml:AuthnStatement/@AuthnInstant":                                                {true, true, true},
			//			"/samlp:Response[1]/saml:Assertion[1]/saml:AuthnStatement/@SessionNotOnOrAfter":                                         {false, true, false},
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

// IDAndTiming for checking the validity
func IDAndTiming() (issueInstant, id, assertionID, assertionNotBefore, assertionNotOnOrAfter, sessionNotOnOrAfter string) {
	now := TestTime
	if now.IsZero() {
		now = time.Now().UTC()
	}
	issueInstant = now.Format(XsDateTime)
	assertionNotBefore = now.Add(-10 * time.Second).Format(XsDateTime)
	assertionNotOnOrAfter = now.Add(4 * time.Minute).Format(XsDateTime)
	sessionNotOnOrAfter = now.Add(4 * time.Hour).Format(XsDateTime)
	id = TestID
	if id == "" {
		id = ID()
	}
	assertionID = TestAssertionID
	if assertionID == "" {
		assertionID = ID()
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
func NewLogoutRequest(destination *goxml.Xp, sloinfo *SLOInfo, issuer string, async bool) (request *goxml.Xp, binding string, err error) {
	role := (sloinfo.HubRole + 1) % 2 // the request is going out from the hub so look for the reverse role in destination metadata
	slo := destination.Query(nil, `./`+Roles[role]+`/md:SingleLogoutService[@Binding="`+REDIRECT+`" or @Binding="`+POST+`"]`)
	if len(slo) == 0 {
		err = goxml.NewWerror("cause:no SingleLogoutService found", "entityID:"+destination.Query1(nil, "./@entityID"))
		return
	}
	binding = destination.Query1(slo[0], "./@Binding")
	request = logoutRequest(sloinfo, issuer, destination.Query1(slo[0], "./@Location"), async)
	return
}

func logoutRequest(sloinfo *SLOInfo, issuer, destination string, async bool) (request *goxml.Xp) {
	template := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0"></samlp:LogoutRequest>`
	request = goxml.NewXpFromString(template)
	issueInstant, _, _, _, _, _ := IDAndTiming()
	request.QueryDashP(nil, "./@IssueInstant", issueInstant, nil)
	request.QueryDashP(nil, "./@ID", sloinfo.ID, nil)
	request.QueryDashP(nil, "./@Destination", destination, nil)
	request.QueryDashP(nil, "./saml:Issuer", issuer, nil)
	if async {
		request.QueryDashP(nil, "./samlp:Extensions/aslo:Asynchronous", "", nil)
	}
	request.QueryDashP(nil, "./saml:NameID/@Format", NameIDList[sloinfo.NameIDFormat], nil)
	if sloinfo.SPNameQualifier != "" {
		request.QueryDashP(nil, "./saml:NameID/@SPNameQualifier", sloinfo.SPNameQualifier, nil)
	}
	if sloinfo.SessionIndex != "" {
		request.QueryDashP(nil, "./samlp:SessionIndex", sloinfo.SessionIndex, nil)
	}
	request.QueryDashP(nil, "./saml:NameID", sloinfo.NameID, nil)
	return
}

// NewLogoutResponse creates a Logout Response oon the basis of Logout request
func NewLogoutResponse(issuer string, destination *goxml.Xp, inResponseTo string, role uint8) (response *goxml.Xp, binding string, err error) {
	for _, binding = range []string{REDIRECT, POST} {
		response, err = NewLogoutResponseWithBinding(issuer, destination, inResponseTo, role, binding)
		if err == nil {
			return
		}
	}
	return
}

func NewLogoutResponseWithBinding(issuer string, destination *goxml.Xp, inResponseTo string, role uint8, binding string) (response *goxml.Xp, err error) {
	template := `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></samlp:LogoutResponse>`
	response = goxml.NewXpFromString(template)
	slo := destination.Query(nil, `./`+Roles[role]+`/md:SingleLogoutService[@Binding="`+binding+`"]`)
	if len(slo) == 0 {
		err = goxml.NewWerror("cause:no SingleLogoutService found", "entityID:"+destination.Query1(nil, "./@entityID"))
		return
	}
	binding = destination.Query1(slo[0], "./@Binding")
	response.QueryDashP(nil, "./@Destination", destination.Query1(slo[0], "./@Location"), nil)
	response.QueryDashP(nil, "./@Version", "2.0", nil)
	response.QueryDashP(nil, "./@IssueInstant", time.Now().Format(XsDateTime), nil)
	response.QueryDashP(nil, "./@ID", ID(), nil)
	response.QueryDashP(nil, "./@InResponseTo", inResponseTo, nil)
	response.QueryDashP(nil, "./saml:Issuer", issuer, nil)
	response.QueryDashP(nil, "./samlp:Status/samlp:StatusCode/@Value", "urn:oasis:names:tc:SAML:2.0:status:Success", nil)
	return
}

// SloRequest generates a single logout request
func SloRequest(w http.ResponseWriter, r *http.Request, response, spMd, IdpMd *goxml.Xp, pk crypto.PrivateKey, protocol string) {
	context := response.Query(nil, "/samlp:Response/saml:Assertion")[0]
	sloinfo := NewSLOInfo(response, context, spMd.Query1(nil, "@entityID"), false, SPRole, protocol)
	request, binding, _ := NewLogoutRequest(IdpMd, sloinfo, spMd.Query1(nil, "@entityID"), false)
	request.QueryDashP(nil, "@ID", ID(), nil)
	switch binding {
	case REDIRECT:
		u, _ := SAMLRequest2URL(request, "", pk, config.DefaultCryptoMethod)
		http.Redirect(w, r, u.String(), http.StatusFound)
	case POST:
		data := Formdata{Acs: request.Query1(nil, "./@Destination"), Samlrequest: base64.StdEncoding.EncodeToString(request.Dump())}
		PostForm.ExecuteTemplate(w, "postForm", data)
	}
}

// SloResponse generates a single logout reponse
func SloResponse(w http.ResponseWriter, r *http.Request, request, issuer, destination *goxml.Xp, pk crypto.PrivateKey, role uint8) (err error) {
	response, binding, err := NewLogoutResponse(issuer.Query1(nil, `./@entityID`), destination, request.Query1(nil, "@ID"), role)
	if err != nil {
		return
	}

	switch binding {
	case REDIRECT:
		u, _ := SAMLRequest2URL(response, "", pk, config.DefaultCryptoMethod)
		http.Redirect(w, r, u.String(), http.StatusFound)
	case POST:
		data := Formdata{Acs: response.Query1(nil, "./@Destination"), Samlresponse: base64.StdEncoding.EncodeToString(response.Dump())}
		PostForm.ExecuteTemplate(w, "postForm", data)
	}
	return
}

// NewSLOInfo extract necessary Logout information - xp is expectd to be a Response
func NewSLOInfo(xp *goxml.Xp, context types.Node, sp string, sloSupport bool, hubRole uint8, protocol string) (slo *SLOInfo) {
	slo = &SLOInfo{
		HubRole:         hubRole,
		IDP:             IDHash(xp.Query1(context, "saml:Issuer")),
		SP:              IDHash(sp),
		NameID:          xp.Query1(context, "saml:Subject/saml:NameID"),
		NameIDFormat:    NameIDMap[xp.Query1(context, "saml:Subject/saml:NameID/@Format")],
		SPNameQualifier: xp.Query1(context, "saml:Subject/saml:NameID/@SPNameQualifier"),
		SessionIndex:    xp.Query1(context, "saml:AuthnStatement/@SessionIndex") + xp.Query1(context, "samlp:SessionIndex"), // never both at the same time !!!
		SLOSupport:      sloSupport,
		Protocol:        protocol,
	}
	return
}

func (sil *SLOInfoList) LogoutRequest(request *goxml.Xp, hub string, hubRole uint8, protocol string) (slo *SLOInfo) {
	context := request.Query(nil, "/samlp:LogoutRequest")[0]
	newSlo := NewSLOInfo(request, context, hub, true, hubRole, protocol)
	if hubRole == IDPRole { // if from a SP we need to swap roles - the hub is the IDP
		newSlo.SP, newSlo.IDP = newSlo.IDP, newSlo.SP
	}
	// to-do delete if async request
	for i, sloInfo := range *sil { // find the SLOInfo
		if newSlo.HubRole == sloInfo.HubRole && newSlo.IDP == sloInfo.IDP && newSlo.SP == sloInfo.SP { // ignoring NameID etc for now
			(*sil)[i].ID = request.Query1(context, "@ID") // remember the ID for the response
			(*sil)[i].NameID = ""                         // sentinel for initial request
			(*sil)[i].SPNameQualifier = ""
			(*sil)[i].SessionIndex = ""
			(*sil)[i].SLOStatus = 1
			(*sil)[i].Async = request.QueryBool(context, "boolean(samlp:Extensions/aslo:Asynchronous)")
			(*sil)[i].Protocol = request.Query1(context, "samlp:Extensions/wayf:protocol")
			break
		}
	}
	slo, _ = sil.Find(nil)
	return
}

func (sil *SLOInfoList) LogoutResponse(response *goxml.Xp) (slo *SLOInfo, sendResponse bool) {
	return sil.Find(response)
}

func (sil *SLOInfoList) Response(response *goxml.Xp, sp string, sloSupport bool, hubRole uint8, protocol string) {
	newSil := SLOInfoList{}
	context := response.Query(nil, "/samlp:Response/saml:Assertion")[0]
	newSlo := NewSLOInfo(response, context, sp, sloSupport, hubRole, protocol)
	newSil = append(newSil, *newSlo)
	for _, sloInfo := range *sil {
		if newSlo.HubRole == sloInfo.HubRole && newSlo.IDP == sloInfo.IDP && newSlo.SP == sloInfo.SP {
			continue // we only support one active "session" per SP/IDP so skip it if already there
		}
		newSil = append(newSil, sloInfo)
	}
	*sil = newSil
	return
}

func (sil *SLOInfoList) Find(response *goxml.Xp) (slo *SLOInfo, ok bool) {
	slo = &SLOInfo{}
	if response != nil {
		id := response.Query1(nil, "@InResponseTo")
		for i, sloInfo := range *sil {
			if id == sloInfo.ID && response.QueryBool(nil, `count(./samlp:Status/samlp:StatusCode[@Value="urn:oasis:names:tc:SAML:2.0:status:Success"]) > 0`) {
				(*sil)[i].SLOStatus = 1
			}
		}
	}
	// try first to find an IDP to log out from
	for i, sloInfo := range *sil { // find the SLOInfo
		if sloInfo.HubRole == SPRole && sloInfo.ID == "" && sloInfo.SLOSupport {
			(*sil)[i].ID = ID()
			slo = &(*sil)[i]
			return
		}
	}
	// If no IDPs find a SP
	for i, sloInfo := range *sil { // find the SLOInfo
		if sloInfo.HubRole == IDPRole && sloInfo.ID == "" && sloInfo.SLOSupport {
			(*sil)[i].ID = ID()
			slo = &(*sil)[i]
			return
		}
	}
	ok = true
	for i, sloInfo := range *sil {
		ok = ok && sloInfo.SLOStatus == 1
		if sloInfo.NameID == "" {
			slo = &(*sil)[i]
		}
	}
	return
}

// SignResponse signs the response with the given method.
// Returns an error if unable to sign.
func SignResponse(response *goxml.Xp, elementQuery string, md *goxml.Xp, signingMethod string, signFor int) (err error) {
	privatekey, cert, err := GetPrivateKeyByMethod(md, "md:IDPSSODescriptor"+SigningCertQuery, config.CryptoMethods[signingMethod].Type)
	if err != nil {
		signingMethod = config.DefaultCryptoMethod // try again with default signingMethod
		privatekey, cert, err = GetPrivateKeyByMethod(md, "md:IDPSSODescriptor"+SigningCertQuery, config.CryptoMethods[signingMethod].Type)
		if err != nil {
			return
		}
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

	err = response.Sign(element[0].(types.Element), before, privatekey, cert, signingMethod)
	return
}

// NewAuthnRequest - create an AuthnRequest using the supplied metadata for setting the fields according to the following rules:
//   - The Destination is the 1st SingleSignOnService with a redirect binding in the idpmetadata
//   - The AssertionConsumerServiceURL is the Location of the 1st ACS with a post binding in the spmetadata
//   - The ProtocolBinding is post
//   - The Issuer is the entityID in the idpmetadata
//   - The NameID defaults to transient
func NewAuthnRequest(originalRequest, spMd, idpMd *goxml.Xp, virtualIDP string, idPList []string, acs string, wantRequesterID bool, spIndex, hubBirkIndex uint8) (request *goxml.Xp, sRequest SamlRequest, err error) {
	template := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    Version="2.0">
<saml:Issuer>Issuer</saml:Issuer>
<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true" />
</samlp:AuthnRequest>`
	idp := idpMd.Query1(nil, "@entityID")
	issueInstant, msgID, _, _, _, _ := IDAndTiming()
	var ID, issuer, nameIDFormat, protocol string

	request = goxml.NewXpFromString(template)
	request.QueryDashP(nil, "./@ID", msgID, nil)
	request.QueryDashP(nil, "./@IssueInstant", issueInstant, nil)
	request.QueryDashP(nil, "./@Destination", idpMd.Query1(nil, `./md:IDPSSODescriptor/md:SingleSignOnService[@Binding="`+REDIRECT+`"]/@Location`), nil)
	var protocolBinding string
	if acs != "" {
		protocolBinding = spMd.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@Location=`+strconv.Quote(acs)+`]/@Binding`)
	} else if acs == "" {
		acs = spMd.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@Binding="`+POST+`"]/@Location`)
		protocolBinding = POST
	}
	if protocolBinding == "" {
		err = goxml.NewWerror("cause:no @Binding found for acs", "acs:"+acs)
		return
	}
	request.QueryDashP(nil, "./@ProtocolBinding", protocolBinding, nil)
	request.QueryDashP(nil, "./@AssertionConsumerServiceURL", acs, nil)
	wayfsp := spMd.Query1(nil, `./@entityID`) // we save the issueing SP in the sRequest for edge request - will be overwritten later if an originalRequest is given
	request.QueryDashP(nil, "./saml:Issuer", wayfsp, nil)
	request.QueryDashP(nil, "./samlp:NameIDPolicy/@Format", spMd.Query1(nil, `./md:SPSSODescriptor/md:NameIDFormat`), nil)

	acsIndex := ""
	if originalRequest != nil { // already checked for supported nameidformat
		ID = originalRequest.Query1(nil, "./@ID")
		issuer = originalRequest.Query1(nil, "./saml:Issuer")
		nameIDFormat = originalRequest.Query1(nil, "./samlp:NameIDPolicy/@Format")
		protocol = originalRequest.Query1(nil, "./samlp:Extensions/wayf:protocol")
		acsIndex = originalRequest.Query1(nil, "./@AssertionConsumerServiceIndex")

		for _, attr := range []string{"./@ForceAuthn", "./@IsPassive"} {
			if val := originalRequest.Query1(nil, attr); val != "" {
				request.QueryDashP(nil, attr, val, nil)
			}
		}

		for _, rac := range originalRequest.QueryMulti(nil, `./saml:AttributeStatement/saml:Attribute[@Name="RequestedAuthnContextClassRef"]/saml:AttributeValue`) {
			if rac != "*" {
				request.QueryDashP(nil, "./samlp:RequestedAuthnContext/saml:AuthnContextClassRef[0]", rac, nil)
			}
		}

		if comparison := originalRequest.Query1(nil, `./saml:AttributeStatement/saml:Attribute[@Name="RequestedAuthnContextComparison"]`); comparison != "" && comparison != "*" {
			request.QueryDashP(nil, "./samlp:RequestedAuthnContext/@Comparison", comparison, nil)
		}

		if wantRequesterID {
			request.QueryDashP(nil, "./samlp:Scoping/samlp:RequesterID", issuer, nil)
			if virtualIDP != idp { // add virtual idp to wayf extension if mapped
				request.QueryDashP(nil, "./samlp:Scoping/samlp:RequesterID[0]", virtualIDP, nil)
			}
		}
	}

	for _, providerID := range idPList {
		if providerID != "" {
			request.QueryDashP(nil, "./samlp:Scoping/samlp:IDPList/samlp:IDPEntry[0]/@ProviderID", providerID, nil)
		}
	}

	sRequest = SamlRequest{
		Nonce:                  msgID,
		RequestID:              ID,
		SP:                     IDHash(issuer),
		IDP:                    IDHash(idp),
		VirtualIDP:             IDHash(virtualIDP),
		WAYFSP:                 IDHash(wayfsp),
		NameIDFormat:           NameIDMap[nameIDFormat],
		AssertionConsumerIndex: acsIndex,
		SPIndex:                spIndex,
		HubBirkIndex:           hubBirkIndex,
		Protocol:               protocol,
	}
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

	issueInstant, msgID, assertionID, assertionNotBefore, assertionNotOnOrAfter, sessionNotOnOrAfter := IDAndTiming()
	assertionIssueInstant := issueInstant

	spEntityID := spMd.Query1(nil, `/md:EntityDescriptor/@entityID`)
	idpEntityID := idpMd.Query1(nil, `/md:EntityDescriptor/@entityID`)

	acs := authnrequest.Query1(nil, "@AssertionConsumerServiceURL")
	response.QueryDashP(nil, "./@ID", msgID, nil)
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
	response.QueryDashP(nameid, "@Format", Transient, nil)
	response.QueryDashP(nameid, ".", ID(), nil)

	subjectconfirmationdata := response.Query(assertion, "saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData")[0]
	response.QueryDashP(subjectconfirmationdata, "@NotOnOrAfter", assertionNotOnOrAfter, nil)
	response.QueryDashP(subjectconfirmationdata, "@Recipient", acs, nil)
	response.QueryDashP(subjectconfirmationdata, "@InResponseTo", authnrequest.Query1(nil, "@ID"), nil)

	conditions := response.Query(assertion, "saml:Conditions")[0]
	response.QueryDashP(conditions, "@NotBefore", assertionNotBefore, nil)
	response.QueryDashP(conditions, "@NotOnOrAfter", assertionNotOnOrAfter, nil)
	response.QueryDashP(conditions, "saml:AudienceRestriction/saml:Audience", spEntityID, nil)

	authstatement := response.Query(assertion, "saml:AuthnStatement")[0]
	response.QueryDashP(authstatement, "@SessionIndex", ID(), nil)

	if sourceResponse != nil {
		srcAssertion := sourceResponse.Query(nil, "saml:Assertion")[0]
		for _, aa := range sourceResponse.QueryMulti(srcAssertion, "saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority") {
			response.QueryDashP(authstatement, "saml:AuthnContext/saml:AuthenticatingAuthority[0]", aa, nil)
		}
		response.QueryDashP(nameid, "@Format", sourceResponse.Query1(srcAssertion, "saml:Subject/saml:NameID/@Format"), nil)
		response.QueryDashP(nameid, ".", sourceResponse.Query1(srcAssertion, "saml:Subject/saml:NameID"), nil)
		response.QueryDashP(authstatement, "saml:AuthnContext/saml:AuthnContextClassRef", sourceResponse.Query1(srcAssertion, `saml:AttributeStatement/saml:Attribute[@Name="AuthnContextClassRef"]/saml:AttributeValue`), nil)
		response.QueryDashP(authstatement, "saml:AuthnContext/saml:AuthenticatingAuthority[0]", sourceResponse.Query1(srcAssertion, "saml:Issuer"), nil)
		response.QueryDashP(authstatement, "@AuthnInstant", sourceResponse.Query1(srcAssertion, "saml:AuthnStatement/@AuthnInstant"), nil)
		response.QueryDashP(authstatement, "@SessionNotOnOrAfter", sourceResponse.Query1(srcAssertion, "saml:AuthnStatement/@SessionNotOnOrAfter"), nil)
	} else {
		response.QueryDashP(authstatement, "@AuthnInstant", assertionIssueInstant, nil)
		response.QueryDashP(authstatement, "@SessionNotOnOrAfter", sessionNotOnOrAfter, nil)
	}
	return
}

// request2samlRequest does the protocol translation from ws-fed to saml
func request2samlRequest(r *http.Request, issuerMdSets, destinationMdSets MdSets, location string) (samlmessage *goxml.Xp, relayState string, err error) {
	relayState = r.Form.Get("wctx") + r.Form.Get("state")
	issuer := r.Form.Get("wtrealm") + r.Form.Get("client_id")
	acs := r.Form.Get("wreply") + r.Form.Get("redirect_uri")
	wa := r.Form.Get("wa")
	response_type := r.Form.Get("response_type")

	switch {
	case wa == "wsignin1.0", response_type == "id_token":
		samlmessage = goxml.NewXpFromString(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0"/>`)
		issueInstant, msgID, _, _, _, _ := IDAndTiming()
		samlmessage.QueryDashP(nil, "./@ID", msgID, nil)
		samlmessage.QueryDashP(nil, "./@IssueInstant", issueInstant, nil)
		samlmessage.QueryDashP(nil, "./@Destination", location, nil)
		samlmessage.QueryDashP(nil, "./@AssertionConsumerServiceURL", acs, nil)
		samlmessage.QueryDashP(nil, "./@ProtocolBinding", POST, nil)
		samlmessage.QueryDashP(nil, "./saml:Issuer", issuer, nil)
		protocol := samlmessage.QueryDashP(nil, "./samlp:Extensions/wayf:protocol", "", nil)
		if wa == "wsignin1.0" {
			samlmessage.QueryDashP(protocol, ".", "wsfed", nil)
		} else if response_type == "id_token" {
			if nonce := r.Form.Get("nonce"); nonce == "" {
				return nil, "", fmt.Errorf("No nonce found")
			}
			for _, acr := range strings.Split(r.Form.Get("acr_values"), " ") {
				samlmessage.QueryDashP(nil, "./samlp:RequestedAuthnContext/saml:AuthnContextClassRef[0]", acr, nil)
			}
			samlmessage.QueryDashPForce(nil, "@ID", "_"+r.Form.Get("nonce"), nil) // force overwriting - even if blank - always start with a _
			samlmessage.QueryDashP(protocol, ".", "oidc", nil)
		}
		return
	case wa == "wsignout1.0":
		samlmessage = logoutRequest(&SLOInfo{ID: "dummy", NameID: "dummy"}, issuer, location, false)
		samlmessage.QueryDashP(nil, "./samlp:Extensions/wayf:protocol", "wsfed", samlmessage.Query(nil, "saml:NameID")[0])
		return
	case wa == "wsignoutcleanup1.0":
	}
	err = fmt.Errorf("No valid SAML, OIDC, WS-fed* request/response found")
	return
}

func handleOIDCResponse(r *http.Request, issuerMdSets MdSets, spMd *goxml.Xp, location string) (samlmessage *goxml.Xp, relayState string, opMd *goxml.Xp, opIndex uint8, signed bool, err error) {
	defer r.Body.Close()
	r.ParseForm()
	id_token := r.Form.Get("id_token")
	relayState = r.Form.Get("state")

	var attrs map[string]interface{}
	attrs, opMd, err = JwtVerify(id_token, issuerMdSets, spMd, SPEnc, "")
	if err != nil {
		err = goxml.Wrap(err)
		return
	}
	// fake an authnRequest with @ACS and @ID
	request := goxml.NewXpFromString(`<pseudo/>`)
	nonce, ok := attrs["nonce"].(string)
	if !ok {
		err = goxml.NewWerror("Mandatory claim not present: nonce")
		return
	}
	request.QueryDashP(nil, "@ID", nonce[1:], nil) // we added a _, now remove it
	request.QueryDashP(nil, "@AssertionConsumerServiceURL", location, nil)
	samlmessage = NewResponse(opMd, spMd, request, nil)

	if err = Map2saml(samlmessage, attrs); err != nil {
		return
	}
	signed = true
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
                <saml1:Subject></saml1:Subject>
            </saml1:AttributeStatement>
            <saml1:AuthenticationStatement>
                <saml1:Subject></saml1:Subject>
            </saml1:AuthenticationStatement>
        </saml1:Assertion>
    </t:RequestedSecurityToken>
    <t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>
    <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
    <t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>
</t:RequestSecurityTokenResponse>
`
	response = goxml.NewXpFromString(template)

	assertionID := sourceResponse.Query1(nil, "./saml:Assertion/@ID")
	issueInstant := sourceResponse.Query1(nil, "@IssueInstant")
	assertionNotBefore := sourceResponse.Query1(nil, "./saml:Assertion/saml:Conditions/@NotBefore")
	assertionNotOnOrAfter := sourceResponse.Query1(nil, "./saml:Assertion/saml:Conditions/@NotOnOrAfter")
	authnInstant := sourceResponse.Query1(nil, "./saml:Assertion/saml:AuthnStatement/@AuthnInstant")

	spEntityID := spMd.Query1(nil, `/md:EntityDescriptor/@entityID`)
	audience := spEntityID
	if specialAudience := spMd.Query1(nil, `/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:actualSPEntityID`); specialAudience != "" {
		audience = specialAudience
	}

	idpEntityID := idpMd.Query1(nil, `/md:EntityDescriptor/@entityID`)

	response.QueryDashP(nil, "./t:Lifetime/wsu:Created", issueInstant, nil)
	response.QueryDashP(nil, "./t:Lifetime/wsu:Expires", assertionNotOnOrAfter, nil)
	response.QueryDashP(nil, "./wsp:AppliesTo/wsa:EndpointReference/wsa:Address", audience, nil)

	assertion := response.Query(nil, "t:RequestedSecurityToken/saml1:Assertion")[0]
	response.QueryDashP(assertion, "@AssertionID", assertionID, nil)
	response.QueryDashP(assertion, "@IssueInstant", issueInstant, nil)
	response.QueryDashP(assertion, "@Issuer", idpEntityID, nil)

	conditions := response.Query(assertion, "saml1:Conditions")[0]
	response.QueryDashP(conditions, "@NotBefore", assertionNotBefore, nil)
	response.QueryDashP(conditions, "@NotOnOrAfter", assertionNotOnOrAfter, nil)
	response.QueryDashP(conditions, "saml1:AudienceRestrictionCondition/saml1:Audience", audience, nil)

	nameIdentifier := sourceResponse.Query1(nil, "./saml:Assertion/saml:Subject/saml:NameID")
	nameIDFormat := sourceResponse.Query1(nil, "./saml:Assertion/saml:Subject/saml:NameID/@Format")

	authStmt := response.Query(assertion, "saml1:AuthenticationStatement")[0]
	response.QueryDashP(authStmt, "@AuthenticationInstant", authnInstant, nil)

	for _, stmt := range response.Query(assertion, ".//saml1:Subject") {
		response.QueryDashP(stmt, "saml1:NameIdentifier", nameIdentifier, nil)
		response.QueryDashP(stmt, "saml1:NameIdentifier/@Format", nameIDFormat, nil)
		response.QueryDashP(stmt, "saml1:SubjectConfirmation/saml1:ConfirmationMethod", "urn:oasis:names:tc:SAML:1.0:cm:bearer", nil)
	}

	attributeStmt := response.Query(assertion, "./saml1:AttributeStatement")[0]
	sourceAttributes := sourceResponse.Query(nil, "./saml:Assertion/saml:AttributeStatement/saml:Attribute")
	for _, stmt := range sourceAttributes {
		attr := response.QueryDashP(attributeStmt, "saml1:Attribute[0]", "", nil)
		for saml2Name, saml1Name := range map[string]string{"Name": "AttributeName", "NameFormat": "AttributeNamespace", "FriendlyName": "FriendlyName"} {
			response.QueryDashP(attr, "@"+saml1Name, sourceResponse.Query1(stmt, "@"+saml2Name), nil)
		}
		for _, value := range sourceResponse.QueryMulti(stmt, "saml:AttributeValue") {
			response.QueryDashP(attr, "saml1:AttributeValue[0]", value, nil)
		}
	}

	authContext := sourceResponse.Query1(nil, "./saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef")
	response.QueryDashP(authStmt, "./@AuthenticationMethod", authContext, nil)
	return
}

// SamlTime2JwtTime - convert string SAML time to epoch
func SamlTime2JwtTime(xmlTime string) int64 {
	samlTime, _ := time.Parse(XsDateTime, xmlTime)
	return samlTime.Unix()
}

// Jwt2saml - JSON based IdP interface
func Jwt2saml(w http.ResponseWriter, r *http.Request, mdHub, mdInternal, mdExternalIDP, mdExternalSP Md, requestHandler func(*goxml.Xp, *goxml.Xp, *goxml.Xp) (map[string][]string, error), signerMd *goxml.Xp) (err error) {
	defer r.Body.Close()
	r.ParseForm()

	msg, spMd, idpMd, relayState, _, _, err := DecodeSAMLMsg(r, MdSets{mdHub, mdExternalSP}, MdSets{mdInternal, mdExternalIDP}, IDPRole, []string{"AuthnRequest", "LogoutRequest", "LogoutResponse"}, r.Form.Get("sso"), nil)
	if err != nil {
		return err
	}

	entityID := idpMd.Query1(nil, `/md:EntityDescriptor/@entityID`)
	log.Println("jwt2saml:", entityID)

	jwt := r.Form.Get("jwt")
	if jwt == "" {
		req, err := requestHandler(msg, idpMd, spMd)
		if err != nil {
			return err
		}
		json, err := json.MarshalIndent(&req, "", "  ")
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(json)))
		w.Write(json)
		return err
	}
	msgType := msg.QueryString(nil, "local-name(/*)")
	switch msgType {
	case "AuthnRequest":
		attrs, _, err := JwtVerify(jwt, MdSets{mdInternal, mdExternalIDP}, spMd, SPEnc, entityID)
		if err != nil {
			return err
		}

		response := NewResponse(idpMd, spMd, msg, nil)
		// for id_tokens Map2saml requires "aud" and "nonce" in attrs - they are already in the response, but for legacy reasons not in the attrs sent to Jwt2saml
		attrs["aud"] = response.Query1(nil, "./saml:Assertion//saml:Conditions/saml:AudienceRestriction/saml:Audience")
		attrs["nonce"] = response.Query1(nil, "./@InResponseTo")
		if err = Map2saml(response, attrs); err != nil {
			return err
		}

		err = SignResponse(response, "/samlp:Response/saml:Assertion", signerMd, config.DefaultCryptoMethod, SAMLSign)
		if err != nil {
			return err
		}
		if spMd.QueryXMLBool(nil, "/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:assertion.encryption") {
			cert := spMd.Query1(nil, "./md:SPSSODescriptor"+EncryptionCertQuery) // actual encryption key is always first
			_, publicKey, _ := PublicKeyInfo(cert)
			assertion := response.Query(nil, "saml:Assertion[1]")[0]
			err = response.Encrypt(assertion, "saml:EncryptedAssertion", publicKey.(*rsa.PublicKey), []string{})
			if err != nil {
				return err
			}
		}

		data := Formdata{Acs: response.Query1(nil, "./@Destination"), Samlresponse: base64.StdEncoding.EncodeToString(response.Dump()), RelayState: relayState}
		return PostForm.ExecuteTemplate(w, "postForm", data)
	case "LogoutRequest":
		response, err := NewLogoutResponseWithBinding(idpMd.Query1(nil, `./@entityID`), spMd, msg.Query1(nil, "@ID"), SPRole, POST)
		if err != nil {
			return err
		}
		data := Formdata{Acs: response.Query1(nil, "./@Destination"), Samlresponse: base64.StdEncoding.EncodeToString(response.Dump())}
		return PostForm.ExecuteTemplate(w, "postForm", data)
	case "LogoutResponse":
	}
	return
}

func Map2saml(response *goxml.Xp, attrs map[string]interface{}) (err error) {
	type claimType struct {
		name, xpath string
	}

	elems := []claimType{
		{"iss", "./saml:Issuer"},
		{"iss", "./saml:Assertion/saml:Issuer"},
		{"aud", "./saml:Assertion//saml:Conditions/saml:AudienceRestriction/saml:Audience"},
		{"nonce", "./@InResponseTo"}, // override what is set by newresponse
		{"nonce", "./saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@InResponseTo"}, // override what is set by newresponse
	}
	for _, claim := range elems {
		if t, ok := attrs[claim.name].(string); ok {
			response.QueryDashPForce(nil, claim.xpath, t, nil)
		} else {
			return goxml.NewWerror("Mandatory claim not present: " + claim.name)
		}
	}

	times := []claimType{
		{"iat", "@IssueInstant"},
		{"iat", "./saml:Assertion/@IssueInstant"},
		{"exp", "./saml:Assertion/saml:Conditions/@NotOnOrAfter"},
		{"nbf", "./saml:Assertion/saml:Conditions/@NotBefore"},
		{"auth_time", "./saml:Assertion/saml:AuthnStatement/@AuthnInstant"},
	}

	for _, claim := range times {
		t, _ := attrs[claim.name].(float64)
		response.QueryDashPForce(nil, claim.xpath, time.Unix(int64(t), 0).Format(XsDateTime), nil)
	}

	destinationAttributes := response.QueryDashP(nil, `/saml:Assertion/saml:AttributeStatement[1]`, "", nil)
	for name, values := range attrs {
		attr := response.QueryDashP(destinationAttributes, `saml:Attribute[@Name=`+strconv.Quote(name)+`]`, "", nil)
		response.QueryDashP(attr, `@NameFormat`, "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", nil)
		switch vals := values.(type) {
		case []interface{}:
			for _, val := range vals {
				if v, ok := val.(string); ok {
					response.QueryDashP(attr, "saml:AttributeValue[0]", v, nil)
				}
			}
		}
	}
	return
}

func Saml2map(response *goxml.Xp) (attrs map[string]interface{}) {
	attrs = map[string]interface{}{}
	assertion := response.Query(nil, "/samlp:Response/saml:Assertion")[0]
	names := response.QueryMulti(assertion, "saml:AttributeStatement/saml:Attribute/@Name")
	for _, name := range names {
		attrs[name] = response.QueryMulti(assertion, "saml:AttributeStatement/saml:Attribute[@Name="+strconv.Quote(name)+"]/saml:AttributeValue")
	}

	attrs["iss"] = response.Query1(assertion, "./saml:Issuer")
	attrs["aud"] = response.Query1(assertion, "./saml:Conditions/saml:AudienceRestriction/saml:Audience")
	attrs["nbf"] = SamlTime2JwtTime(response.Query1(assertion, "./saml:Conditions/@NotBefore"))
	attrs["exp"] = SamlTime2JwtTime(response.Query1(assertion, "./saml:Conditions/@NotOnOrAfter"))
	attrs["iat"] = SamlTime2JwtTime(response.Query1(assertion, "@IssueInstant"))
	if tmp, ok := attrs["eduPersonPrincipalName"]; ok {
		attrs["sub"] = tmp.([]string)[0]
	}

	attrs["saml:AuthenticatingAuthority"] = response.QueryMulti(assertion, "./saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority")
	attrs["acr"] = response.QueryMulti(assertion, "./saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef")
	//attrs["saml:AuthenticatingAuthority"] = append(attrs["saml:AuthenticatingAuthority"].([]string), attrs["iss"].(string))
	return
}

// Saml2jwt - JSON based SP interface
func Saml2jwt(w http.ResponseWriter, r *http.Request, mdHub, mdInternal, mdExternalIDP, mdExternalSP Md, requestHandler func(*goxml.Xp, *goxml.Xp, *goxml.Xp) (map[string][]string, error), defaultIdpentityid string) (err error) {
	defer r.Body.Close()
	r.ParseForm()

	// backward compatible - use either or
	entityID := r.Header.Get("X-Issuer") + r.Form.Get("issuer")
	log.Println("saml2jwt:", entityID)

	spMd, _, err := FindInMetadataSets(MdSets{mdInternal, mdExternalSP}, entityID)
	if err != nil {
		return
	}

	idpentityid := r.Form.Get("idpentityid")
	if idpentityid == "" {
		idpentityid = defaultIdpentityid
	}

	app := r.Header.Get("X-App") + r.Form.Get("app")
	acs := r.Header.Get("X-Acs") + r.Form.Get("acs")

	if _, ok := r.Form["SAMLResponse"]; ok {
		response, idpMd, _, relayState, _, _, err := DecodeSAMLMsg(r, MdSets{mdHub, mdExternalIDP}, MdSets{mdInternal, mdExternalSP}, SPRole, []string{"Response", "LogoutResponse"}, acs, nil)
		if err != nil {
			return err
		}
		privatekey, _, err := GetPrivateKeyByMethod(idpMd, "md:IDPSSODescriptor"+SigningCertQuery, x509.RSA)
		if err != nil {
			return err
		}
		switch response.QueryString(nil, "local-name(/*)") {
		case "Response":

			if err = CheckDigestAndSignatureAlgorithms(response); err != nil {
				return err
			}
			if _, err = requestHandler(response, idpMd, spMd); err != nil {
				return err
			}

			attrs := Saml2map(response)

			json, err := json.Marshal(&attrs)
			if err != nil {
				return err
			}
			jwt, _, err := JwtSign(json, privatekey, "RS256")
			if err != nil {
				return err
			}

			w.Header().Set("Authorization", "Bearer "+jwt)

			if relayState != "" {
				app, err := AuthnRequestCookie.Decode("app", relayState)
				if err != nil {
					return err
				}

				w.Header().Set("X-Accel-Redirect", string(app))
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(jwt))
			return err
		case "LogoutResponse":
			jwt, _, err := JwtSign([]byte("{}"), privatekey, "RS256")
			if err != nil {
				return err
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(jwt))
			return nil
		}
	} else if _, ok := r.Form["SAMLRequest"]; ok {
		request, idpMd, _, _, _, _, err := DecodeSAMLMsg(r, MdSets{mdHub, mdExternalIDP}, MdSets{mdInternal, mdExternalSP}, SPRole, []string{"LogoutRequest"}, acs, nil)
		if err != nil {
			return err
		}
		return SloResponse(w, r, request, spMd, idpMd, "", IDPRole)
	} else if sloinfoJSON := r.Form.Get("slo"); sloinfoJSON != "" {
		idpMd, _, err := FindInMetadataSets(MdSets{mdHub, mdExternalIDP}, idpentityid)
		if err != nil {
			return err
		}
		//sloinfo.HubRole = SPRole // NewLogoutRequest see it from a hub perspective ie. looks for a reverse role in destination md
		request, _, err := NewLogoutRequest(idpMd, &SLOInfo{HubRole: SPRole}, entityID, false)
		if err != nil {
			return err
		}
		request.QueryDashP(nil, "@ID", ID(), nil)
		u, err := SAMLRequest2URL(request, "", "", config.DefaultCryptoMethod)
		if err != nil {
			return err
		}

		http.Redirect(w, r, u.String(), http.StatusFound)
		return err
	} else if idpentityid != "" {
		idpMd, _, err := FindInMetadataSets(MdSets{mdHub, mdExternalIDP}, idpentityid)
		if err != nil {
			return err
		}

		relayState, err := AuthnRequestCookie.Encode("app", []byte(app))
		if err != nil {
			return err
		}

		request, _, err := NewAuthnRequest(nil, spMd, idpMd, "", strings.Split(r.Form.Get("idplist"), ","), acs, false, 0, 0)
		if err != nil {
			return err
		}

		u, err := SAMLRequest2URL(request, relayState, nil, config.DefaultCryptoMethod)
		if err != nil {
			return err
		}

		http.Redirect(w, r, u.String(), http.StatusFound)
		return err
	} else {
		discoveryURLTemplate := `https://wayf.wayf.dk/ds/?returnIDParam=idpentityid&entityID={{.EntityID}}&return={{.ACS}}`
		discoveryURL := template.Must(template.New("discoveryURL").Parse(discoveryURLTemplate))
		buf := new(bytes.Buffer)
		discoveryURL.Execute(buf, struct{ EntityID, ACS string }{entityID, acs})
		http.Redirect(w, r, buf.String(), http.StatusFound)
		return
	}
	return
}

// JwtSign - sign a json payload, return jwt and at_atHash
func JwtSign(payload []byte, privatekey crypto.PrivateKey, alg string) (jwt, atHash string, err error) {
	hd, _ := json.Marshal(map[string]interface{}{"typ": "JWT", "alg": alg})
	header := base64.RawURLEncoding.EncodeToString(hd) + "."
	payload = append([]byte(header), base64.RawURLEncoding.EncodeToString(payload)...)
	var dgst hash.Hash
	var signature []byte
	switch alg {
	case "EdDSA":
		dgst = sha512.New()
		dg := sha512.Sum512(payload)
		signature, err = goxml.Sign(dg[:], privatekey, "ed25519")
	case "RS256":
		dgst = sha256.New()
		dg := sha256.Sum256(payload)
		signature, err = goxml.Sign(dg[:], privatekey, "rsa256")
	case "RS512":
		dgst = sha512.New()
		dg := sha512.Sum512(payload)
		signature, err = goxml.Sign(dg[:], privatekey, "rsa512")
	default:
		return jwt, atHash, fmt.Errorf("Unsupported alg: %s", alg)
	}
	if err != nil {
		err = goxml.Wrap(err)
		return
	}

	jwt = string(payload) + "." + base64.RawURLEncoding.EncodeToString(signature)
	io.WriteString(dgst, jwt)
	atHashDigest := dgst.Sum(nil)
	atHash = base64.RawURLEncoding.EncodeToString(atHashDigest[:len(atHashDigest)/2])
	return
}

func JwtVerify(jwt string, issuerMdSets MdSets, md *goxml.Xp, path, iss string) (attrs map[string]interface{}, idpMd *goxml.Xp, err error) {
	peica := strings.Split(jwt, ".")
	if len(peica) == 5 {
		privatekey, _, err := GetPrivateKeyByMethod(md, path, x509.RSA)
		if err != nil {
			return nil, nil, err
		}
		jwt, err = goxml.DeJwe(peica, privatekey)
		if err != nil {
			return nil, nil, err
		}
	}

	hps := strings.SplitN(jwt, ".", 3)
	if len(hps) != 3 {
		return nil, nil, fmt.Errorf("Not a valid jws")
	}
	payload, err := base64.RawURLEncoding.DecodeString(hps[1])
	if err != nil {
		return
	}

	hp := []byte(strings.Join(hps[:2], "."))
	headerJSON, _ := base64.RawURLEncoding.DecodeString(hps[0])
	header := struct{ Alg string }{}
	err = json.Unmarshal(headerJSON, &header)
	if err != nil {
		return
	}
	var hh crypto.Hash
	var digest []byte
	switch header.Alg {
	case "RS256":
		dg := sha256.Sum256(hp)
		digest = dg[:]
		hh = crypto.SHA256
	case "RS384":
		dg := sha512.Sum384(hp)
		digest = dg[:]
		hh = crypto.SHA384
	case "RS512":
		dg := sha512.Sum512(hp)
		digest = dg[:]
		hh = crypto.SHA512
	default:
		return nil, nil, fmt.Errorf("Unsupported alg: %s", header.Alg)
	}

	err = json.Unmarshal(payload, &attrs)
	if err != nil {
		return
	}
	if iss == "" {
		iss, _ = attrs["iss"].(string) // no reason to error already - we won't find any md later
	}
	idpMd, _, err = FindInMetadataSets(issuerMdSets, iss)
	if err != nil {
		return
	}

	certs := idpMd.QueryMulti(nil, "./md:IDPSSODescriptor"+SigningCertQuery)
	signature, _ := base64.RawURLEncoding.DecodeString(hps[2])
	switch header.Alg {
	case "RS256", "RS384", "RS512":
		_, _, pubs, err := PublicKeyInfoByMethod(certs, x509.RSA)
		for _, pub := range pubs {
			err = rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), hh, digest, signature)
			if err == nil {
				err = json.Unmarshal(payload, &attrs)
				if err == nil {
					return attrs, idpMd, err
				}
			}
		}
		return nil, nil, fmt.Errorf("jwtVerify failed")
	}
	return nil, nil, errors.New("jwtVerify failed")
}

// CheckDigestAndSignatureAlgorithms -
func CheckDigestAndSignatureAlgorithms(response *goxml.Xp) (err error) {
	contexts := []string{"/samlp:Response/ds:Signature/ds:SignedInfo/", "/samlp:Response/saml:Assertion/ds:Signature/ds:SignedInfo/"}
	signatureMethod := "ds:SignatureMethod/@Algorithm"
	digestMethod := "ds:Reference/ds:DigestMethod/@Algorithm"
	seen := 0
	for _, context := range contexts {
		sigMethod := response.Query1(nil, context+signatureMethod)
		digMethod := response.Query1(nil, context+digestMethod)
		for _, method := range config.CryptoMethods {
			if sigMethod == method.SigningMethod {
				seen++
			}
			if digMethod == method.DigestMethod {
				seen++
			}
		}
	}
	if seen < 2 {
		return fmt.Errorf("No or to few Digest/Signing algoritms found")
	}
	return
}

// Encode using hand-held MessagePack for keeping the size down - no double base64 encodings
func (h *Hm) Encode(id string, msg []byte) (str string, err error) {
	bts, err := h.innerSign(id, msg, time.Now().Unix())
	str = base64.RawURLEncoding.EncodeToString(bts)
	return
}

// Decode - the whole message
func (h *Hm) Decode(id, in string) ([]byte, error) {
	signedMsg, _ := base64.RawURLEncoding.DecodeString(in)
	return h.innerValidate(id, signedMsg)
}

func (h *Hm) innerSign(id string, msg []byte, ts int64) (signedMsg []byte, err error) {
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, uint32(ts))
	hash := hmac.New(h.Hash, h.Key)
	hash.Write([]byte(id))
	hash.Write([]byte(bs))
	hash.Write(msg)

	signedMsg = append(signedMsg, 0xc4, 0x10)
	signedMsg = append(signedMsg, hash.Sum(nil)[:16]...)
	signedMsg = append(signedMsg, 0xd6, 0xFF)
	signedMsg = append(signedMsg, bs...)
	signedMsg = append(signedMsg, msg...)
	return signedMsg, nil
}

func (h *Hm) innerValidate(id string, signedMsg []byte) (msg []byte, err error) {
	ts := int64(binary.BigEndian.Uint32(signedMsg[20:24]))
	msg = signedMsg[24:]
	computed, err := h.innerSign(id, msg, ts)
	if err != nil {
		return
	}
	if hmac.Equal(signedMsg[:24], []byte(computed)[:24]) {
		// secure cookie timeout has to be testable
		now := TestTime
		if now.IsZero() {
			now = time.Now()
		}
		diff := now.Unix() - ts
		if diff >= 0 && diff < h.TTL {
			return msg, nil
		}
	}
	return nil, goxml.NewWerror("hmac failed")
}

// Marshal hand-held marshal SamlRequest
func (r SamlRequest) Marshal() (msg []byte) {
	prefix := []byte{}
	for _, str := range []string{r.RequestID} {
		l := len(str)
		prefix = append(prefix, byte(l>>8), byte(l)) // if over 65535 we are in trouble
		msg = append(msg, str...)
	}
	for _, str := range []string{r.Nonce, r.SP, r.IDP, r.VirtualIDP, r.WAYFSP, r.AssertionConsumerIndex, r.Protocol, r.IDPProtocol} {
		prefix = append(prefix, uint8(len(str))) // if over 255 we are in trouble
		msg = append(msg, str...)
	}
	msg = append(msg, r.NameIDFormat+97, r.SPIndex+97, r.HubBirkIndex+97) // use a-z for small numbers 0-26 that does not need to be b64 encoded
	msg = append(prefix, msg...)
	msg = append([]byte{byte(len(prefix) + 97)}, msg...)
	return
}

// Unmarshal - hand held unmarshal for SamlRequest
func (r *SamlRequest) Unmarshal(msg []byte) {
	i := int(msg[0]-97) + 1 // start of texts
	j := 1
	for _, x := range []*string{&r.RequestID} {
		l := int(msg[j])<<8 + int(msg[j+1])
		j += 2
		*x = string(msg[i : i+l])
		i = i + l
	}

	for _, x := range []*string{&r.Nonce, &r.SP, &r.IDP, &r.VirtualIDP, &r.WAYFSP, &r.AssertionConsumerIndex, &r.Protocol, &r.IDPProtocol} {
		l := int(msg[j])
		j++
		*x = string(msg[i : i+l])
		i = i + l
	}
	r.NameIDFormat = msg[i] - 97 // cheap char to int8
	r.SPIndex = msg[i+1] - 97
	r.HubBirkIndex = msg[i+2] - 97
	return
}

// Marshal - hand-held marshal for SLOInfo struct - save some b64 encoding by keeping ascii values at end
func (sil SLOInfoList) Marshal() (msg []byte) {
	n := 0
	prefix := []byte{}
	for _, r := range sil {
		fields := []string{r.IDP, r.SP, r.NameID, r.SPNameQualifier, r.SessionIndex, r.ID, r.Protocol}
		n = len(fields)
		for _, str := range fields {
			l := len(str)
	    	prefix = append(prefix, byte(0xff & (l >> 8)), byte(0xff & l)) // signals string longer than 254 when decoding
    		msg = append(msg, str...)
		}
		msg = append(msg, r.NameIDFormat+97, r.HubRole+97, r.SLOStatus+97, B2I[r.SLOSupport]+97, B2I[r.Async]+97)
	}
	msg = append(prefix, msg...)
	msg = append([]byte{byte(len(sil) + 97), byte(n + 97)}, msg...)
	return
}

// Unmarshal - hand-held unmarshal for SLOInfo struct
func (sil *SLOInfoList) Unmarshal(msg []byte) {
	length := len(msg)
	if length == 0 {
		return
	}
	i := int((msg[0]-97)*(msg[1]-97)*2) + 2 // num records and number of b64 encoded string lengths
	j := 2
	for {
		if i == length {
			break
		}
		r := SLOInfo{}
		for _, x := range []*string{&r.IDP, &r.SP, &r.NameID, &r.SPNameQualifier, &r.SessionIndex, &r.ID, &r.Protocol} {
			l := int(msg[j]) << 8 + int(msg[j+1])
			*x = string(msg[i : i+l])
			i = i + l
			j = j + 2
		}
		r.NameIDFormat = msg[i] - 97
		i++
		r.HubRole = msg[i] - 97
		i++
		r.SLOStatus = msg[i] - 97
		i++
		r.SLOSupport = msg[i]-97 != 0
		i++
		r.Async = msg[i]-97 != 0
		i++
		*sil = append(*sil, r)
	}
	return
}
