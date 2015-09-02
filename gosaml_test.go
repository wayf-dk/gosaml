package gosaml

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
//	"log"
//    "testing"
)

var (
response = []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                ID="zf0de122f115e3bb7e0c2eebcc4537ac44189c6dc"
                Version="2.0"
                IssueInstant="2015-08-31T07:56:12Z"
                InResponseTo="_0fd2d0b6be1b06574654626c5191a427486893c6"
                Destination="https://phph.wayf.dk"
                >
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://birk.wayf.dk/birk.php/orphanage.wayf.dk</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </samlp:Status>
    <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                    xmlns:xs="http://www.w3.org/2001/XMLSchema"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="pfx704769d9-22c0-8f24-eec3-6c43ca7ce30e"
                    Version="2.0"
                    IssueInstant="2015-08-31T07:56:11Z"
                    >
        <saml:Issuer>https://birk.wayf.dk/birk.php/orphanage.wayf.dk</saml:Issuer>
        <saml:Subject>
            <saml:NameID SPNameQualifier="https://birk.wayf.dk/birk.php/metadata.wayf.dk/PHPh-proxy"
                         Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
                         >_6c41e4c164d64aee825cdecc23ca67187f4741f390</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter="2015-08-31T08:01:11Z"
                                              Recipient="https://phph.wayf.dk"
                                              InResponseTo="_0fd2d0b6be1b06574654626c5191a427486893c6"
                                              />
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="2015-08-31T07:55:41Z"
                         NotOnOrAfter="2015-08-31T08:01:11Z"
                         >
            <saml:AudienceRestriction>
                <saml:Audience>https://metadata.wayf.dk/PHPh</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="2015-08-31T07:56:09Z"
                             SessionNotOnOrAfter="2015-08-31T15:56:11Z"
                             SessionIndex="_556e8dad5ac1586a81d484f15a6c91ee81a6c02c36"
                             >
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
                <saml:AuthenticatingAuthority>https://orphanage.wayf.dk</saml:AuthenticatingAuthority>
                <saml:AuthenticatingAuthority>https://wayf.wayf.dk</saml:AuthenticatingAuthority>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
            <saml:Attribute Name="eduPersonPrincipalName"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">joe@example.com</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`)

privatekey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----`)

metadata = []byte(`<?xml version="1.0"?>
<md:EntityDescriptor xmlns:wayf="http://wayf.dk/2014/08/wayf" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://birk.wayf.dk/birk.php/wayf.ait.dtu.dk/saml2/idp/metadata.php">
  <md:Extensions>
    <mdrpi:RegistrationInfo registrationInstant="2015-05-12T14:25:09Z" registrationAuthority="https://www.wayf.dk">
      <mdrpi:RegistrationPolicy xml:lang="en">http://wayf.dk/images/stories/WAYF-filer/metadataregistrationpracticestatementwayf.pdf</mdrpi:RegistrationPolicy>
    </mdrpi:RegistrationInfo>
  </md:Extensions>
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:Extensions>
      <shibmd:Scope regexp="false">dtu.dk</shibmd:Scope>
      <mdui:UIInfo>
        <mdui:DisplayName xml:lang="da">Danmarks Tekniske Universitet</mdui:DisplayName>
        <mdui:DisplayName xml:lang="en">Technical University of Denmark</mdui:DisplayName>
      </mdui:UIInfo>
      <mdui:DiscoHints>
        <mdui:DomainHint>dtu.dk</mdui:DomainHint>
      </mdui:DiscoHints>
    </md:Extensions>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIC5jCCAc4CAQcwDQYJKoZIhvcNAQELBQAwOTE3MDUGA1UEAwwuaHR0cHM6Ly93
YXlmLmFpdC5kdHUuZGsvc2FtbDIvaWRwL21ldGFkYXRhLnBocDAeFw0xNTAxMDEw
MDAwMDBaFw0yNTEyMzEyMzU5NTlaMDkxNzA1BgNVBAMMLmh0dHBzOi8vd2F5Zi5h
aXQuZHR1LmRrL3NhbWwyL2lkcC9tZXRhZGF0YS5waHAwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDHiAwKahBTuI4Z+IJ1rgOeEiCCy3bR9QIe3BpCsejF
CU5rSzkWANqVuc1PDfp0JdIZhrPXsmDJQMmidPCGPIDQKo+bk+af3+EUFS/I/+35
sSBX2vf+h1DHvZV9jsznmpSVjp7HZ/WoPWBykWBJO0AOVmzB5zlaqkS36J76+wxe
rwdpuExVnYSNd73S+AyT/EZ+tXAO+6lQ8FL/YMlJnUkSaSqLSHFy01D2qBNmYRwB
pCS6/dUZyxi0t5j8ghKUD4BHOZVavn65J62cJdXiOcMRyUAIp57GXQrL63KtrjIc
Xddq+CZyZ5t37EdUOIz42joFcy73MFOntynlKEvOw1BJAgMBAAEwDQYJKoZIhvcN
AQELBQADggEBAFLiQoHCoNhKCkBY6mFKLePGqnubEwiHRvnAFwDTbzhM1l1m5ZUW
iHF23a7Rcg1KHVp4LQ3OgbeH5FVssEBRHyINDlFrdTHozYtzeDkTZgi7/Cg24wqQ
BnVtITujEJatVPNyfYN2ID8DMVNB+7x7iRpRbusj05UGcguFvkRPF/s9OhKkEHuY
CmpPNruZm9ubkqkJ/8jRLuL4oCxQ0O7INGbNn3tKhka0ekEeuj6qfod0D5zJvTSL
3v6mMX8MkShdTtY7SLyT90nN6t/4cW7tvi9HVhBOFr/N+vBQkm58rCWcV/+nw2OV
yPzz3RRNmKq5lLVVYikx8FVc4IVMw9++ixM=
</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIC5jCCAc4CAQcwDQYJKoZIhvcNAQELBQAwOTE3MDUGA1UEAwwuaHR0cHM6Ly93
YXlmLmFpdC5kdHUuZGsvc2FtbDIvaWRwL21ldGFkYXRhLnBocDAeFw0xNTAxMDEw
MDAwMDBaFw0yNTEyMzEyMzU5NTlaMDkxNzA1BgNVBAMMLmh0dHBzOi8vd2F5Zi5h
aXQuZHR1LmRrL3NhbWwyL2lkcC9tZXRhZGF0YS5waHAwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDHiAwKahBTuI4Z+IJ1rgOeEiCCy3bR9QIe3BpCsejF
CU5rSzkWANqVuc1PDfp0JdIZhrPXsmDJQMmidPCGPIDQKo+bk+af3+EUFS/I/+35
sSBX2vf+h1DHvZV9jsznmpSVjp7HZ/WoPWBykWBJO0AOVmzB5zlaqkS36J76+wxe
rwdpuExVnYSNd73S+AyT/EZ+tXAO+6lQ8FL/YMlJnUkSaSqLSHFy01D2qBNmYRwB
pCS6/dUZyxi0t5j8ghKUD4BHOZVavn65J62cJdXiOcMRyUAIp57GXQrL63KtrjIc
Xddq+CZyZ5t37EdUOIz42joFcy73MFOntynlKEvOw1BJAgMBAAEwDQYJKoZIhvcN
AQELBQADggEBAFLiQoHCoNhKCkBY6mFKLePGqnubEwiHRvnAFwDTbzhM1l1m5ZUW
iHF23a7Rcg1KHVp4LQ3OgbeH5FVssEBRHyINDlFrdTHozYtzeDkTZgi7/Cg24wqQ
BnVtITujEJatVPNyfYN2ID8DMVNB+7x7iRpRbusj05UGcguFvkRPF/s9OhKkEHuY
CmpPNruZm9ubkqkJ/8jRLuL4oCxQ0O7INGbNn3tKhka0ekEeuj6qfod0D5zJvTSL
3v6mMX8MkShdTtY7SLyT90nN6t/4cW7tvi9HVhBOFr/N+vBQkm58rCWcV/+nw2OV
yPzz3RRNmKq5lLVVYikx8FVc4IVMw9++ixM=
</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://birk.wayf.dk/birk.php/wayf.ait.dtu.dk/saml2/idp/SSOService.php"/>
  </md:IDPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="da">Danmarks Tekniske Universitet</md:OrganizationName>
    <md:OrganizationName xml:lang="en">Technical University of Denmark</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="da">Danmarks Tekniske Universitet</md:OrganizationDisplayName>
    <md:OrganizationDisplayName xml:lang="en">Technical University of Denmark</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="da">http://www.dtu.dk</md:OrganizationURL>
    <md:OrganizationURL xml:lang="en">http://www.dtu.dk/English.aspx</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="technical">
    <md:GivenName>WAYF</md:GivenName>
    <md:SurName>Operations</md:SurName>
    <md:EmailAddress>drift@wayf.dk</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>`)
)

func ExampleSignAndValidate() {
	block, _ := pem.Decode(privatekey)
	priv, _  := x509.ParsePKCS1PrivateKey(block.Bytes)

	xp := New(response)
	assertion := xp.Query("saml:Assertion[1]", nil)[0]
	xp.Sign(assertion, priv, "sha256")

	xp = New([]byte(xp.Pp()))

	fmt.Println(xp.Q1("saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm", nil))
	fmt.Println(xp.Q1("/samlp:Response/saml:Assertion/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm", nil))

	assertion = xp.Query("saml:Assertion[1]", nil)[0]

	pub := &priv.PublicKey

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion, pub))
        // Output:

	xp.Sign(assertion, priv, "sha1")
	//log.Print(xp.C14n(nil))

	xp = New([]byte(xp.Pp()))

	fmt.Println(xp.Q1("saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm", nil))
	fmt.Println(xp.Q1("saml:Assertion/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm", nil))
	fmt.Println(xp.Q1("saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue", nil))
	fmt.Println(xp.Q1("saml:Assertion/ds:Signature/ds:SignatureValue", nil))
    // Output:
    // http://www.w3.org/2001/04/xmlenc#sha256
    // http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    // verify: true
    // http://www.w3.org/2000/09/xmldsig#sha1
    // http://www.w3.org/2000/09/xmldsig#rsa-sha1
    // PpfypKN3QeBy3DTjzZx3cgA6KfA=
    // LlDp6BWKMiQZOapOaUKH2rwrk3tU5xLqLh5cb8LdgZ4z3nFn0Ok0+AC+9kHCHtIxmdyGYwrIg35MsSM/y1FZ1il65bMufHwBY4D8rXWqO2wEKNRYq01n1pb/g74AMFkBjtasfPMXl7CF6jl+dZw7yiSf8dRfXTLLHTkT1MAGp6A=
}

func ExampleMetadata() {
	md := New(metadata)
    fmt.Println(md.Q1("/md:EntityDescriptor/@entityID", nil))
    fmt.Println(md.Q1("/md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat", nil))
    // Output:
    // https://birk.wayf.dk/birk.php/wayf.ait.dtu.dk/saml2/idp/metadata.php
    // urn:oasis:names:tc:SAML:2.0:nameid-format:transient
}

func ExampleQueryDashP_1() {
	xp := New(response)
    xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[1]`, "anton", nil)
    xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`, "banton", nil)

    fmt.Println(xp.Q1(`saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`, nil))
    fmt.Println(xp.Q1(`saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[2]`, nil))
    fmt.Println(xp.Q1(`saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[1]`, nil))
    // Output:
    // banton
    // https://wayf.wayf.dk
    // anton
}

func ExampleQueryDashP_2() {
	xp := New([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`))
    xp.QueryDashP(nil, `/samlp:Response/@ID`, "zf0de122f115e3bb7e0c2eebcc4537ac44189c6dc", nil)
    xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`, "banton", nil)

    fmt.Print(xp.Pp())
    fmt.Println(xp.Q1(`saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`, nil))
    // Output:
    // <?xml version="1.0"?>
    // <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="zf0de122f115e3bb7e0c2eebcc4537ac44189c6dc">
    //   <saml:Assertion>
    //     <saml:AuthnStatement>
    //       <saml:AuthnContext>
    //         <saml:AuthenticatingAuthority/>
    //         <saml:AuthenticatingAuthority/>
    //         <saml:AuthenticatingAuthority>banton</saml:AuthenticatingAuthority>
    //       </saml:AuthnContext>
    //     </saml:AuthnStatement>
    //   </saml:Assertion>
    // </samlp:Response>
    // banton
}



