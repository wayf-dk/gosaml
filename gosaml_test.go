package gosaml

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

type Testparams struct {
	spmd, idpmd, hubmd, testidpmd *Xp
	cookiejar                     map[string]map[string]*http.Cookie
	idpentityID                   string
	usescope                      bool
	usedoubleproxy                bool
	resolv                        map[string]string
	initialrequest                *Xp
	newresponse                   *Xp
	resp                          *http.Response
	responsebody                  []byte
	err                           error
	logredirects                  bool
}

var (
	_  = log.Printf // For debugging; delete when done.
	wg sync.WaitGroup

	mdq = "https://phph.wayf.dk/MDQ/"

	spmetadata, idpmetadata, hubmetadata, testidpmetadata, testidpviabirkmetadata *Xp

	attributestmt = []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                >
        <saml:AttributeStatement>
            <saml:Attribute Name="cn"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Mads Freek Petersen</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="eduPersonEntitlement"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">https://wayf.dk/kanja/admin</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://wayf.dk/orphanage/admin</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://wayf.dk/vo/admin</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="organizationName"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">WAYF Where Are You From</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="preferredLanguage"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">da</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="mail"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">freek@wayf.dk</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="eduPersonPrincipalName"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">gikcaswid@orphanage.wayf.dk</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="gn"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Mads Freek</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="sn"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Petersen</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="eduPersonPrimaryAffiliation"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">member</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="eduPersonAssurance"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">1</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="schacHomeOrganization"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">orphanage.wayf.dk</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="schacHomeOrganizationType"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:homeOrganizationType:int:NRENAffiliate</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="eduPersonTargetedID"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">WAYF-DK-a462971438f09f28b0cf806965a5b5461376815b</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:2.5.4.3"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Mads Freek Petersen</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">https://wayf.dk/kanja/admin</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://wayf.dk/orphanage/admin</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://wayf.dk/vo/admin</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:2.5.4.10"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">WAYF Where Are You From</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:2.16.840.1.113730.3.1.39"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">da</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">freek@wayf.dk</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">gikcaswid@orphanage.wayf.dk</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:2.5.4.42"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Mads Freek</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:2.5.4.4"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Petersen</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.5"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">member</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.11"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">1</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.9"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">orphanage.wayf.dk</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.10"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:homeOrganizationType:int:NRENAffiliate</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">WAYF-DK-a462971438f09f28b0cf806965a5b5461376815b</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
</samlp:Response>
`)

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
                <saml:AttributeValue xsi:type="xs:string">gikcaswid@orphanage.wayf.dk</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                            >
                <saml:AttributeValue xsi:type="xs:string">gikcaswid@orphanage.wayf.dk</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">only@thisone.example.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:2.5.4.42"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                            >
                <saml:AttributeValue xsi:type="xs:string">anton</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">banton</saml:AttributeValue>
            </saml:Attribute>

        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`)

	privatekey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`

	wayfmdxml = []byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" entityID="https://wayf.wayf.dk">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:Extensions>
      <mdui:UIInfo xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">
        <mdui:Description xml:lang="da">WAYF - den danske identitetsfederation for forskning og uddannelse</mdui:Description>
        <mdui:Description xml:lang="en">WAYF - The Danish identity federation for research and higher education</mdui:Description>
        <mdui:DisplayName xml:lang="da">WAYF - Where Are You From</mdui:DisplayName>
        <mdui:DisplayName xml:lang="en">WAYF - Where Are You From</mdui:DisplayName>
      </mdui:UIInfo>
      <shibmd:Scope regexp="false">adm.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">aub.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">civil.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">create.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">es.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">hst.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">id.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">its.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">learning.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">m-tech.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">plan.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sbi.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">staff.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">student.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">kb.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">hi.is</shibmd:Scope>
      <shibmd:Scope regexp="false">ruc.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">orphanage.wayf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ucl.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">viauc.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ucc.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">drlund-gym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">iha.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sdu.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">itu.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">aip.itsf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">gg.itsf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">lg.itsf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">mg.itsf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sosur.itsf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sska.itsf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sss.itsf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">its.itsf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sikker-adgang.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ibc.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">natmus.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">rungsted-gym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ucsj.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sosuc.cphwest.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">dab.minibib.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ism.minibib.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">fbo.minibib.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">fsv.minibib.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">vfc.minibib.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">dsl.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">zbc.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">frsgym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">cbs.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">uniit.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">dskd.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ku.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">kristne-gym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">dsn.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">vordingborg-gym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">dmjx.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">hasseris-gym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">apoteket.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">erhvervsakademiaarhus.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">kadk.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">dtu.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ucn.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">frhavn-gym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sde.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">eal.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">hrs.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sceu.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">vgtgym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">odense.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">au.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">knord.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">vibkat.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">vghf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">eucnord.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">phmetropol.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">handelsskolen.com</shibmd:Scope>
      <shibmd:Scope regexp="false">cphbusiness.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">kea.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">eadania.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">dansidp.stads.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">umit.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">campusvejle.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">rosborg-gym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">fhavnhs.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ah.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">basyd.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">statsbiblioteket.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">eamv.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">aams.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">regionsjaelland.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">fms.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">smk.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">msk.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">drcmr.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">simac.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ucsyd.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">this.is.not.a.valid.idp</shibmd:Scope>
    </md:Extensions>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIE3TCCA8WgAwIBAgISESFgDbqp6YXwPvILGKAnrUDtMA0GCSqGSIb3DQEBBQUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS0wKwYDVQQDEyRHbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBIC0gRzIwHhcNMTIwMTA0MDkzNTU0WhcNMTcwMTAzMDkzNTU0WjBHMQswCQYDVQQGEwJESzEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRUwEwYDVQQDEwx3YXlmLndheWYuZGswggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAosqmcujXhA49vHQLLTKZxFTz3guMRnwHvUxz5vvuMPYVTGl+fXPdq9ULhkNc1jlCr4+pFOwLdy9zkuAn8dK7grQEaU58K0uF4MTyKixFnPvU3806roL8PnrmUQ2t8y76U9jzsk/B3Ggi5pVqhOktHpZyzz1yBpE14R+/DPzHrpKIFJY4N2uzoBrcEAsJY6aTUfIaB/NEpe4BY8sDZ3CTuU3tWUfhdlZESYsmngdnHD6k0HUKti9F43UM6JyN6fz7T70JlHAcTHzYKhjtPLcWG8lWFqNtry7fCYC5SlKn4zmyifoASxRoH3EuxtE/Fmmt+M6I83kg3H0R1b8PHimfAgMBAAGjggGxMIIBrTAOBgNVHQ8BAf8EBAMCBaAwTAYDVR0gBEUwQzBBBgkrBgEEAaAyAQowNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wFwYDVR0RBBAwDoIMd2F5Zi53YXlmLmRrMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3MvZ3Nkb21haW52YWxnMi5jcmwwgYgGCCsGAQUFBwEBBHwwejBBBggrBgEFBQcwAoY1aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nkb21haW52YWxnMi5jcnQwNQYIKwYBBQUHMAGGKWh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9nc2RvbWFpbnZhbGcyMB0GA1UdDgQWBBS44PHFNUdj1NTiqkjShHfvW50SIzAfBgNVHSMEGDAWgBSWrfqwW7mDZCp2whyKadpC3P79KDANBgkqhkiG9w0BAQUFAAOCAQEAjqwtcRjT+gYKMhgwpJ4MNpL6W80efrcMDdWnZUJzN081ht0dcQqvdAVjkWylEQbbS1LXc9OZecRJGR1vxBzS7bq0lRauPuYodzOsDzP4cEW/W+PvWIEIpm5yIBZ31P7VnRpaRwmeff8OlhDOvM4+wdovRvIpLgyeyW05R2i4DenI8juCaWXNG+CATj35gW3uh/LD9DBzpZDoQ41/5yJPZUuiHfZtnW0M7oVnhidn5sT319Xiag3Jlqe7dx1D+b0oZVDTbwrECOdROTcbOkbGsr4VleBcTtL5RoF4cDokYB6LpIDmSMiBV6DztPcrPC/ERS/tEBMbfMWVAus4f0SvdQ==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIE3TCCA8WgAwIBAgISESFgDbqp6YXwPvILGKAnrUDtMA0GCSqGSIb3DQEBBQUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS0wKwYDVQQDEyRHbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBIC0gRzIwHhcNMTIwMTA0MDkzNTU0WhcNMTcwMTAzMDkzNTU0WjBHMQswCQYDVQQGEwJESzEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRUwEwYDVQQDEwx3YXlmLndheWYuZGswggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAosqmcujXhA49vHQLLTKZxFTz3guMRnwHvUxz5vvuMPYVTGl+fXPdq9ULhkNc1jlCr4+pFOwLdy9zkuAn8dK7grQEaU58K0uF4MTyKixFnPvU3806roL8PnrmUQ2t8y76U9jzsk/B3Ggi5pVqhOktHpZyzz1yBpE14R+/DPzHrpKIFJY4N2uzoBrcEAsJY6aTUfIaB/NEpe4BY8sDZ3CTuU3tWUfhdlZESYsmngdnHD6k0HUKti9F43UM6JyN6fz7T70JlHAcTHzYKhjtPLcWG8lWFqNtry7fCYC5SlKn4zmyifoASxRoH3EuxtE/Fmmt+M6I83kg3H0R1b8PHimfAgMBAAGjggGxMIIBrTAOBgNVHQ8BAf8EBAMCBaAwTAYDVR0gBEUwQzBBBgkrBgEEAaAyAQowNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wFwYDVR0RBBAwDoIMd2F5Zi53YXlmLmRrMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3MvZ3Nkb21haW52YWxnMi5jcmwwgYgGCCsGAQUFBwEBBHwwejBBBggrBgEFBQcwAoY1aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nkb21haW52YWxnMi5jcnQwNQYIKwYBBQUHMAGGKWh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9nc2RvbWFpbnZhbGcyMB0GA1UdDgQWBBS44PHFNUdj1NTiqkjShHfvW50SIzAfBgNVHSMEGDAWgBSWrfqwW7mDZCp2whyKadpC3P79KDANBgkqhkiG9w0BAQUFAAOCAQEAjqwtcRjT+gYKMhgwpJ4MNpL6W80efrcMDdWnZUJzN081ht0dcQqvdAVjkWylEQbbS1LXc9OZecRJGR1vxBzS7bq0lRauPuYodzOsDzP4cEW/W+PvWIEIpm5yIBZ31P7VnRpaRwmeff8OlhDOvM4+wdovRvIpLgyeyW05R2i4DenI8juCaWXNG+CATj35gW3uh/LD9DBzpZDoQ41/5yJPZUuiHfZtnW0M7oVnhidn5sT319Xiag3Jlqe7dx1D+b0oZVDTbwrECOdROTcbOkbGsr4VleBcTtL5RoF4cDokYB6LpIDmSMiBV6DztPcrPC/ERS/tEBMbfMWVAus4f0SvdQ==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://wayf.wayf.dk/saml2/idp/SingleLogoutService.php"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://wayf.wayf.dk/saml2/idp/SSOService.php"/>
  </md:IDPSSODescriptor> <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol">
   <md:KeyDescriptor use="signing">
     <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
       <ds:X509Data>
         <ds:X509Certificate>MIIE3TCCA8WgAwIBAgISESFgDbqp6YXwPvILGKAnrUDtMA0GCSqGSIb3DQEBBQUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS0wKwYDVQQDEyRHbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBIC0gRzIwHhcNMTIwMTA0MDkzNTU0WhcNMTcwMTAzMDkzNTU0WjBHMQswCQYDVQQGEwJESzEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRUwEwYDVQQDEwx3YXlmLndheWYuZGswggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAosqmcujXhA49vHQLLTKZxFTz3guMRnwHvUxz5vvuMPYVTGl+fXPdq9ULhkNc1jlCr4+pFOwLdy9zkuAn8dK7grQEaU58K0uF4MTyKixFnPvU3806roL8PnrmUQ2t8y76U9jzsk/B3Ggi5pVqhOktHpZyzz1yBpE14R+/DPzHrpKIFJY4N2uzoBrcEAsJY6aTUfIaB/NEpe4BY8sDZ3CTuU3tWUfhdlZESYsmngdnHD6k0HUKti9F43UM6JyN6fz7T70JlHAcTHzYKhjtPLcWG8lWFqNtry7fCYC5SlKn4zmyifoASxRoH3EuxtE/Fmmt+M6I83kg3H0R1b8PHimfAgMBAAGjggGxMIIBrTAOBgNVHQ8BAf8EBAMCBaAwTAYDVR0gBEUwQzBBBgkrBgEEAaAyAQowNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wFwYDVR0RBBAwDoIMd2F5Zi53YXlmLmRrMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3MvZ3Nkb21haW52YWxnMi5jcmwwgYgGCCsGAQUFBwEBBHwwejBBBggrBgEFBQcwAoY1aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nkb21haW52YWxnMi5jcnQwNQYIKwYBBQUHMAGGKWh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9nc2RvbWFpbnZhbGcyMB0GA1UdDgQWBBS44PHFNUdj1NTiqkjShHfvW50SIzAfBgNVHSMEGDAWgBSWrfqwW7mDZCp2whyKadpC3P79KDANBgkqhkiG9w0BAQUFAAOCAQEAjqwtcRjT+gYKMhgwpJ4MNpL6W80efrcMDdWnZUJzN081ht0dcQqvdAVjkWylEQbbS1LXc9OZecRJGR1vxBzS7bq0lRauPuYodzOsDzP4cEW/W+PvWIEIpm5yIBZ31P7VnRpaRwmeff8OlhDOvM4+wdovRvIpLgyeyW05R2i4DenI8juCaWXNG+CATj35gW3uh/LD9DBzpZDoQ41/5yJPZUuiHfZtnW0M7oVnhidn5sT319Xiag3Jlqe7dx1D+b0oZVDTbwrECOdROTcbOkbGsr4VleBcTtL5RoF4cDokYB6LpIDmSMiBV6DztPcrPC/ERS/tEBMbfMWVAus4f0SvdQ==</ds:X509Certificate>
       </ds:X509Data>
     </ds:KeyInfo>
   </md:KeyDescriptor>
   <md:KeyDescriptor use="encryption">
     <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
       <ds:X509Data>
         <ds:X509Certificate>MIIE3TCCA8WgAwIBAgISESFgDbqp6YXwPvILGKAnrUDtMA0GCSqGSIb3DQEBBQUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS0wKwYDVQQDEyRHbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBIC0gRzIwHhcNMTIwMTA0MDkzNTU0WhcNMTcwMTAzMDkzNTU0WjBHMQswCQYDVQQGEwJESzEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRUwEwYDVQQDEwx3YXlmLndheWYuZGswggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAosqmcujXhA49vHQLLTKZxFTz3guMRnwHvUxz5vvuMPYVTGl+fXPdq9ULhkNc1jlCr4+pFOwLdy9zkuAn8dK7grQEaU58K0uF4MTyKixFnPvU3806roL8PnrmUQ2t8y76U9jzsk/B3Ggi5pVqhOktHpZyzz1yBpE14R+/DPzHrpKIFJY4N2uzoBrcEAsJY6aTUfIaB/NEpe4BY8sDZ3CTuU3tWUfhdlZESYsmngdnHD6k0HUKti9F43UM6JyN6fz7T70JlHAcTHzYKhjtPLcWG8lWFqNtry7fCYC5SlKn4zmyifoASxRoH3EuxtE/Fmmt+M6I83kg3H0R1b8PHimfAgMBAAGjggGxMIIBrTAOBgNVHQ8BAf8EBAMCBaAwTAYDVR0gBEUwQzBBBgkrBgEEAaAyAQowNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wFwYDVR0RBBAwDoIMd2F5Zi53YXlmLmRrMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3MvZ3Nkb21haW52YWxnMi5jcmwwgYgGCCsGAQUFBwEBBHwwejBBBggrBgEFBQcwAoY1aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nkb21haW52YWxnMi5jcnQwNQYIKwYBBQUHMAGGKWh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9nc2RvbWFpbnZhbGcyMB0GA1UdDgQWBBS44PHFNUdj1NTiqkjShHfvW50SIzAfBgNVHSMEGDAWgBSWrfqwW7mDZCp2whyKadpC3P79KDANBgkqhkiG9w0BAQUFAAOCAQEAjqwtcRjT+gYKMhgwpJ4MNpL6W80efrcMDdWnZUJzN081ht0dcQqvdAVjkWylEQbbS1LXc9OZecRJGR1vxBzS7bq0lRauPuYodzOsDzP4cEW/W+PvWIEIpm5yIBZ31P7VnRpaRwmeff8OlhDOvM4+wdovRvIpLgyeyW05R2i4DenI8juCaWXNG+CATj35gW3uh/LD9DBzpZDoQ41/5yJPZUuiHfZtnW0M7oVnhidn5sT319Xiag3Jlqe7dx1D+b0oZVDTbwrECOdROTcbOkbGsr4VleBcTtL5RoF4cDokYB6LpIDmSMiBV6DztPcrPC/ERS/tEBMbfMWVAus4f0SvdQ==</ds:X509Certificate>
       </ds:X509Data>
     </ds:KeyInfo>
   </md:KeyDescriptor>
   <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://wayf.wayf.dk/module.php/saml/sp/saml2-logout.php/wayf.wayf.dk"/>
   <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://wayf.wayf.dk/module.php/saml/sp/saml2-acs.php/wayf.wayf.dk" index="0"/>
   <md:AttributeConsumingService index="0">
     <md:ServiceName xml:lang="en">WAYF - Where are you from</md:ServiceName>
     <md:ServiceName xml:lang="da">WAYF - Where are you from</md:ServiceName>
     <md:ServiceDescription xml:lang="en">Denmarks Identity Federation for Education and Research.</md:ServiceDescription>
     <md:ServiceDescription xml:lang="da">Danmarks Identitetsfoederation for Uddannelse og Forskning.</md:ServiceDescription>
     <md:RequestedAttribute Name="sn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" isRequired="true"/>
     <md:RequestedAttribute Name="gn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" isRequired="true"/>
     <md:RequestedAttribute Name="cn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" isRequired="true"/>
     <md:RequestedAttribute Name="eduPersonPrincipalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" isRequired="true"/>
     <md:RequestedAttribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" isRequired="true"/>
     <md:RequestedAttribute Name="eduPersonPrimaryAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" isRequired="true"/>
     <md:RequestedAttribute Name="organizationName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" isRequired="true"/>
     <md:RequestedAttribute Name="eduPersonAssurance" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" isRequired="true"/>
     <md:RequestedAttribute Name="schacPersonalUniqueID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
     <md:RequestedAttribute Name="schacCountryOfCitizenship" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
     <md:RequestedAttribute Name="eduPersonScopedAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
     <md:RequestedAttribute Name="preferredLanguage" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
     <md:RequestedAttribute Name="eduPersonEntitlement" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
     <md:RequestedAttribute Name="norEduPersonLIN" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
   </md:AttributeConsumingService>
 </md:SPSSODescriptor>
 <md:Organization>
   <md:OrganizationName xml:lang="en">WAYF</md:OrganizationName>
   <md:OrganizationName xml:lang="da">WAYF</md:OrganizationName>
   <md:OrganizationDisplayName xml:lang="en">WAYF - Where are you from</md:OrganizationDisplayName>
   <md:OrganizationDisplayName xml:lang="da">WAYF - Where are you from</md:OrganizationDisplayName>
   <md:OrganizationURL xml:lang="da">http://wayf.dk/index.php/da</md:OrganizationURL>
   <md:OrganizationURL xml:lang="en">http://wayf.dk/index.php/en</md:OrganizationURL>
 </md:Organization>
 <md:ContactPerson contactType="technical">
   <md:GivenName>WAYF</md:GivenName>
   <md:SurName>Operations</md:SurName>
   <md:EmailAddress>drift@wayf.dk</md:EmailAddress>
 </md:ContactPerson>
</md:EntityDescriptor>`)
)

func TestMain(m *testing.M) {
	spmetadata = NewMD(mdq+"EDUGAIN", "https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth")
	idpmetadata = NewMD(mdq+"EDUGAIN", "https://aai-logon.switch.ch/idp/shibboleth")
	//wayfmetadata = NewMD(mdq, "wayf-hub-public", "https://wayf.wayf.dk")
	hubmetadata = NewXp(wayfmdxml)
	testidpmetadata = NewMD(mdq+"HUB-OPS", "https://this.is.not.a.valid.idp")
	testidpviabirkmetadata = NewMD(mdq+"BIRK-OPS", "https://birk.wayf.dk/birk.php/this.is.not.a.valid.idp")
	os.Exit(m.Run())
}

func ExampleMetadata() {
	fmt.Println(idpmetadata.Query1(nil, "/md:EntityDescriptor/@entityID"))
	fmt.Println(idpmetadata.Query1(nil, "/md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat"))
	// Output:
	// https://aai-logon.switch.ch/idp/shibboleth
	// urn:mace:shibboleth:1.0:nameIdentifier
}

func ExampleSignAndValidate() {
	xp := NewXp(response)
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	xp.Sign(assertion, privatekey, "-", "", "sha256")

	xp = NewXp([]byte(xp.Pp()))
	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm"))
	fmt.Println(xp.Query1(nil, "/samlp:Response/saml:Assertion/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm"))

	block, _ := pem.Decode([]byte(privatekey))
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pub := &priv.PublicKey

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion, pub))
	// Output:

	xp.Sign(assertion, privatekey, "-", "", "sha1")

	//log.Print(xp.C14n(nil))

	xp = NewXp([]byte(xp.Pp()))

	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm"))
	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm"))
	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue"))
	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignatureValue"))
	// Output:
	// http://www.w3.org/2001/04/xmlenc#sha256
	// http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
	// verify: true
	// http://www.w3.org/2000/09/xmldsig#sha1
	// http://www.w3.org/2000/09/xmldsig#rsa-sha1
	// qsO7ZLDcPcICBcxUAM7BGfi49dg=
	// MspQt4VY+49td+ubVcY9HOAQRULqFPTAcPIuQoZgeUU7hPbJniTAzwoh+BDnAdaqxlMt5biaIWAM/s50sLDm0c7fyoe7iVkKokVjGe7gO28/RTo2KYMOyDFTT6HDJVfLWC68E8Q2XV2+Sa4gtWfbq6HlmMZXN3g+Z1rOqTCht3Y=
}

func ExampleQueryDashP_1() {
	xp := NewXp(response)
	xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[1]`, "anton", nil)
	xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`, "banton", nil)

	fmt.Println(xp.Query1(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`))
	fmt.Println(xp.Query1(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[2]`))
	fmt.Println(xp.Query1(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[1]`))
	// Output:
	// banton
	// https://wayf.wayf.dk
	// anton
}

func ExampleQueryDashP_2() {
	xp := NewXp([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`))
	xp.QueryDashP(nil, `/samlp:Response/@ID`, "zf0de122f115e3bb7e0c2eebcc4537ac44189c6dc", nil)
	xp.QueryDashP(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`, "banton", nil)

	fmt.Print(xp.Pp())
	fmt.Println(xp.Query1(nil, `saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[3]`))
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

func ExampleAuthnRequest() {
	spmd := spmetadata
	idpmd := idpmetadata

	request := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, spmd, idpmd)
	fmt.Print(request.Pp())
	// Output:
	// <?xml version="1.0"?>
	// <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="ID" IssueInstant="0001-01-01T00:00:00Z" Destination="https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO" AssertionConsumerServiceURL="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
	// <saml:Issuer>https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth</saml:Issuer>
	// <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/>
	// </samlp:AuthnRequest>
}

func ExampleResponse() {
	idpmd := idpmetadata
	spmd := spmetadata

	sourceResponse := NewXp(response)
	request := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, spmd, idpmd)
	response := NewResponse(IdAndTiming{time.Time{}, 4 * time.Minute, 4 * time.Hour, "ID", "AssertionID"}, idpmd, spmd, request, sourceResponse)

	fmt.Print(response.Pp())
	// Output:
	// <?xml version="1.0"?>
	// <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="ID" Version="2.0" IssueInstant="0001-01-01T00:00:00Z" InResponseTo="ID" Destination="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST">
	//     <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://aai-logon.switch.ch/idp/shibboleth</saml:Issuer>
	//     <samlp:Status>
	//         <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
	//     </samlp:Status>
	//     <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="AssertionID" Version="2.0" IssueInstant="0001-01-01T00:00:00Z">
	//         <saml:Issuer>https://aai-logon.switch.ch/idp/shibboleth</saml:Issuer>
	//         <saml:Subject>
	//             <saml:NameID SPNameQualifier="https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth" Format="NameID@Format">Subject</saml:NameID>
	//             <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
	//                 <saml:SubjectConfirmationData NotOnOrAfter="0001-01-01T00:04:00Z" Recipient="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST" InResponseTo="ID"/>
	//             </saml:SubjectConfirmation>
	//         </saml:Subject>
	//         <saml:Conditions NotBefore="0001-01-01T00:00:00Z" NotOnOrAfter="0001-01-01T00:04:00Z">
	//             <saml:AudienceRestriction>
	//                 <saml:Audience>https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth</saml:Audience>
	//             </saml:AudienceRestriction>
	//         </saml:Conditions>
	//         <saml:AuthnStatement AuthnInstant="0001-01-01T00:00:00Z" SessionNotOnOrAfter="0001-01-01T04:00:00Z" SessionIndex="missing">
	//             <saml:AuthnContext>
	//                 <saml:AuthnContextClassRef>missing</saml:AuthnContextClassRef>
	//             </saml:AuthnContext>
	//         </saml:AuthnStatement>
	//         <saml:AttributeStatement>
	//         <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">gikcaswid@orphanage.wayf.dk</saml:AttributeValue><saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">only@thisone.example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
	//     </saml:Assertion>
	// </samlp:Response>
}

func ExampleEncryptAndDecrypt() {
	idpmd := idpmetadata
	spmd := spmetadata

	sourceResponse := NewXp(response)
	request := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, spmd, idpmd)
	response := NewResponse(IdAndTiming{time.Time{}, 4 * time.Minute, 4 * time.Hour, "ID", "AssertionID"}, idpmd, spmd, request, sourceResponse)
	assertion := response.Query(nil, "saml:Assertion[1]")[0]

    pk := Pem2PrivateKey(privatekey, "")
	response.Encrypt(assertion, &pk.PublicKey)
    assertion = response.Query(nil, "//saml:EncryptedAssertion")[0]
    response.Decrypt(assertion, pk)
	fmt.Print(response.Pp())

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
    //             <saml:NameID Format="NameID@Format" SPNameQualifier="https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth">Subject</saml:NameID>
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
    //                 <saml:AuthnContextClassRef>missing</saml:AuthnContextClassRef>
    //             </saml:AuthnContext>
    //         </saml:AuthnStatement>
    //         <saml:AttributeStatement>
    //         <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">gikcaswid@orphanage.wayf.dk</saml:AttributeValue><saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">only@thisone.example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
    //     </saml:Assertion>
    //</samlp:Response>
}

func ExampleValidateSchema() {
	xp := NewXp(response)
	fmt.Println(xp.SchemaValidate("schemas/saml-schema-protocol-2.0.xsd"))
	// make the document schema-invalid
	xp.UnlinkNode(xp.Query(nil, "//saml:Assertion/saml:Issuer")[0])
	fmt.Println(xp.SchemaValidate("schemas/saml-schema-protocol-2.0.xsd"))
	// Output:
	// [] <nil>
	// [] Document validation error

}