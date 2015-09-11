package gosaml

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
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

	spmetadata = []byte(`<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://attribute-viewer.aai.switch.ch/shibboleth">
  <md:Extensions>
    <mdrpi:RegistrationInfo registrationAuthority="http://rr.aai.switch.ch/" registrationInstant="2015-08-21T10:35:34Z">
      <mdrpi:RegistrationPolicy xml:lang="en">https://www.switch.ch/aai/federation/switchaai/metadata-registration-practice-statement-20110711.txt</mdrpi:RegistrationPolicy>
    </mdrpi:RegistrationInfo>
    <mdattr:EntityAttributes>
      <saml:Attribute Name="http://macedir.org/entity-category" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
				</saml:Attribute>
      <saml:Attribute FriendlyName="swissEduPersonHomeOrganization" Name="urn:oid:2.16.756.1.2.5.1.1.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>switch.ch</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="swissEduPersonHomeOrganizationType" Name="urn:oid:2.16.756.1.2.5.1.1.5" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>others</saml:AttributeValue>
      </saml:Attribute>
    </mdattr:EntityAttributes>
  </md:Extensions>
  <md:SPSSODescriptor errorURL="http://www.switch.ch/aai/support/help" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:1.1:protocol">
    <md:Extensions>
      <mdui:UIInfo>
        <mdui:DisplayName xml:lang="de">AAI Attributes Viewer</mdui:DisplayName>
        <mdui:DisplayName xml:lang="en">AAI Attributes Viewer</mdui:DisplayName>
        <mdui:DisplayName xml:lang="fr">AAI Attributes Viewer</mdui:DisplayName>
        <mdui:DisplayName xml:lang="it">AAI Attributes Viewer</mdui:DisplayName>
        <mdui:Description xml:lang="de">Zeigt zu Test und Informationszwecken alle Attribute eines Benutzers.</mdui:Description>
        <mdui:Description xml:lang="en">Displays all available attributes of a user for debugging and informational purposes.</mdui:Description>
        <mdui:Description xml:lang="fr">Pr&#xE9;sente tous les attributs d'un utilisateur pour tester et pour obtenir des renseignements.</mdui:Description>
        <mdui:Description xml:lang="it">Ha tutti gli attributi di un utente per testare e per ottenere informazioni.</mdui:Description>
        <mdui:Logo height="16" width="16">data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAACF0RVh0U29mdHdhcmUAR3JhcGhpY0NvbnZlcnRlciAoSW50ZWwpd4f6GQAAAZJJREFUeJyUk08og2Ecx5+SHNSW/DtQlHKg1MhByjIpLRNx0NZKk0kbbSStHXZdHOVP4bCi5swuXNxQLjiN5UBNc1AzbeR936/39zz7c7B/Dt+e31PP9/P8ft/3eRkARpKPnVDuQsjsy1W2kA8skKwM8tEsEH8tG5QDqEZpqZILdgblbB34+igJygG2RrlRWqsXcqi1pwXKdaAoJLehtk99kJa1wkxrupb9OihPl3lBf6kqiPLg3ThER3BVCRDl8/aI4oC0lFhYGOyiG9nTKIAECjqzQZdMmVqnEbBaAfi0gLeaQ6grGrkkIPqexJjFi+E+PSZGTDANGjHQq8dQdz8CPndhY+Q5hjnPPlirGazDBta5CNakrrVmmGybiETj+UegG3cOz8Gap4V6FgSgYRLthhXcP7zkDzH1/cONmjYrP8xNXXZea9Q6dHELOlPwM1pX98BqxoWRpLZep5uHf/cEic9UwceULaZc22LetGj+eCJZ/lOmYBgzwDizAQrw3z+T2x/E1U24bGNGvwAAAP//AwCkGcs+iePLFQAAAABJRU5ErkJggg==</mdui:Logo>
        <mdui:Logo height="60" width="80">data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFAAAAA8CAIAAAB+RarbAAAC0GlDQ1BJQ0NQcm9maWxlAAB4nI2Uz0sUYRjHv7ONGChBYGZ7iKFDSKhMFmVE5a6/2LRtWX+UEsTs7Lu7k7Oz08zsmiIRXjpm0T0qDx76Azx46JSXwsAsAuluUUSCl5LteWfG3RHtxwsz83mfH9/ned/hfYEaWTFNPSQBecOxkn1R6fromFT7ESEcQR3CqFNU24wkEgOgwWOxa2y+h8C/K617+/866tK2mgeE/UDoR5rZKrDvF9kLWWoEELlew4RjOsT3OFue/THnlMfzrn0o2UW8SHxANS0e/5q4Q80paaBGJG7JBmJSAc7rRdXv5yA99cwYHqTvcerpLrN7fBZm0kp3P3Eb8ec06+7hmsTzGa03RtxMz1rG6h32WDihObEhj0Mjhh4f8LnJSMWv+pqi6UST2/p2abBn235LuZwgDhMnxwv9PKaRcjunckPXPBb0qVxX3Od3VjHJ6x6jmDlTd/8X9RZ6hVHoYNBg0NuAhCT6EEUrTFgoIEMejSI0sjI3xiK2Mb5npI5EgCXyr1POuptzG0XK5lkjiMYx01JRkOQP8ld5VX4qz8lfZsPF5qpnxrqpqcsPvpMur7yt63v9njx9lepGyKsjS9Z8ZU12oNNAdxljNlxV4jXY/fhmYJUsUKkVKVdp3K1Ucn02vSOBan/aPYpdml5sqtZaFRdurNQvTe/Yq8KuVbHKqnbOq3HBfCYeFU+KMbFDPAdJvCR2ihfFbpqdFwcqGcOkomHCVbKhUJaBSfKaO/6ZFwvvrLmjoY8ZzNJUiZ//hFXIaDoLHNF/uP9z8HvFo7Ei8MIGDp+u2jaS7h0iNC5Xbc4V4MI3ug/eVm3NdB4OPQEWzqhFq+RLC8IbimZ3HD7pKpiTlpbNOVK7LJ+VInQlMSlmqG0tkqLrkuuyJYvZzCqxdBvszKl2T6WedqXmU7m8Qeev9hGw9bBc/vmsXN56Tj2sAS/138C8/UXN/ALEAAAJI2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iWE1QIENvcmUgNC40LjAiPgogICA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPgogICAgICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIi8+CiAgIDwvcmRmOlJERj4KPC94OnhtcG1ldGE+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAKPD94cGFja2V0IGVuZD0idyI/Pqfd9JIAAAAhdEVYdFNvZnR3YXJlAEdyYXBoaWNDb252ZXJ0ZXIgKEludGVsKXeH+hkAAAaRSURBVHic7JZpUFNXFMf92A+dsR8ECrQ6Fq2tlVVELVQEZLNaoSwV1FEsy6CMuyJhFRAQQiAJEBCIiCigaAUFFARZlE0EAReoiiCgLGUnJIQktyc8GpKXSPnUzjzefzKZ9+4979z7u/fcc+4StMi05P+ewH8tEpjoIoGJLhKY6CKBiS4SmOgigYkuEpjoIoGJLhKY6CKBia5FDMyZnLpT/Nzl+FXbgykObmw719TopLKe3hHoEolE2bkN9NTy8XGe9Me37zUHUQu7P4pt0EgHqo5EnRUy7qd56CkLteXBo0AovJRZc7f4BdbTNzAenfgwKqEkGn6sUkZKGS3pYRSrlMoqjaAX5z94Ie3mz/Z+WkrZbs/LtgdT7VzZ9m7snPxnXN60xIA/LUjOqCoqb5UnnOTykzKrwLMM8NgEz9krfc2WsF0uKY4elxzg535J35q63opa19gJBtl5jUqavuysGmlfj2rffrb8hBclR/xSehrRl6G+JpnRXuUg2lL0Oh8ep/gCw12xHt7XsZ62t31We1iWzizrPYnmTqyVm4MNdtC270uycmaZOcZFJpTMrphAeJ5e9K1RqJFNrL27GNXBnf2LS7LGjyFup7N4U9MSKj3LqFMhufLAg8McGHfpGm8ZYFjdlZuCi8tbBQKhxLS98y/tbRfcz2RjA8MCw+uHvlFpdyfP3f58tU99eSliqaOSkzJD8UZR2kZ0yw4JhdgmGNsxvHxzsE6hSARbxOXxebzpzu4hLbMLjNRyWBRogR8YY2aFZa/U1wcw2RVDIxyJY5hkes4TNV3/ipo3EmCDn6O9z+cpBDa2Y6rrBcgAw/Js+ZU5OsbFWZ8Nu+PpcwN7rn/2/iv9QL/IfGkD4FfXjzhmswOlrUGjnTIf1zMR7QvUXYW94YBxTtaZRsRcfCjfFRxzD7rGJ3i49o6uQY3NwUlXZp1zuPwN8wEz8MBGtnSIXtzugSBmpI/KmdC8FRuDnrd+lLahJtd4WpqipxHSjSLOAErUQAVukpZ5gCFTiIGTFAAHUAuM7ZmSDZcItjS/5Pnr9n7J64bt0ZSIO/IexiemTOzjVHX9ZYAhXcHuuRy/llfUUv30XW1jR/PLnvc9w9NSEQ7q6hleaxJ+8ESmSCiSNA6M8K/QqIjbK20pqAwRMVTRYNscMF8MfJiieIe1tl1QuMOB1AITxzh5YJy4XP6mnTG/n8x80tQJk5f8IAGVVLZt3hmjrOkrAwzKvd8CWcHQhg5faptH6phH/mASbr47obahQ9p1fNojFR2/4oq5fMgXoJrCXNHU+JwRcDJVURlF+sP5Qrp3RNMsgqYI2D+qwHQBwLDDP9nSVxmG6lqIZ65jESl+mHkGllWGIV/rB+KB0Uz5gS+HRyY/9o3CIamsfQvwkEVhcyQ2E5wpM8d4C6cEKGNYy+PG3qD99ujV5TlHxUdErFVorGuhwDM7HK0opAOphaaO8QsB3riDdjTg1sDgRO/AWG//GPbfNzDW+qYP1gK/w4+ftDe2dPOnhThHUCchMw8OT0g33n3wUlnbDytRsEZ7j988tssCXd2AuEPi7v5mxFAV1DFwruY/w5/a4aDoQghI4MG1Q6KGip2V24C9cmbOsE+4gjM8PDq51V4uSytr+ULuhj6cNTO1HIBh2XCDOR1K17WIgliorn+nph+SwWCgBGVUFwMrgHKdEVsP8YYWDoyFtMKkFRp7/3vjMMi0uHZILlBZvPxmvc2WpTAFwFhZUsMlLbhvrDYKrW2QqSucSf5vnmmmDnHSIY2pvun9CoMgmM2ew+lwbRBn8gJXxNJAzWmIoYKa2PID/2tI0xQB3y9rVdMLyLhZh2uvqn+33CAoPq1SFnjBZamza8h6byKcctdTWYd8bnh4Z3ucybZwZsEqZN1ukPeCZkr0lzr+yw3OQYYXvw+9RqxvEF0FXdsmvnLICS4VRjb0Q/9UdWlBSK/dGhadWCrfBWsNdxuYBlwEYVZwC4KJ7TuSsXZrOOSRrg/DmBmEtJ5V1OlP3LRg3GXrKDLA4gmPcJipFbqWkUpaFGUtP0jFTofTG5q75F1ggqJ14NhVmM1cRqlnirKtUXuRQnswOxH0R2xyuXwXHJn9RzOu5yleWaFQlHuv5TvjMCVNioq2n9I6CgQ5hMOQVJzDfcHz7PWLGdXyn4+N847637Q5kIwHXiQigYkuEpjoIoGJLhKY6CKBiS4SmOgigYkuEpjoIoGJLhKY6CKBia5FB/w3AAAA//8DABFh2N/+esWhAAAAAElFTkSuQmCC</mdui:Logo>
        <mdui:InformationURL xml:lang="en">https://attribute-viewer.aai.switch.ch/</mdui:InformationURL>
        <mdui:InformationURL xml:lang="fr">https://attribute-viewer.aai.switch.ch/?lang=fr</mdui:InformationURL>
        <mdui:InformationURL xml:lang="it">https://attribute-viewer.aai.switch.ch/?lang=it</mdui:InformationURL>
        <mdui:InformationURL xml:lang="de">https://attribute-viewer.aai.switch.ch/?lang=de</mdui:InformationURL>
        <mdui:PrivacyStatementURL xml:lang="it">https://attribute-viewer.aai.switch.ch/privacy_statement.php?lang=it</mdui:PrivacyStatementURL>
        <mdui:PrivacyStatementURL xml:lang="fr">https://attribute-viewer.aai.switch.ch/privacy_statement.php?lang=fr</mdui:PrivacyStatementURL>
        <mdui:PrivacyStatementURL xml:lang="en">https://attribute-viewer.aai.switch.ch/privacy_statement.php</mdui:PrivacyStatementURL>
        <mdui:PrivacyStatementURL xml:lang="de">https://attribute-viewer.aai.switch.ch/privacy_statement.php?lang=de</mdui:PrivacyStatementURL>
      </mdui:UIInfo>
    </md:Extensions>
    <md:KeyDescriptor>
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>
MIIDVDCCAjygAwIBAgIJAKGvh4Rjh+jgMA0GCSqGSIb3DQEBBQUAMCkxJzAlBgNV
BAMTHmF0dHJpYnV0ZS12aWV3ZXIuYWFpLnN3aXRjaC5jaDAeFw0xNDA1MTQxNDQ1
MzhaFw0xNzA1MTMxNDQ1MzhaMCkxJzAlBgNVBAMTHmF0dHJpYnV0ZS12aWV3ZXIu
YWFpLnN3aXRjaC5jaDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK7w
bFh51f8XC/y1CJiXg32dC1TojB6F7RHxRuxpPuNh/zp9/7kWStnddGaaOtw9e2fU
Q/BOe+ztIT5njJ34lKJqfY4mFj3SbuKjDEBk24o/M15IWTLR+0qx5l0uc/U/CSqu
2wqS6H6u0BMfuRVGFM8NWXJ55SeKBLXbKJVyboweP2pO5AyRBXZHsM8ZEue9hKbn
qTrXCMS//OfzLarQ7baYtHr+nRbcihJWa2xa+5swiOuf5vEG6sKJT7NbtVbI5b1v
tzPiCH36ACSHaKkDMsPGCeu5ectunqxQWbufLijzvurKf7EHilIhNvfT+63CIfCp
t5ViglqeiMJ1tDqham8CAwEAAaN/MH0wXAYDVR0RBFUwU4IeYXR0cmlidXRlLXZp
ZXdlci5hYWkuc3dpdGNoLmNohjFodHRwczovL2F0dHJpYnV0ZS12aWV3ZXIuYWFp
LnN3aXRjaC5jaC9zaGliYm9sZXRoMB0GA1UdDgQWBBSDmwCkWamUzbmbv6h8wpic
9PoE7jANBgkqhkiG9w0BAQUFAAOCAQEAms0jw2xzz2dsT+y1sG6Omc9idxl2ffzf
Km6t4tEACaDFWxGhP1xGZ9omE+UyuiftW8Tj/8+c4bVUTd/UhhiIdkmhld5M7awF
8xtzM979p+uL5abezo5D/8O4IYFWpHZdQ+VSl/Wr9tc9N6dmB5c0xzUm4/YzCaNz
anih2XoBQzYD8ZpxYWopH/Uwt6KiUf9TV92rR2EkmZloH3HyfxdmaOIxQU1boi8e
GCyqkxNBftgYk65n7Yn5UVBeUr7IBTmzXLFmluhpNYmcslYf/ClArFLNGhHpI5F0
UDgBXcQzpXHOg7ks4xbcEPCe0gaQhOKyWjMDALDCmiA7f7/Rnam3CA==
						</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:mace:shibboleth:1.0:nameIdentifier</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://attribute-viewer.aai.switch.ch/Shibboleth.sso/SAML2/POST" index="1"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://attribute-viewer.aai.switch.ch/Shibboleth.sso/SAML2/Artifact" index="2"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:PAOS" Location="https://attribute-viewer.aai.switch.ch/Shibboleth.sso/SAML2/ECP" index="3"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:1.0:profiles:browser-post" Location="https://attribute-viewer.aai.switch.ch/Shibboleth.sso/SAML/POST" index="4"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:1.0:profiles:artifact-01" Location="https://attribute-viewer.aai.switch.ch/Shibboleth.sso/SAML/Artifact" index="5"/>
    <md:AttributeConsumingService index="1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <md:ServiceName xml:lang="de">AAI Attributes Viewer</md:ServiceName>
      <md:ServiceName xml:lang="en">AAI Attributes Viewer</md:ServiceName>
      <md:ServiceName xml:lang="fr">AAI Attributes Viewer</md:ServiceName>
      <md:ServiceName xml:lang="it">AAI Attributes Viewer</md:ServiceName>
      <md:ServiceDescription xml:lang="de">Zeigt zu Test und Informationszwecken alle Attribute eines Benutzers.</md:ServiceDescription>
      <md:ServiceDescription xml:lang="en">Displays all available attributes of a user for debugging and informational purposes.</md:ServiceDescription>
      <md:ServiceDescription xml:lang="fr">Pr&#xE9;sente tous les attributs d'un utilisateur pour tester et pour obtenir des renseignements.</md:ServiceDescription>
      <md:ServiceDescription xml:lang="it">Ha tutti gli attributi di un utente per testare e per ottenere informazioni.</md:ServiceDescription>
      <md:RequestedAttribute FriendlyName="preferredLanguage" Name="urn:oid:2.16.840.1.113730.3.1.39" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="email" Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="homePostalAddress" Name="urn:oid:0.9.2342.19200300.100.1.39" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="postalAddress" Name="urn:oid:2.5.4.16" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="homePhone" Name="urn:oid:0.9.2342.19200300.100.1.20" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="telephoneNumber" Name="urn:oid:2.5.4.20" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="mobile" Name="urn:oid:0.9.2342.19200300.100.1.41" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonOrgDN" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonOrgUnitDN" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonEntitlement" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="surname" Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="givenName" Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="uid" Name="urn:oid:0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="employeeNumber" Name="urn:oid:2.16.840.1.113730.3.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="ou" Name="urn:oid:2.5.4.11" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrincipalName" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true">
      <saml:AttributeValue xsi:type="xs:string">only@thisone.example.com</saml:AttributeValue>
      </md:RequestedAttribute>
      <md:RequestedAttribute FriendlyName="eduPersonAssurance" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.11" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonTargetedID" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrimaryOrgUnitDN" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.8" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="primaryGroupID" Name="urn:oid:1.3.6.1.4.1.7165.2.1.15" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="isMemberOf" Name="urn:oid:1.3.6.1.4.1.5923.1.5.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonNickname" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.2" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonScopedAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.9" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrimaryAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.5" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="displayName" Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="commonName" Name="urn:oid:2.5.4.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacHomeOrganization" Name="urn:oid:1.3.6.1.4.1.25178.1.2.9" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacHomeOrganizationType" Name="urn:oid:1.3.6.1.4.1.25178.1.2.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonUniqueId" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.13" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">switch.ch</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="de">SWITCH</md:OrganizationDisplayName>
    <md:OrganizationDisplayName xml:lang="en">SWITCH</md:OrganizationDisplayName>
    <md:OrganizationDisplayName xml:lang="fr">SWITCH</md:OrganizationDisplayName>
    <md:OrganizationDisplayName xml:lang="it">SWITCH</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="de">http://www.switch.ch/</md:OrganizationURL>
    <md:OrganizationURL xml:lang="en">http://www.switch.ch/</md:OrganizationURL>
    <md:OrganizationURL xml:lang="fr">http://www.switch.ch/</md:OrganizationURL>
    <md:OrganizationURL xml:lang="it">http://www.switch.ch/</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="support">
    <md:GivenName>SWITCHaai</md:GivenName>
    <md:SurName>Team</md:SurName>
    <md:EmailAddress>mailto:aai@switch.ch</md:EmailAddress>
    <md:TelephoneNumber>+41 44 268 15 05</md:TelephoneNumber>
  </md:ContactPerson>
  <md:ContactPerson contactType="technical">
    <md:GivenName>SWITCHaai</md:GivenName>
    <md:SurName>Team</md:SurName>
    <md:EmailAddress>mailto:aai@switch.ch</md:EmailAddress>
    <md:TelephoneNumber>+41 44 268 15 05</md:TelephoneNumber>
  </md:ContactPerson>
</md:EntityDescriptor>`)

	idpmetadata = []byte(`<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://aai-logon.switch.ch/idp/shibboleth">
  <md:Extensions>
    <mdrpi:RegistrationInfo registrationAuthority="http://rr.aai.switch.ch/" registrationInstant="2015-05-05T15:15:15Z">
      <mdrpi:RegistrationPolicy xml:lang="en">https://www.switch.ch/aai/federation/switchaai/metadata-registration-practice-statement-20110711.txt</mdrpi:RegistrationPolicy>
    </mdrpi:RegistrationInfo>
    <mdattr:EntityAttributes>
      <saml:Attribute Name="http://macedir.org/entity-category-support" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>http://www.geant.net/uri/dataprotection-code-of-conduct/v1</saml:AttributeValue>
        <saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue>
      </saml:Attribute>
    </mdattr:EntityAttributes>
  </md:Extensions>
  <md:IDPSSODescriptor errorURL="http://www.switch.ch/aai/contact/" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:1.1:protocol urn:mace:shibboleth:1.0">
    <md:Extensions>
      <shibmd:Scope regexp="false">switch.ch</shibmd:Scope>
      <mdui:UIInfo>
        <mdui:DisplayName xml:lang="de">SWITCH</mdui:DisplayName>
        <mdui:DisplayName xml:lang="en">SWITCH</mdui:DisplayName>
        <mdui:DisplayName xml:lang="fr">SWITCH</mdui:DisplayName>
        <mdui:DisplayName xml:lang="it">SWITCH</mdui:DisplayName>
        <mdui:Description xml:lang="de">SWITCH erbringt innovative, einzigartige Internet-Dienstleistungen f&#xFC;r die Schweizer Hochschulen und Internetbenutzer.</mdui:Description>
        <mdui:Description xml:lang="en">SWITCH provides innovative, unique internet services for the Swiss universities and internet users.</mdui:Description>
        <mdui:Description xml:lang="fr">SWITCH fournit des prestations innovantes et uniques pour les hautes &#xE9;coles suisses et les utilisateurs d'Internet.</mdui:Description>
        <mdui:Description xml:lang="it">SWITCH eroga servizi Internet innovativi e unici per le scuole universitarie svizzere e per gli utenti di Internet.</mdui:Description>
        <mdui:Keywords xml:lang="en">Zurich</mdui:Keywords>
        <mdui:Keywords xml:lang="de">Z&#xFC;rich</mdui:Keywords>
        <mdui:Keywords xml:lang="fr">Zurich</mdui:Keywords>
        <mdui:Keywords xml:lang="it">Zurigo</mdui:Keywords>
        <mdui:Logo height="16" width="16">data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAACF0RVh0U29mdHdhcmUAR3JhcGhpY0NvbnZlcnRlciAoSW50ZWwpd4f6GQAAAgFJREFUeJxi+P//P8PHXd1nfj484w1ik4rBxNsVeR+f1Kr+/7ira/Pfr++USTbg3aqCj4/LJP8/Lpf6/6LP8ce38+tb/v/7y0W8AWtKnj8qFvn/pFrp/+NKOTB+syD+0a/HF0KJMuD324eS79eVzwd64+/jCpn/T2qABgHpp/Ua/z9sadz759NLbbwGwPDP+ydNXs+NPPK4UhbsiifVimBvPe+2+f3l1LL+f39+8eM1AIz//mH8em5N5Is+p0cgzU+BhjytAhpWIf3/zeywF7/uH08EqmPEbQAU//v2nuvnockNj1uMv96r1vh/r0bz/70K5f/367T/P1pVc/zr2+cmeA348+8/49KtZ8Nt/ItvGzklvzd2SX2vZ5/0Xtc24X1xWevVp48e+uI04PCZW0YeKb2HWLWT/7PopIExg2rif1WP6p/z1x/v/P7rLy9WL9x59EoivW7hXF6jzL/Mmkn/ufTT/jMBaRHz3P9VfWt2vH73WR1rIL7/+JW9a862Mhn7oo+MGolgjSDb2XVT/gflTLl3/trDALzRmN+69DKDcux/Dt3U/xx6qf9BhhgF1H9bu+tM3b9//zkJJqSEyjkfGdUT/jMBNUpYF/xvnbF57ftP3+SJTsoJFXM+MgM1x5TOunbj3nNXkjNTet2Cx/PWHCoGsllJ0QzCAAAAAP//AwC4nrtuPmwfNwAAAABJRU5ErkJggg==</mdui:Logo>
        <mdui:Logo height="60" width="80">data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFAAAAA8CAYAAADxJz2MAAAC0GlDQ1BJQ0NQcm9maWxlAAB4nI2Uz0sUYRjHv7ONGChBYGZ7iKFDSKhMFmVE5a6/2LRtWX+UEsTs7Lu7k7Oz08zsmiIRXjpm0T0qDx76Azx46JSXwsAsAuluUUSCl5LteWfG3RHtxwsz83mfH9/ned/hfYEaWTFNPSQBecOxkn1R6fromFT7ESEcQR3CqFNU24wkEgOgwWOxa2y+h8C/K617+/866tK2mgeE/UDoR5rZKrDvF9kLWWoEELlew4RjOsT3OFue/THnlMfzrn0o2UW8SHxANS0e/5q4Q80paaBGJG7JBmJSAc7rRdXv5yA99cwYHqTvcerpLrN7fBZm0kp3P3Eb8ec06+7hmsTzGa03RtxMz1rG6h32WDihObEhj0Mjhh4f8LnJSMWv+pqi6UST2/p2abBn235LuZwgDhMnxwv9PKaRcjunckPXPBb0qVxX3Od3VjHJ6x6jmDlTd/8X9RZ6hVHoYNBg0NuAhCT6EEUrTFgoIEMejSI0sjI3xiK2Mb5npI5EgCXyr1POuptzG0XK5lkjiMYx01JRkOQP8ld5VX4qz8lfZsPF5qpnxrqpqcsPvpMur7yt63v9njx9lepGyKsjS9Z8ZU12oNNAdxljNlxV4jXY/fhmYJUsUKkVKVdp3K1Ucn02vSOBan/aPYpdml5sqtZaFRdurNQvTe/Yq8KuVbHKqnbOq3HBfCYeFU+KMbFDPAdJvCR2ihfFbpqdFwcqGcOkomHCVbKhUJaBSfKaO/6ZFwvvrLmjoY8ZzNJUiZ//hFXIaDoLHNF/uP9z8HvFo7Ei8MIGDp+u2jaS7h0iNC5Xbc4V4MI3ug/eVm3NdB4OPQEWzqhFq+RLC8IbimZ3HD7pKpiTlpbNOVK7LJ+VInQlMSlmqG0tkqLrkuuyJYvZzCqxdBvszKl2T6WedqXmU7m8Qeev9hGw9bBc/vmsXN56Tj2sAS/138C8/UXN/ALEAAAJI2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iWE1QIENvcmUgNC40LjAiPgogICA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPgogICAgICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIi8+CiAgIDwvcmRmOlJERj4KPC94OnhtcG1ldGE+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAKPD94cGFja2V0IGVuZD0idyI/Pqfd9JIAAAAhdEVYdFNvZnR3YXJlAEdyYXBoaWNDb252ZXJ0ZXIgKEludGVsKXeH+hkAAAiDSURBVHic7Fh7bFPXGT9x4vgR29fva1/HsRM78StODE0CCTQoJiEPh7wgNoFAgkt4jpF2/aNTira0/2za2qGC1IcoUwlTaaF0XRJRaLRB2QCxTtAHrxUWNfQBnWAPprFNNN5377UTO7GzKop2dKQc6ed7z3dev/O73znnO0aRSATNY/bAToB0YCdAOrATIB3YCZAO7ARIB3YCpAM7AdKBnQDpwE6AdGAnQDqwEyAd2AmQDuwESAd2AqQDOwHSgZ0A6cBOgHRgJ0A6sBMgHdgJkA7sBEgHdgKkg/9hk1jlkJvKX1LmN/9B62y/oXe03YTnNWV+06CMWbQBxSWpqWKv0tZwRiBjsnlLWqwoU5pTdUJhrdmPxBRnyFYj40AbdbqvSvyDWKUMAf/sKBbuOhpSXgiXiCr4AimSWfw/zzJXvslmTSZaMDh0HF4azirtjROgbIHJdwBC/rNjtz5ndj/9dDxNeZZh4ePKvLphtXP1ZXY+eseqm1oAZVkO3E01PPX0iQbpipx0hS0wLNF5f4pSJ4HcunwPlVf7m0kBhTKruqDlnrE4/GfaFTqhdwWPAF7Xu0Lv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</mdui:Logo>
        <mdui:InformationURL xml:lang="en">http://www.switch.ch/about/</mdui:InformationURL>
        <mdui:InformationURL xml:lang="de">http://www.switch.ch/de/about/</mdui:InformationURL>
        <mdui:InformationURL xml:lang="fr">http://www.switch.ch/fr/about/</mdui:InformationURL>
        <mdui:InformationURL xml:lang="it">http://www.switch.ch/it/about/</mdui:InformationURL>
      </mdui:UIInfo>
      <mdui:DiscoHints>
        <mdui:IPHint>130.59.0.0/16</mdui:IPHint>
        <mdui:IPHint>2001:620::/48</mdui:IPHint>
        <mdui:DomainHint>switch.ch</mdui:DomainHint>
        <mdui:GeolocationHint>geo:47.37333,8.53111</mdui:GeolocationHint>
      </mdui:DiscoHints>
    </md:Extensions>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>
MIIDLDCCAhSgAwIBAgIJAIHilzMu/j8KMA0GCSqGSIb3DQEBBQUAMB4xHDAaBgNV
BAMTE2FhaS1sb2dvbi5zd2l0Y2guY2gwHhcNMTMxMjAyMTUxNzI5WhcNMTYxMjAx
MTUxNzI5WjAeMRwwGgYDVQQDExNhYWktbG9nb24uc3dpdGNoLmNoMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA72Gf8Be0k33Ucdk6+m/wpe70eZdL8n9Q
Dk4AuJ7uLFqo9vfJFRpEDbfGAt2s9esAfxX0harLVhEP7bX4HQxDt7uM9PeDXZ3M
GGiKL4hCNR4RKY1pfx7PoLDHthiO5vVgQzlBAis3R24kL1omDGcHaxuazC5esJ5W
cW3utZiVvmuLyysAuRupkMsLe2Cy4nEYA3IKVjqJskTACOyBhrv1TjJyVHgUPfqk
acqMwIHL9fVmLpJwvNHd43btsx4RWtyTMeHxN4N09LnhUP7xlJZeFTgCW02Aqz8J
HMzqwDJLBmSo7S3tQDUcoID8wXjjC0FH2WcrAi+A6mIaSwweXPXI1wIDAQABo20w
azBKBgNVHREEQzBBghNhYWktbG9nb24uc3dpdGNoLmNohipodHRwczovL2FhaS1s
b2dvbi5zd2l0Y2guY2gvaWRwL3NoaWJib2xldGgwHQYDVR0OBBYEFKCIdiqWvBra
kKosFDkwV2lqXHPPMA0GCSqGSIb3DQEBBQUAA4IBAQCebaL+8PbVVbIpGsr+ZwvG
06XdJYWW6adQiOy110041UBodrjqi40rsqfJjhysrNxW9eCyVhJ8tq7Q/QUI6KHJ
iOOciw+p2c2KNI1nq54Nebjkal+hTbUvS8N7HTMvhYdu7gqqDgnvgP7s3iFAXI5b
qyPh4TWKXlb45GinyZ3T8OjB6UsHAmhn1hRFuwOa27csxu1qPvFhTgEgbXieo2Nr
vmIdMu967nRbVMztmAfd7Vv0eMj+YoKuA/RUWqJI6lMjHVpkl2ggE/Kb8mXX/wX1
pSfkm5o6j1ysHdGdoojvd+BikyPR7hGEs1lukWxump98WxdIHzmo5ErBr770nWRR
						</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="https://aai-logon.switch.ch/idp/profile/SAML1/SOAP/ArtifactResolution" index="1"/>
    <md:ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://aai-logon.switch.ch/idp/profile/SAML2/SOAP/ArtifactResolution" index="2"/>
    <md:NameIDFormat>urn:mace:shibboleth:1.0:nameIdentifier</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:mace:shibboleth:1.0:profiles:AuthnRequest" Location="https://aai-logon.switch.ch/idp/profile/Shibboleth/SSO"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://aai-logon.switch.ch/idp/profile/SAML2/POST/SSO"/>
  </md:IDPSSODescriptor>
  <md:AttributeAuthorityDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:1.1:protocol">
    <md:Extensions>
      <shibmd:Scope regexp="false">switch.ch</shibmd:Scope>
    </md:Extensions>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>
MIIFVDCCBDygAwIBAgIULqFVZ3v/ZWU2QoNe1Y/XyQSqGeAwDQYJKoZIhvcNAQEL
BQAwTTELMAkGA1UEBhMCQk0xGTAXBgNVBAoTEFF1b1ZhZGlzIExpbWl0ZWQxIzAh
BgNVBAMTGlF1b1ZhZGlzIEdsb2JhbCBTU0wgSUNBIEcyMB4XDTEzMTIwOTEyMTgw
N1oXDTE1MTIwOTEyMTcyNFowgcgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFTATBgsr
BgEEAYI3PAIBAhMEQmVybjEdMBsGA1UEDxMUUHJpdmF0ZSBPcmdhbml6YXRpb24x
GzAZBgNVBAUTEkNILTAzNS43LjAwMS4yNzgtOTELMAkGA1UEBhMCQ0gxEDAOBgNV
BAgTB1p1ZXJpY2gxEDAOBgNVBAcTB1p1ZXJpY2gxDzANBgNVBAoTBlNXSVRDSDEc
MBoGA1UEAxMTYWFpLWxvZ29uLnN3aXRjaC5jaDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAKplsvC4tYqZuV9IOjCWn6r5gMxMnmJ2EVZkMU8SSW4To8aB
/dhPc8MUkHQ3bQoew4iolSzBdQ8dCeALCHQLmHD5rqXsRvsTjtkPS7SjaEM4viLF
dz8oC8Y3x9RA5ruZf5KKPh6f2Dd/1s0IKpf7lPJx6px4ho2QwnOmwIAe3+QWrhK5
136hmtyObl+rDDkzCwBnir6BXYEPHMSXqR9u9McfCXHjw3qow/qSv2+Ae4lVHh2K
fiNbFTMa2t5zF53NyQNbK33ckrAJ1R1QcysBT3lyPK4wy3IACZkR2S6Af/GLGE5y
DWCiwZqKRI+TUcGGHNj7+GEFCfdfHgY8og8Rl/MCAwEAAaOCAa4wggGqMHMGCCsG
AQUFBwEBBGcwZTAqBggrBgEFBQcwAYYeaHR0cDovL29jc3AucXVvdmFkaXNnbG9i
YWwuY29tMDcGCCsGAQUFBzAChitodHRwOi8vdHJ1c3QucXVvdmFkaXNnbG9iYWwu
Y29tL3F2c3NsZzIuY3J0MFEGA1UdIARKMEgwRgYMKwYBBAG+WAACZAECMDYwNAYI
KwYBBQUHAgEWKGh0dHA6Ly93d3cucXVvdmFkaXNnbG9iYWwuY29tL3JlcG9zaXRv
cnkwOAYDVR0RBDEwL4ITYWFpLWxvZ29uLnN3aXRjaC5jaIIYeDUwOS5hYWktbG9n
b24uc3dpdGNoLmNoMAsGA1UdDwQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwHwYDVR0jBBgwFoAUkRlirVsXpzD78N45JbG9jLm4UScwOgYDVR0f
BDMwMTAvoC2gK4YpaHR0cDovL2NybC5xdW92YWRpc2dsb2JhbC5jb20vcXZzc2xn
Mi5jcmwwHQYDVR0OBBYEFO5qHZPNwV4RRgjWgE/kQYdVOMgYMA0GCSqGSIb3DQEB
CwUAA4IBAQAwEck5/yI4crrtFbfMDQzqBCXVQqLQPLZQuy6LcltubJgMY2gixwUk
g11zTpP8ydZWUzZJ4TdmJwQSxWOiHrmrkpXjPMJ/NKCS7VUjsR9qSLDeJzEs61E0
Pk8ssP/Caza7B5kUoY52NAfgCLyqGNNqDSCM02JD/sUIF4T5+OiVaDDzKPdBkOHE
Rei3SQPXcLygCnwaXVWkmQLoqXESIXqmOwbWoACmBolMHKPGzp/4rvp3ejPUwYru
FIwRkLdxvdKOzE/feFbX4GkXgvg6GmELxSZbakbuQoNeS/aTLYR2Y/GuE4UrA533
Sih8+vYwOym3ZyV+cdIM1uoInD5lJmgl
						</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>
MIIDLDCCAhSgAwIBAgIJAIHilzMu/j8KMA0GCSqGSIb3DQEBBQUAMB4xHDAaBgNV
BAMTE2FhaS1sb2dvbi5zd2l0Y2guY2gwHhcNMTMxMjAyMTUxNzI5WhcNMTYxMjAx
MTUxNzI5WjAeMRwwGgYDVQQDExNhYWktbG9nb24uc3dpdGNoLmNoMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA72Gf8Be0k33Ucdk6+m/wpe70eZdL8n9Q
Dk4AuJ7uLFqo9vfJFRpEDbfGAt2s9esAfxX0harLVhEP7bX4HQxDt7uM9PeDXZ3M
GGiKL4hCNR4RKY1pfx7PoLDHthiO5vVgQzlBAis3R24kL1omDGcHaxuazC5esJ5W
cW3utZiVvmuLyysAuRupkMsLe2Cy4nEYA3IKVjqJskTACOyBhrv1TjJyVHgUPfqk
acqMwIHL9fVmLpJwvNHd43btsx4RWtyTMeHxN4N09LnhUP7xlJZeFTgCW02Aqz8J
HMzqwDJLBmSo7S3tQDUcoID8wXjjC0FH2WcrAi+A6mIaSwweXPXI1wIDAQABo20w
azBKBgNVHREEQzBBghNhYWktbG9nb24uc3dpdGNoLmNohipodHRwczovL2FhaS1s
b2dvbi5zd2l0Y2guY2gvaWRwL3NoaWJib2xldGgwHQYDVR0OBBYEFKCIdiqWvBra
kKosFDkwV2lqXHPPMA0GCSqGSIb3DQEBBQUAA4IBAQCebaL+8PbVVbIpGsr+ZwvG
06XdJYWW6adQiOy110041UBodrjqi40rsqfJjhysrNxW9eCyVhJ8tq7Q/QUI6KHJ
iOOciw+p2c2KNI1nq54Nebjkal+hTbUvS8N7HTMvhYdu7gqqDgnvgP7s3iFAXI5b
qyPh4TWKXlb45GinyZ3T8OjB6UsHAmhn1hRFuwOa27csxu1qPvFhTgEgbXieo2Nr
vmIdMu967nRbVMztmAfd7Vv0eMj+YoKuA/RUWqJI6lMjHVpkl2ggE/Kb8mXX/wX1
pSfkm5o6j1ysHdGdoojvd+BikyPR7hGEs1lukWxump98WxdIHzmo5ErBr770nWRR
						</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:AttributeService Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="https://aai-logon.switch.ch/idp/profile/SAML1/SOAP/AttributeQuery"/>
    <md:AttributeService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://aai-logon.switch.ch/idp/profile/SAML2/SOAP/AttributeQuery"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:mace:shibboleth:1.0:nameIdentifier</md:NameIDFormat>
  </md:AttributeAuthorityDescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">switch.ch</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="de">SWITCH</md:OrganizationDisplayName>
    <md:OrganizationDisplayName xml:lang="en">SWITCH</md:OrganizationDisplayName>
    <md:OrganizationDisplayName xml:lang="fr">SWITCH</md:OrganizationDisplayName>
    <md:OrganizationDisplayName xml:lang="it">SWITCH</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="de">http://www.switch.ch/</md:OrganizationURL>
    <md:OrganizationURL xml:lang="en">http://www.switch.ch/</md:OrganizationURL>
    <md:OrganizationURL xml:lang="fr">http://www.switch.ch/</md:OrganizationURL>
    <md:OrganizationURL xml:lang="it">http://www.switch.ch/</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="support">
    <md:GivenName>SWITCHaai</md:GivenName>
    <md:SurName>Team</md:SurName>
    <md:EmailAddress>mailto:aai@switch.ch</md:EmailAddress>
    <md:TelephoneNumber>+41 44 268 1505</md:TelephoneNumber>
  </md:ContactPerson>
  <md:ContactPerson contactType="technical">
    <md:GivenName>SWITCHaai</md:GivenName>
    <md:SurName>Team</md:SurName>
    <md:EmailAddress>mailto:aai@switch.ch</md:EmailAddress>
    <md:TelephoneNumber>+41 44 268 1505</md:TelephoneNumber>
  </md:ContactPerson>
</md:EntityDescriptor>`)
)

func ExampleSignAndValidate() {
	block, _ := pem.Decode(privatekey)
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	xp := NewXp(response)
	assertion := xp.Query(nil, "saml:Assertion[1]")[0]
	xp.Sign(assertion, priv, "sha256")

	xp = NewXp([]byte(xp.Pp()))

	fmt.Println(xp.Query1(nil, "saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm"))
	fmt.Println(xp.Query1(nil, "/samlp:Response/saml:Assertion/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm"))

	assertion = xp.Query(nil, "saml:Assertion[1]")[0]

	pub := &priv.PublicKey

	fmt.Printf("verify: %v\n", xp.VerifySignature(assertion, pub))
	// Output:

	xp.Sign(assertion, priv, "sha1")
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
	// PpfypKN3QeBy3DTjzZx3cgA6KfA=
	// LlDp6BWKMiQZOapOaUKH2rwrk3tU5xLqLh5cb8LdgZ4z3nFn0Ok0+AC+9kHCHtIxmdyGYwrIg35MsSM/y1FZ1il65bMufHwBY4D8rXWqO2wEKNRYq01n1pb/g74AMFkBjtasfPMXl7CF6jl+dZw7yiSf8dRfXTLLHTkT1MAGp6A=
}

func ExampleMetadata() {
	md := NewXp(idpmetadata)
	fmt.Println(md.Query1(nil, "//md:EntityDescriptor/@entityID"))
	fmt.Println(md.Query1(nil, "//md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat"))
	// Output:
	// https://aai-logon.switch.ch/idp/shibboleth
	// urn:mace:shibboleth:1.0:nameIdentifier
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
	spmd := NewXp(spmetadata)
	idpmd := NewXp(idpmetadata)
	spmd.context = spmd.Query(nil, `//md:SPSSODescriptor`)[0]
	idpmd.context = idpmd.Query(nil, `//md:IDPSSODescriptor`)[0]
	request := NewAuthnRequest(spmd, idpmd)
	// fixate the IssueInstant and ID for testing ....
	request.QueryDashP(nil, "./@IssueInstant", "2015-09-03T14:15:16Z", nil)
	request.QueryDashP(nil, "./@ID", "fixed id", nil)
	fmt.Print(request.Pp())
	log.Print(request.Pp())
	// Output:
	// <?xml version="1.0"?>
	// <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="fixed id" IssueInstant="2015-09-03T14:15:16Z" Destination="https://aai-logon.switch.ch/idp/profile/SAML2/Redirect/SSO" AssertionConsumerServiceURL="x" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerURL="https://attribute-viewer.aai.switch.ch/Shibboleth.sso/SAML2/POST">
	// <saml:Issuer>x</saml:Issuer>
	// <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/>
	// </samlp:AuthnRequest>
}

func ExampleResponse() {
	idpmd := NewXp(idpmetadata)
	spmd := NewXp(spmetadata)
	idpmd.context = idpmd.Query(nil, `//md:IDPSSODescriptor`)[0]
	spmd.context = spmd.Query(nil, `//md:SPSSODescriptor`)[0]

	sourceResponse := NewXp(response)

	request := NewAuthnRequest(spmd, idpmd)
	response := NewResponse(idpmd, spmd, request, sourceResponse)
	//log.Print(response.Pp())

	// fixate the IssueInstant and ID for testing ....
	response.QueryDashP(nil, "./@IssueInstant", "2015-09-03T14:15:16Z", nil)
	response.QueryDashP(nil, "./@ID", "fixed id", nil)
	fmt.Print(response.Pp())
	// Output:
	// <?xml version="1.0"?>
}

func ExampleJustForKeepingLogImported() {
	log.Println("ExampleJustForKeepingLogImported")
}
