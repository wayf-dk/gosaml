package gosaml

import (
	"crypto"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/wayf-dk/go-libxml2/types"
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

	mdq = "https://phph.wayf.dk/MDQ/"

	spmetadata, idpmetadata, hubmetadata, testidpmetadata, testidpviabirkmetadata *goxml.Xp

	spmetadatxml = `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth">
  <md:Extensions>
    <mdrpi:RegistrationInfo registrationAuthority="http://rr.aai.switch.ch/" registrationInstant="2017-06-21T10:32:46Z">
      <mdrpi:RegistrationPolicy xml:lang="en">https://www.switch.ch/aai/federation/switchaai/metadata-registration-practice-statement-20110711.txt</mdrpi:RegistrationPolicy>
    </mdrpi:RegistrationInfo>
    <mdattr:EntityAttributes>
      <saml:Attribute Name="http://macedir.org/entity-category" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>http://www.geant.net/uri/dataprotection-code-of-conduct/v1</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="swissEduPersonHomeOrganization" Name="urn:oid:2.16.756.1.2.5.1.1.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>switch.ch</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="swissEduPersonHomeOrganizationType" Name="urn:oid:2.16.756.1.2.5.1.1.5" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>others</saml:AttributeValue>
      </saml:Attribute>
    </mdattr:EntityAttributes>
  </md:Extensions>
  <md:SPSSODescriptor errorURL="http://www.switch.ch/aai/support/help" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:Extensions>
      <mdui:UIInfo>
        <mdui:DisplayName xml:lang="en">AAI Viewer Interfederation Test</mdui:DisplayName>
        <mdui:Description xml:lang="en">This service is used to test the interfederation readiness of SWITCHaai Identity Providers.</mdui:Description>
        <mdui:Logo height="16" width="16">data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAACF0RVh0U29mdHdhcmUAR3JhcGhpY0NvbnZlcnRlciAoSW50ZWwpd4f6GQAAAZJJREFUeJyUk08og2Ecx5+SHNSW/DtQlHKg1MhByjIpLRNx0NZKk0kbbSStHXZdHOVP4bCi5swuXNxQLjiN5UBNc1AzbeR936/39zz7c7B/Dt+e31PP9/P8ft/3eRkARpKPnVDuQsjsy1W2kA8skKwM8tEsEH8tG5QDqEZpqZILdgblbB34+igJygG2RrlRWqsXcqi1pwXKdaAoJLehtk99kJa1wkxrupb9OihPl3lBf6kqiPLg3ThER3BVCRDl8/aI4oC0lFhYGOyiG9nTKIAECjqzQZdMmVqnEbBaAfi0gLeaQ6grGrkkIPqexJjFi+E+PSZGTDANGjHQq8dQdz8CPndhY+Q5hjnPPlirGazDBta5CNakrrVmmGybiETj+UegG3cOz8Gap4V6FgSgYRLthhXcP7zkDzH1/cONmjYrP8xNXXZea9Q6dHELOlPwM1pX98BqxoWRpLZep5uHf/cEic9UwceULaZc22LetGj+eCJZ/lOmYBgzwDizAQrw3z+T2x/E1U24bGNGvwAAAP//AwCkGcs+iePLFQAAAABJRU5ErkJggg==</mdui:Logo>
        <mdui:Logo height="60" width="80">data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFAAAAA8CAIAAAB+RarbAAAC0GlDQ1BJQ0NQcm9maWxlAAB4nI2Uz0sUYRjHv7ONGChBYGZ7iKFDSKhMFmVE5a6/2LRtWX+UEsTs7Lu7k7Oz08zsmiIRXjpm0T0qDx76Azx46JSXwsAsAuluUUSCl5LteWfG3RHtxwsz83mfH9/ned/hfYEaWTFNPSQBecOxkn1R6fromFT7ESEcQR3CqFNU24wkEgOgwWOxa2y+h8C/K617+/866tK2mgeE/UDoR5rZKrDvF9kLWWoEELlew4RjOsT3OFue/THnlMfzrn0o2UW8SHxANS0e/5q4Q80paaBGJG7JBmJSAc7rRdXv5yA99cwYHqTvcerpLrN7fBZm0kp3P3Eb8ec06+7hmsTzGa03RtxMz1rG6h32WDihObEhj0Mjhh4f8LnJSMWv+pqi6UST2/p2abBn235LuZwgDhMnxwv9PKaRcjunckPXPBb0qVxX3Od3VjHJ6x6jmDlTd/8X9RZ6hVHoYNBg0NuAhCT6EEUrTFgoIEMejSI0sjI3xiK2Mb5npI5EgCXyr1POuptzG0XK5lkjiMYx01JRkOQP8ld5VX4qz8lfZsPF5qpnxrqpqcsPvpMur7yt63v9njx9lepGyKsjS9Z8ZU12oNNAdxljNlxV4jXY/fhmYJUsUKkVKVdp3K1Ucn02vSOBan/aPYpdml5sqtZaFRdurNQvTe/Yq8KuVbHKqnbOq3HBfCYeFU+KMbFDPAdJvCR2ihfFbpqdFwcqGcOkomHCVbKhUJaBSfKaO/6ZFwvvrLmjoY8ZzNJUiZ//hFXIaDoLHNF/uP9z8HvFo7Ei8MIGDp+u2jaS7h0iNC5Xbc4V4MI3ug/eVm3NdB4OPQEWzqhFq+RLC8IbimZ3HD7pKpiTlpbNOVK7LJ+VInQlMSlmqG0tkqLrkuuyJYvZzCqxdBvszKl2T6WedqXmU7m8Qeev9hGw9bBc/vmsXN56Tj2sAS/138C8/UXN/ALEAAAJI2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iWE1QIENvcmUgNC40LjAiPgogICA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPgogICAgICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIi8+CiAgIDwvcmRmOlJERj4KPC94OnhtcG1ldGE+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAKPD94cGFja2V0IGVuZD0idyI/Pqfd9JIAAAAhdEVYdFNvZnR3YXJlAEdyYXBoaWNDb252ZXJ0ZXIgKEludGVsKXeH+hkAAAaRSURBVHic7JZpUFNXFMf92A+dsR8ECrQ6Fq2tlVVELVQEZLNaoSwV1FEsy6CMuyJhFRAQQiAJEBCIiCigaAUFFARZlE0EAReoiiCgLGUnJIQktyc8GpKXSPnUzjzefzKZ9+4979z7u/fcc+4StMi05P+ewH8tEpjoIoGJLhKY6CKBiS4SmOgigYkuEpjoIoGJLhKY6CKBia5FDMyZnLpT/Nzl+FXbgykObmw719TopLKe3hHoEolE2bkN9NTy8XGe9Me37zUHUQu7P4pt0EgHqo5EnRUy7qd56CkLteXBo0AovJRZc7f4BdbTNzAenfgwKqEkGn6sUkZKGS3pYRSrlMoqjaAX5z94Ie3mz/Z+WkrZbs/LtgdT7VzZ9m7snPxnXN60xIA/LUjOqCoqb5UnnOTykzKrwLMM8NgEz9krfc2WsF0uKY4elxzg535J35q63opa19gJBtl5jUqavuysGmlfj2rffrb8hBclR/xSehrRl6G+JpnRXuUg2lL0Oh8ep/gCw12xHt7XsZ62t31We1iWzizrPYnmTqyVm4MNdtC270uycmaZOcZFJpTMrphAeJ5e9K1RqJFNrL27GNXBnf2LS7LGjyFup7N4U9MSKj3LqFMhufLAg8McGHfpGm8ZYFjdlZuCi8tbBQKhxLS98y/tbRfcz2RjA8MCw+uHvlFpdyfP3f58tU99eSliqaOSkzJD8UZR2kZ0yw4JhdgmGNsxvHxzsE6hSARbxOXxebzpzu4hLbMLjNRyWBRogR8YY2aFZa/U1wcw2RVDIxyJY5hkes4TNV3/ipo3EmCDn6O9z+cpBDa2Y6rrBcgAw/Js+ZU5OsbFWZ8Nu+PpcwN7rn/2/iv9QL/IfGkD4FfXjzhmswOlrUGjnTIf1zMR7QvUXYW94YBxTtaZRsRcfCjfFRxzD7rGJ3i49o6uQY3NwUlXZp1zuPwN8wEz8MBGtnSIXtzugSBmpI/KmdC8FRuDnrd+lLahJtd4WpqipxHSjSLOAErUQAVukpZ5gCFTiIGTFAAHUAuM7ZmSDZcItjS/5Pnr9n7J64bt0ZSIO/IexiemTOzjVHX9ZYAhXcHuuRy/llfUUv30XW1jR/PLnvc9w9NSEQ7q6hleaxJ+8ESmSCiSNA6M8K/QqIjbK20pqAwRMVTRYNscMF8MfJiieIe1tl1QuMOB1AITxzh5YJy4XP6mnTG/n8x80tQJk5f8IAGVVLZt3hmjrOkrAwzKvd8CWcHQhg5faptH6phH/mASbr47obahQ9p1fNojFR2/4oq5fMgXoJrCXNHU+JwRcDJVURlF+sP5Qrp3RNMsgqYI2D+qwHQBwLDDP9nSVxmG6lqIZ65jESl+mHkGllWGIV/rB+KB0Uz5gS+HRyY/9o3CIamsfQvwkEVhcyQ2E5wpM8d4C6cEKGNYy+PG3qD99ujV5TlHxUdErFVorGuhwDM7HK0opAOphaaO8QsB3riDdjTg1sDgRO/AWG//GPbfNzDW+qYP1gK/w4+ftDe2dPOnhThHUCchMw8OT0g33n3wUlnbDytRsEZ7j988tssCXd2AuEPi7v5mxFAV1DFwruY/w5/a4aDoQghI4MG1Q6KGip2V24C9cmbOsE+4gjM8PDq51V4uSytr+ULuhj6cNTO1HIBh2XCDOR1K17WIgliorn+nph+SwWCgBGVUFwMrgHKdEVsP8YYWDoyFtMKkFRp7/3vjMMi0uHZILlBZvPxmvc2WpTAFwFhZUsMlLbhvrDYKrW2QqSucSf5vnmmmDnHSIY2pvun9CoMgmM2ew+lwbRBn8gJXxNJAzWmIoYKa2PID/2tI0xQB3y9rVdMLyLhZh2uvqn+33CAoPq1SFnjBZamza8h6byKcctdTWYd8bnh4Z3ucybZwZsEqZN1ukPeCZkr0lzr+yw3OQYYXvw+9RqxvEF0FXdsmvnLICS4VRjb0Q/9UdWlBSK/dGhadWCrfBWsNdxuYBlwEYVZwC4KJ7TuSsXZrOOSRrg/DmBmEtJ5V1OlP3LRg3GXrKDLA4gmPcJipFbqWkUpaFGUtP0jFTofTG5q75F1ggqJ14NhVmM1cRqlnirKtUXuRQnswOxH0R2xyuXwXHJn9RzOu5yleWaFQlHuv5TvjMCVNioq2n9I6CgQ5hMOQVJzDfcHz7PWLGdXyn4+N847637Q5kIwHXiQigYkuEpjoIoGJLhKY6CKBiS4SmOgigYkuEpjoIoGJLhKY6CKBia5FB/w3AAAA//8DABFh2N/+esWhAAAAAElFTkSuQmCC</mdui:Logo>
        <mdui:InformationURL xml:lang="en">https://attribute-viewer.aai.switch.ch/interfederation-test/</mdui:InformationURL>
        <mdui:PrivacyStatementURL xml:lang="en">https://attribute-viewer.aai.switch.ch/interfederation-test/privacy-statement.html</mdui:PrivacyStatementURL>
      </mdui:UIInfo>
    </md:Extensions>
    <md:KeyDescriptor>
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>
MIIEazCCAtOgAwIBAgIJAMzpWW4jK45pMA0GCSqGSIb3DQEBCwUAMCkxJzAlBgNV
BAMTHmF0dHJpYnV0ZS12aWV3ZXIuYWFpLnN3aXRjaC5jaDAeFw0xNzA1MDIxMzEx
MDVaFw0yMDA1MDExMzExMDVaMCkxJzAlBgNVBAMTHmF0dHJpYnV0ZS12aWV3ZXIu
YWFpLnN3aXRjaC5jaDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBANAo
zd3IqeB3uhUk3ibftET4UbbZIZozq00Zs7aIR8RvTyEPh31LC3MprQiFOG2GRZr1
XKwGvMTkolFKLyF1ylYpTxZr0MRx3R+Zvgzx+l5pQkE1/6NiEJpM+8K0IQmJraGS
exZ+EFkR1aBB/HrSyhfHUJ5bsD+gGmQa+w/lJNs0PJ+BDkwRc4gIAOrJuOWZ2OAt
uhO77LYTeOteYH4RpH3NOJXt9V47O+XVWr89pu3JZpwlV/ARx39jnqN7bCTbGEAh
+q0Iogk04ygJ1CyFy89g8Bt2Ov8ug4AwU6em0BrmHSCXkTpHH0y56lNhQYh9VoDL
G+vAdoIXYMpRmYn05FPlbHGMx/HJangKpulCKGu7+uf5u3zYjpbNUnWZllNQp4Oy
BAbQD4cKFtD4feYa32XBUL7zAQxCq0eOm5dvBen4da+QPeaO67YbflF2eK+9qDtB
OruM4jKAnOWhXmEGOjm9oiikmhe8i5TX06GA+dU1Srlx0ACZ0BrYNp/ogS/8CwID
AQABo4GVMIGSMHEGA1UdEQRqMGiCHmF0dHJpYnV0ZS12aWV3ZXIuYWFpLnN3aXRj
aC5jaIZGaHR0cHM6Ly9hdHRyaWJ1dGUtdmlld2VyLmFhaS5zd2l0Y2guY2gvaW50
ZXJmZWRlcmF0aW9uLXRlc3Qvc2hpYmJvbGV0aDAdBgNVHQ4EFgQUDb5B6ltdkhzV
LOXRU+EQjrIEHbAwDQYJKoZIhvcNAQELBQADggGBAKxwMmaDDhu84c7TrFmayfvW
hXxey0HiauxGr4RrtmoUV00N48TOaX7rsVji/8u9cz2kxShQAWFYvpe/mCRBkZhy
y9D87zqdw7EksKmj/7/vGD1D15wMqtK98SLHRRiUoUAAsckn4C9nAtY7Hvvz4Xxb
BCJ2mfwhYHw02gzGeDSsH0xKdAKI17HxSx7+BG/220g1FP+1PMdcJTi8h5b5lDmf
Q4bmcPiyIjvqEhYB4gAafXr9w96L/u2H2vQQCsxn8kmCV6SCruIkL/3mg++z0vQB
q12vFZw6ITX+iPayPjw1cKbL/3t/W3EUEB9IegRtu/9YIazyyObEf1Y67wjL2KE6
hI/yn+W8fyS340deg7IlWsogDKSrahTnF8g1HDb06gnRwqQzsGcqHY7KCArbh5Ks
X+QsxofV054+Ex6vtMd0fgnKA7DaInnmrIiN2OWl3TC2exSjt5O5zK6suX+3Rzzy
o62EePTDB7SHh4OWulz08Em6RtbKgyiKmNvHdmT4Ww==
						</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST" index="1"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST-SimpleSign" index="2"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/Artifact" index="3"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:PAOS" Location="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/ECP" index="4"/>
    <md:AttributeConsumingService index="1">
      <md:ServiceName xml:lang="en">AAI Viewer Interfederation Test</md:ServiceName>
      <md:ServiceDescription xml:lang="en">This service is used to test the interfederation readiness of SWITCHaai Identity Providers.</md:ServiceDescription>
      <md:RequestedAttribute FriendlyName="eduPersonAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="email" Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonScopedAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.9" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonTargetedID" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="commonName" Name="urn:oid:2.5.4.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="displayName" Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonUniqueId" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.13" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrincipalName" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacHomeOrganization" Name="urn:oid:1.3.6.1.4.1.25178.1.2.9" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacHomeOrganizationType" Name="urn:oid:1.3.6.1.4.1.25178.1.2.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
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
    <md:GivenName>AAI</md:GivenName>
    <md:SurName>Team</md:SurName>
    <md:EmailAddress>mailto:aai@switch.ch</md:EmailAddress>
    <md:TelephoneNumber>+41 44 268 1505</md:TelephoneNumber>
  </md:ContactPerson>
  <md:ContactPerson contactType="technical">
    <md:GivenName>AAI</md:GivenName>
    <md:SurName>Team</md:SurName>
    <md:EmailAddress>mailto:aai@switch.ch</md:EmailAddress>
    <md:TelephoneNumber>+41 44 268 1505</md:TelephoneNumber>
  </md:ContactPerson>
</md:EntityDescriptor>`

	idpmetadataxml = `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:remd="http://refeds.org/metadata" entityID="https://aai-logon.switch.ch/idp/shibboleth">
  <md:Extensions>
    <mdrpi:RegistrationInfo registrationAuthority="http://rr.aai.switch.ch/" registrationInstant="2017-05-18T14:28:03Z">
      <mdrpi:RegistrationPolicy xml:lang="en">https://www.switch.ch/aai/federation/switchaai/metadata-registration-practice-statement-20110711.txt</mdrpi:RegistrationPolicy>
    </mdrpi:RegistrationInfo>
    <mdattr:EntityAttributes>
      <saml:Attribute Name="http://macedir.org/entity-category-support" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>http://www.geant.net/uri/dataprotection-code-of-conduct/v1</saml:AttributeValue>
        <saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="urn:oasis:names:tc:SAML:attribute:assurance-certification" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>https://refeds.org/sirtfi</saml:AttributeValue>
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
        <mdui:Logo height="60" width="80">data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFAAAAA8CAYAAADxJz2MAAAC0GlDQ1BJQ0NQcm9maWxlAAB4nI2Uz0sUYRjHv7ONGChBYGZ7iKFDSKhMFmVE5a6/2LRtWX+UEsTs7Lu7k7Oz08zsmiIRXjpm0T0qDx76Azx46JSXwsAsAuluUUSCl5LteWfG3RHtxwsz83mfH9/ned/hfYEaWTFNPSQBecOxkn1R6fromFT7ESEcQR3CqFNU24wkEgOgwWOxa2y+h8C/K617+/866tK2mgeE/UDoR5rZKrDvF9kLWWoEELlew4RjOsT3OFue/THnlMfzrn0o2UW8SHxANS0e/5q4Q80paaBGJG7JBmJSAc7rRdXv5yA99cwYHqTvcerpLrN7fBZm0kp3P3Eb8ec06+7hmsTzGa03RtxMz1rG6h32WDihObEhj0Mjhh4f8LnJSMWv+pqi6UST2/p2abBn235LuZwgDhMnxwv9PKaRcjunckPXPBb0qVxX3Od3VjHJ6x6jmDlTd/8X9RZ6hVHoYNBg0NuAhCT6EEUrTFgoIEMejSI0sjI3xiK2Mb5npI5EgCXyr1POuptzG0XK5lkjiMYx01JRkOQP8ld5VX4qz8lfZsPF5qpnxrqpqcsPvpMur7yt63v9njx9lepGyKsjS9Z8ZU12oNNAdxljNlxV4jXY/fhmYJUsUKkVKVdp3K1Ucn02vSOBan/aPYpdml5sqtZaFRdurNQvTe/Yq8KuVbHKqnbOq3HBfCYeFU+KMbFDPAdJvCR2ihfFbpqdFwcqGcOkomHCVbKhUJaBSfKaO/6ZFwvvrLmjoY8ZzNJUiZ//hFXIaDoLHNF/uP9z8HvFo7Ei8MIGDp+u2jaS7h0iNC5Xbc4V4MI3ug/eVm3NdB4OPQEWzqhFq+RLC8IbimZ3HD7pKpiTlpbNOVK7LJ+VInQlMSlmqG0tkqLrkuuyJYvZzCqxdBvszKl2T6WedqXmU7m8Qeev9hGw9bBc/vmsXN56Tj2sAS/138C8/UXN/ALEAAAJI2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iWE1QIENvcmUgNC40LjAiPgogICA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPgogICAgICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIi8+CiAgIDwvcmRmOlJERj4KPC94OnhtcG1ldGE+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAKPD94cGFja2V0IGVuZD0idyI/Pqfd9JIAAAAhdEVYdFNvZnR3YXJlAEdyYXBoaWNDb252ZXJ0ZXIgKEludGVsKXeH+hkAAAiDSURBVHic7Fh7bFPXGT9x4vgR29fva1/HsRM78StODE0CCTQoJiEPh7wgNoFAgkt4jpF2/aNTira0/2za2qGC1IcoUwlTaaF0XRJRaLRB2QCxTtAHrxUWNfQBnWAPprFNNN5377UTO7GzKop2dKQc6ed7z3dev/O73znnO0aRSATNY/bAToB0YCdAOrATIB3YCZAO7ARIB3YCpAM7AdKBnQDpwE6AdGAnQDqwEyAd2AmQDuwESAd2AqQDOwHSgZ0A6cBOgHRgJ0A6sBMgHdgJkA7sBEgHdgKkg/9hk1jlkJvKX1LmN/9B62y/oXe03YTnNWV+06CMWbQBxSWpqWKv0tZwRiBjsnlLWqwoU5pTdUJhrdmPxBRnyFYj40AbdbqvSvyDWKUMAf/sKBbuOhpSXgiXiCr4AimSWfw/zzJXvslmTSZaMDh0HF4azirtjROgbIHJdwBC/rNjtz5ndj/9dDxNeZZh4ePKvLphtXP1ZXY+eseqm1oAZVkO3E01PPX0iQbpipx0hS0wLNF5f4pSJ4HcunwPlVf7m0kBhTKruqDlnrE4/GfaFTqhdwWPAF7Xu0Lv0O6Oy0zxY+OqvLonYj1IDAvLmaLwA2Ve/YF49TjWpvLHmeJND7OYRT42v69B8coXu4x3t5aJLJO1uCbG013qu3/aYXzfbxcIefkppHevOatxrPqIE5DRCYaG30Uor31E7w6NAJ8R2rP2gql4U4T2rPuQzbNAqGnk1q0vmN27owJKNLS2oPUq44N67rW/h7kMAQ7zcwoeNRZt/BjGuYfkZiaeu1DtRFA2qjRV/HIGAdNBo2Gjp/OrCQFlzOKfMb6e/8jMj1qTNBCq7I1XjEXhy0jtEMeMKlvgFaZoYwQK3TFRokqmaR2rryBn50ethXTZ2E46sr9JsYMtEAnSkCj6wXcszuy/08tE9tYrOE8QcSMpkM4VOqspaOUEzMqSokCgkX0DcRVcO5G+uIzxdkUyjaXNvOi8vaurC5WUlHDvytyalxjf5og8p7I6Vh6fJMYSZIL5yC3+XfH2DHUBCNg9Sn0LAWlXx+0JAZW5K44bvN03EJWbtIVYW/gdjX3lC0J1wQQbgdrhhsH+qbY1Hp6omMavTQFlLUL5XQ/fWOO/fX0b+sRKIyk3chovNOSs58Pav13ZQg/bDSgjap0m4MTE4ievL65kvN0RsaFkVcwmEsbVhQ8E7c/pXMFLKSUQyhHt7RrS2JsGEsaJCvhtPBBWZpyAeXUjBu/GsXSlfVrtNEFGooHL875G5a7YB0t5XKwrijYEe1pUD0PtW4fXBR7+uBpxHpYJE4t5X79feuDuE8w3/VXSIjYvjg2RQsD4lEzAqUnnaLuoLWg5g6ZsL/FJZCqvFuuLl8TbZi0g7FsvmxZsHqdya5bM0BClTWy4UV4yo9ZQuOEvQPjZaZWz9Ez9I4+8qpfxWUFsKkrEXOrR37/YQx9L6ItNcyUgtIc98H2UVMApJsGk+3ICemEJM2VHUvXNdkC7gr9KEBA23VwgPQLqfw0F52nXml9DpZOwmb+htjfuhz2lP1NdYOKbpyf0BifuNtisx7KMJcqEcqnZ2bV00YFCOkouyvvFgOL5r3tNo99bIub6E8Z3N2ceCAI6UgmYOvECdo3CATWmcQUHNa7Q8WlwBgdBp6/AC28nhjHpEiShfWaFeVm50lpdq7LVh9S2+i2a/OaXjd4N9+D0+xgpLFmTw0W5STQIBvxA71n7KhIpJwvpunNHOxvG99ShcMzoyUaqT7cb7ox0atsS+oil/4MHCoXCafVjtpiAEOqchgijHUK1oNJWPwUN7aDHB+BkUwSMS6KpeXphH1McjsjNSxckFES9TcaUP2ny9UQU5kreSylrLcrvHn9nfe39G9vRlzoN4hbyay1U/+1dzM2e0kyOcSwenJzJHAroaP1tqnKfz4dWrgxwKC0tnbDHLeFjqdoifgkPJSzhgYFD5oFDvzAfPHgQ+f3++Lr8Q25uNng6I5S12p+0ywypSe/uGKcL178JMaUATuzryNl9fWeFfcWdXt03L9TLnlqahyy3djJ/PRZU7U5JbY4E1DraLgHOpyrv7e1FQ8PvoWFAX1/f5DRme4g8tuX7Fzdtf3Y0HN6MnI786U0UlqCxcH2EsvgfnVYW9UIIrl+EgDuidrQ+B8HouCK3toMtPbFOc+raNvqzobXKPWM7jeONbuThWEz1PjbNkYBsGAOB8rVkZTKZNPq2fC9CNSPsm1zOn3SzFhChiiOoIPxvhEosyVrIc5a9DuI8kBrLbDN0bNA5V0eyF2yJGLwbbsC1iDM2eTJ8n3/XOH7/SVPkYKtieIb2cyYgRBN72S0ly1Q+/YNDytC62b3uJNy+EpZqhmqWgTQs0WVaV/ABeM5nsHfs09oCz+hsDc9o7YGfgCin4MbxUFPQ8hoSqZKfatEAWqwv2gM3FnapRyfHeafg7ZD65NWt9D9Kc5CLs6Y6G0Uq7iqnjV7lkiWJ3ldp8m6MiI1lKQVEYo0BlvB1mM/fIcQ6pLU1/JCbj62hHw6X50G839GFnf8S633L45sJNS4Ece2oMvt/COgODRs8675MPEQk6jJ59tIBuKKdUzlWf6JyBq+oHKsuQf6EPHvJU0iskvBipSftNY0XUSGzNZ5KV/COHFumWxcLyw6FpIOcbQZm7A2B/TNBlrMsZRwmVNoWULl1Z2CytcmJREcQynQwn32qgpYLKteaPwI+VTnbr6rymz+kLFXvIsrCRQLxF4UMyiqg8uqHJFrPj2ZgKZDnVD1H5dW+N/931lz9nTWPeQHnBSQV2AmQDuwESAd2AqQDOwHSgZ0A6cBOgHRgJ0A6sBMgHdgJkA7sBEgHdgKkAzsB0oGdAOnAToB0YCdAOrATIB3YCZAO7ARIB3YCpOO/AAAA//8DAB7/hgVtBuDqAAAAAElFTkSuQmCC</mdui:Logo>
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
MIIDODCCAiCgAwIBAgIVAOHRUcIpcc6WV15j+aah9ZXVVyJZMA0GCSqGSIb3DQEB
CwUAMB4xHDAaBgNVBAMME2FhaS1sb2dvbi5zd2l0Y2guY2gwHhcNMTYxMDI3MTQy
MjM4WhcNMTkxMDI3MTUyMjM4WjAeMRwwGgYDVQQDDBNhYWktbG9nb24uc3dpdGNo
LmNoMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArLd72HcN5+YRFvU4
Rl+xw6pq2eRFTUQ4j3TyN5q1xcWkkmpX3CAYQA86X465Jj7wc/RVryn9PZMQvv0p
XesDO4cjjp3S2w4QqtrInjFNIPXZZeamAr2QX3BHhWFnDkmCynmOiJyS4ngV7NUl
Rai3wsHjF7dEBXpJgmiMRxNUYcvr8BoAZzhO3Vu9SoM6ufoBHhup6oUQNegfmm/n
KD/3JPvqIQRKZbh+8/qxVVTIafuPVuTrVeF8Xnax7FA91XdwhmOMZPHS2E4uMRFI
R1TcY+D0jshWhoEEtBMb/SmCNxSvZm04hgcWyOwoXotaHu22PpoyKylVHkBRo6YH
t0xNgQIDAQABo20wazAdBgNVHQ4EFgQUbHSsyKFXxRa/CbTsl/rzWU2S4qMwSgYD
VR0RBEMwQYITYWFpLWxvZ29uLnN3aXRjaC5jaIYqaHR0cHM6Ly9hYWktbG9nb24u
c3dpdGNoLmNoL2lkcC9zaGliYm9sZXRoMA0GCSqGSIb3DQEBCwUAA4IBAQBT2U1g
r9O1Sd3cOOwDMrn/js5SUp7eBES1p6DBodrxgNBcL6JFX4qnE0eN9p4k/YdnbblZ
lB1/BSgz5ywnN0vdJILGmTK9qYRH3aN76fmX0mTvYK0pvBDKXhfQChcy60sb+asW
PG5ew1mG1ygfaCU4shIvUr//RaOHJOwtGKMQDXc9O+TOSOCGd+MzLXpxsq//a8ZJ
ZXwnpCEmUJoymMlOoEHAUxX7IdhrJwjtRm+b91dQpZk/jAEU/T7hfRUdhyznPaVt
bmjMq7ionfJYA34hS6c/2PXki5INUn9cPbi0GUZayF0hsspr85iPkD9u9MsrI48Z
Wk7ii+Su2RCnqP9H
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
MIIDODCCAiCgAwIBAgIVAOHRUcIpcc6WV15j+aah9ZXVVyJZMA0GCSqGSIb3DQEB
CwUAMB4xHDAaBgNVBAMME2FhaS1sb2dvbi5zd2l0Y2guY2gwHhcNMTYxMDI3MTQy
MjM4WhcNMTkxMDI3MTUyMjM4WjAeMRwwGgYDVQQDDBNhYWktbG9nb24uc3dpdGNo
LmNoMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArLd72HcN5+YRFvU4
Rl+xw6pq2eRFTUQ4j3TyN5q1xcWkkmpX3CAYQA86X465Jj7wc/RVryn9PZMQvv0p
XesDO4cjjp3S2w4QqtrInjFNIPXZZeamAr2QX3BHhWFnDkmCynmOiJyS4ngV7NUl
Rai3wsHjF7dEBXpJgmiMRxNUYcvr8BoAZzhO3Vu9SoM6ufoBHhup6oUQNegfmm/n
KD/3JPvqIQRKZbh+8/qxVVTIafuPVuTrVeF8Xnax7FA91XdwhmOMZPHS2E4uMRFI
R1TcY+D0jshWhoEEtBMb/SmCNxSvZm04hgcWyOwoXotaHu22PpoyKylVHkBRo6YH
t0xNgQIDAQABo20wazAdBgNVHQ4EFgQUbHSsyKFXxRa/CbTsl/rzWU2S4qMwSgYD
VR0RBEMwQYITYWFpLWxvZ29uLnN3aXRjaC5jaIYqaHR0cHM6Ly9hYWktbG9nb24u
c3dpdGNoLmNoL2lkcC9zaGliYm9sZXRoMA0GCSqGSIb3DQEBCwUAA4IBAQBT2U1g
r9O1Sd3cOOwDMrn/js5SUp7eBES1p6DBodrxgNBcL6JFX4qnE0eN9p4k/YdnbblZ
lB1/BSgz5ywnN0vdJILGmTK9qYRH3aN76fmX0mTvYK0pvBDKXhfQChcy60sb+asW
PG5ew1mG1ygfaCU4shIvUr//RaOHJOwtGKMQDXc9O+TOSOCGd+MzLXpxsq//a8ZJ
ZXwnpCEmUJoymMlOoEHAUxX7IdhrJwjtRm+b91dQpZk/jAEU/T7hfRUdhyznPaVt
bmjMq7ionfJYA34hS6c/2PXki5INUn9cPbi0GUZayF0hsspr85iPkD9u9MsrI48Z
Wk7ii+Su2RCnqP9H
						</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:AttributeService Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="https://aai-logon.switch.ch/idp/profile/SAML1/SOAP/AttributeQuery"/>
    <md:AttributeService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://aai-logon.switch.ch/idp/profile/SAML2/SOAP/AttributeQuery"/>
    <md:NameIDFormat>urn:mace:shibboleth:1.0:nameIdentifier</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
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
  <md:ContactPerson xmlns:remd="http://refeds.org/metadata" contactType="other" remd:contactType="http://refeds.org/metadata/contactType/security">
    <md:GivenName>SWITCHaai</md:GivenName>
    <md:SurName>Team</md:SurName>
    <md:EmailAddress>mailto:aai@switch.ch</md:EmailAddress>
    <md:TelephoneNumber>+41 44 268 1505</md:TelephoneNumber>
  </md:ContactPerson>
</md:EntityDescriptor>`

	attributestmt = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
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
`

	response = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
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
</samlp:Response>`

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

	wayfmdxml = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" entityID="https://wayf.wayf.dk">
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
</md:EntityDescriptor>`
)

func TestMain(m *testing.M) {
	spmetadata = goxml.NewXp(spmetadatxml)    // NewMD(mdq+"EDUGAIN", "https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth")
	idpmetadata = goxml.NewXp(idpmetadataxml) // NewMD(mdq+"EDUGAIN", "https://aai-logon.switch.ch/idp/shibboleth")
	//wayfmetadata = NewMD(mdq, "wayf-hub-public", "https://wayf.wayf.dk")
	hubmetadata = goxml.NewXp(wayfmdxml)
	//	testidpmetadata = NewMD(mdq+"HUB-OPS", "https://this.is.not.a.valid.idp")
	//	testidpviabirkmetadata = NewMD(mdq+"BIRK-OPS", "https://birk.wayf.dk/birk.php/this.is.not.a.valid.idp")
	os.Exit(m.Run())
}

func ExampleMetadata() {
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
	// <samlp:NameIDPolicy Format="urn:mace:shibboleth:1.0:nameIdentifier" AllowCreate="true"/>
	// </samlp:AuthnRequest>
}

func ExampleResponse() {
	idpmd := idpmetadata
	spmd := spmetadata

	sourceResponse := goxml.NewXp(response)
	request := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, spmd, idpmd)
	response := NewResponse(IdAndTiming{time.Time{}, 4 * time.Minute, 4 * time.Hour, "ID", "AssertionID"}, idpmd, spmd, request, sourceResponse)

	fmt.Print(response.Doc.Dump(true))
	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="ID" Version="2.0" IssueInstant="0001-01-01T00:00:00Z" InResponseTo="ID" Destination="https://attribute-viewer.aai.switch.ch/interfederation-test/Shibboleth.sso/SAML2/POST">
	//     <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://aai-logon.switch.ch/idp/shibboleth</saml:Issuer>
	//     <samlp:Status>
	//         <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
	//     </samlp:Status>
	//     <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="AssertionID" Version="2.0" IssueInstant="0001-01-01T00:00:00Z">
	//         <saml:Issuer>https://aai-logon.switch.ch/idp/shibboleth</saml:Issuer>
	//         <saml:Subject>
	//             <saml:NameID SPNameQualifier="https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_6c41e4c164d64aee825cdecc23ca67187f4741f390</saml:NameID>
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
	//                 <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
	//             </saml:AuthnContext>
	//         </saml:AuthnStatement>
	//         <saml:AttributeStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema">
	//         <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">gikcaswid@orphanage.wayf.dk</saml:AttributeValue><saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">only@thisone.example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
	//     </saml:Assertion>
	// </samlp:Response>
}

func xExampleEncryptAndDecrypt() {
	idpmd := idpmetadata
	spmd := spmetadata

	sourceResponse := goxml.NewXp(response)
	request := NewAuthnRequest(IdAndTiming{time.Time{}, 0, 0, "ID", ""}, spmd, idpmd)
	response := NewResponse(IdAndTiming{time.Time{}, 4 * time.Minute, 4 * time.Hour, "ID", "AssertionID"}, idpmd, spmd, request, sourceResponse)
	assertion := response.Query(nil, "saml:Assertion[1]")[0]

	pk := goxml.Pem2PrivateKey(privatekey, "")
	ea := goxml.NewXp(`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:EncryptedAssertion>`)
	response.Encrypt(assertion.(types.Element), &pk.PublicKey, ea)

	assertion = response.Query(nil, "//saml:EncryptedAssertion")[0]
	response.Decrypt(assertion.(types.Element), pk)
	fmt.Print(response.Doc.Dump(true))

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
