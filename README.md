# gosaml

Gosaml is a library for doing SAML 2.0 stuff in Go. It is a thin layer on top of libxml2 with a little crypto thrown in for signing and signature verification of SAML XML protocol messages and metadata.

It's basic datastructure is the DOM representation of all things SAML - there is no marshalling into native go structures.

It is intended for use in a integration test framework at WAYF and does not (yet) have the error handling that makes it suitable for use in actual SAML messaging. The xmldsig stuff has not yet been tested for XML signature wrapping vulnerabilities. 
