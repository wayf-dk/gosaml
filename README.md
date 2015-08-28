# gosaml

Gosaml is a library for doing SAML 2.0 stuff in Go. It is a thin layer on top of libxml2 with a little crypto thrown in for signing and signature verification of SAML XML protocol messages and metadata.

It's basic datastructure is the DOM representation of all things SAML - there is no marshalling into native go structures.