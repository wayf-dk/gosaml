module github.com/wayf-dk/gosaml

go 1.21

toolchain go1.21.3

require (
	github.com/wayf-dk/go-libxml2 v0.0.0-20210308214358-9c9e7b3a8e9c
	github.com/wayf-dk/goxml v0.0.0-20201218125345-b1a8c71da4f0
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	x.config v0.0.0-00010101000000-000000000000
)

require (
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/wayf-dk/goeleven v0.0.0-20210622080738-31052701ada3 // indirect
	golang.org/x/sys v0.0.0-20201119102817-f84b799fce68 // indirect
)

replace (
	github.com/wayf-dk/go-libxml2 => ../go-libxml2
	github.com/wayf-dk/goxml => ../goxml
	x.config => ../hybrid-config
)
