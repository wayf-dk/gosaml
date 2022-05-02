module github.com/wayf-dk/gosaml

go 1.16

require (
	github.com/wayf-dk/go-libxml2 v0.0.0-20210308214358-9c9e7b3a8e9c
	github.com/wayf-dk/goxml v0.0.0-20201218125345-b1a8c71da4f0
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2 // indirect
	x.config v0.0.0-00010101000000-000000000000
)

replace (
	github.com/wayf-dk/go-libxml2 => ../go-libxml2
	github.com/wayf-dk/goxml => ../goxml
	x.config => ../hybrid-config
)
