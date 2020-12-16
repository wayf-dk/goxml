module github.com/wayf-dk/goxml

go 1.15

require (
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/wayf-dk/go-libxml2 v0.0.0-20200913202138-5af62eb8566b
	github.com/wayf-dk/goeleven v0.0.0-20200817121619-2e6a9bee65e8
)

replace (
	github.com/wayf-dk/go-libxml2 => ../go-libxml2
	github.com/wayf-dk/goeleven => ../goeleven
)
