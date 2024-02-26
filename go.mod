module github.com/wayf-dk/goxml

go 1.22.0

require (
	github.com/wayf-dk/go-libxml2 v0.0.0-20231207144727-d602dab8cded
	github.com/wayf-dk/goeleven v0.0.0-20230816115740-d287bc08e939
	x.config v0.0.0-00010101000000-000000000000
)

require (
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2 // indirect
	golang.org/x/sys v0.0.0-20201119102817-f84b799fce68 // indirect
)

replace (
	github.com/wayf-dk/go-libxml2 => ../go-libxml2
	github.com/wayf-dk/goeleven => ../goeleven
	x.config => ../hybrid-config
)
