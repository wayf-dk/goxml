module github.com/wayf-dk/goxml

go 1.16

require (
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.7.0 // indirect
	github.com/wayf-dk/go-libxml2 v0.0.0-20200913202138-5af62eb8566b
	github.com/wayf-dk/goeleven@Dev2021
	gopkg.in/xmlpath.v1 v1.0.0-20140413065638-a146725ea6e7 // indirect
)

replace (
	github.com/wayf-dk/go-libxml2 => ../go-libxml2
	github.com/wayf-dk/goeleven => ../goeleven
)
