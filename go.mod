module goxml

go 1.16

require (
	github.com/wayf-dk/go-libxml2 v0.0.0-20210308214358-9c9e7b3a8e9c
	github.com/wayf-dk/goeleven v0.0.0-20210622080738-31052701ada3
	x.config v0.0.0-00010101000000-000000000000
)

replace (
	github.com/wayf-dk/go-libxml2 => ../go-libxml2
	github.com/wayf-dk/goeleven => ../goeleven
	x.config => ../hybrid-config
)
