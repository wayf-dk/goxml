[![Go Report Card](https://goreportcard.com/badge/github.com/wayf-dk/goxml)](https://goreportcard.com/report/github.com/wayf-dk/goxml)

# goxml

XPath/DOM interface to lestrrat/go-libxml

## File structure overview

- goxml.go: Main library file (initialization)
- xp.go: Core Xp (XPath) functionality
- crypt.go: Cryptography related functionality
- namespaces.go: Namespace prefix -> uri lookup table
- nodeutils.go: Utilities for manipulating and traversing XML nodes
- werror.go: Enriched error wrapper functionality
