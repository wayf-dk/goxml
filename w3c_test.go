package goxml

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/wayf-dk/go-libxml2/types"
	"io/ioutil"
	"strings"
)

func ExampleDecrypt() {

	tests := []string{
		"cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p.xml",
		"cipherText__RSA-3072__aes192-gcm__rsa-oaep-mgf1p__Sha256.xml",
		"cipherText__RSA-3072__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1.xml",
		"cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource.xml",
	}

	for _, test := range tests {
		cipherText, _ := ioutil.ReadFile("testdata/w3c/" + test)
		parts := strings.Split(test, "__")
		//       	keyType := strings.Split(parts[1], "-")[0]
		pemFile := "testdata/w3c/" + parts[1] + ".pem" // +"_SHA256With"+ keyType + ".p12"
		pemBlock, _ := ioutil.ReadFile(pemFile)
		block, _ := pem.Decode(pemBlock)
		pKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
		xp := NewXp(string(cipherText))
		doc, _ := xp.Doc.DocumentElement()
		xp.Decrypt(doc.(types.Element), pKey)
		fmt.Println(xp.PP())
	}
	// Output:
	// xxx
}
