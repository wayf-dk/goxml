package goxml

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/goeleven"
	"x.config"
)

var (
	DigestMethods  = map[string]config.CryptoMethod{}
	SigningMethods = map[string]config.CryptoMethod{}
)

func init() {
	for _, method := range config.CryptoMethods {
		DigestMethods[method.DigestMethod] = method
		SigningMethods[method.SigningMethod] = method

		DigestMethods[strings.Replace(method.DigestMethod, "http://", "https://", 1)] = method
		SigningMethods[strings.Replace(method.SigningMethod, "http://", "https://", 1)] = method
	}
}

// Sign the given context with the given private key - which is a PEM or hsm: key
// A hsm: key is a urn 'key' that points to a specific key/action in a goeleven interface to a HSM
// See https://github.com/wayf-dk/
func (xp *Xp) Sign(context, before types.Node, privatekey, pw []byte, cert, algo string) (err error) {
	contextHash := Hash(config.CryptoMethods[algo].Hash, xp.C14n(context, ""))
	contextDigest := base64.StdEncoding.EncodeToString(contextHash)

	id := xp.Query1(context, "@ID | @AssertionID")

	signedInfo := xp.QueryDashP(context, `ds:Signature/ds:SignedInfo`, "", before)
	xp.QueryDashP(signedInfo, `/ds:CanonicalizationMethod/@Algorithm`, "http://www.w3.org/2001/10/xml-exc-c14n#", nil)
	xp.QueryDashP(signedInfo, `ds:SignatureMethod[1]/@Algorithm`, config.CryptoMethods[algo].SigningMethod, nil)
	xp.QueryDashP(signedInfo, `ds:Reference/@URI`, "#"+id, nil)
	xp.QueryDashP(signedInfo, `ds:Reference/ds:Transforms/ds:Transform[1][@Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"]`, "", nil)
	xp.QueryDashP(signedInfo, `ds:Reference/ds:Transforms/ds:Transform[2][@Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"]`, "", nil)
	xp.QueryDashP(signedInfo, `ds:Reference/ds:DigestMethod[1]/@Algorithm`, config.CryptoMethods[algo].DigestMethod, nil)
	xp.QueryDashP(signedInfo, `ds:Reference/ds:DigestValue[1]`, contextDigest, nil)

	signedInfoC14n := xp.C14n(signedInfo, "")
	digest := Hash(config.CryptoMethods[algo].Hash, signedInfoC14n)

	signaturevalue, err := Sign(digest, privatekey, pw, algo)
	if err != nil {
		return
	}

	signatureval := base64.StdEncoding.EncodeToString(signaturevalue)
	xp.QueryDashP(context, `ds:Signature/ds:SignatureValue`, signatureval, nil)
	xp.QueryDashP(context, `ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate`, cert, nil)
	return
}

// VerifySignature Verify a signature for the given context and public key
func (xp *Xp) VerifySignature(context types.Node, publicKeys []crypto.PublicKey) (err error) {
	signaturelist := xp.Query(context, "ds:Signature[1]")
	if len(signaturelist) != 1 {
		return fmt.Errorf("no signature found")
	}
	signature := signaturelist[0]

	signatureValue := xp.Query1(signature, "ds:SignatureValue")
	signedInfo := xp.Query(signature, "ds:SignedInfo")[0]

	signedInfoC14n := xp.C14n(signedInfo, "")
	digestValue := xp.Query1(signedInfo, "ds:Reference/ds:DigestValue")
	ID := xp.Query1(context, "@ID | @AssertionID")
	URI := xp.Query1(signedInfo, "ds:Reference/@URI")
	isvalid := "#"+ID == URI
	if !isvalid {
		return fmt.Errorf("ID mismatch")
	}

	digestMethod := xp.Query1(signedInfo, "ds:Reference/ds:DigestMethod/@Algorithm")
	nsPrefix := xp.Query1(signature, ".//ec:InclusiveNamespaces/@PrefixList")

	nextsibling, _ := signature.NextSibling()
	context.RemoveChild(signature)

	contextDigest := Hash(DigestMethods[digestMethod].Hash, xp.C14n(context, nsPrefix))

	if nextsibling != nil {
		nextsibling.AddPrevSibling(signature)
	} else {
		context.AddChild(signature)
	}

	contextDigestValueComputed := base64.StdEncoding.EncodeToString(contextDigest)

	isvalid = contextDigestValueComputed == digestValue
	if !isvalid {
		return fmt.Errorf("digest mismatch")
	}
	signatureMethod := xp.Query1(signedInfo, "ds:SignatureMethod/@Algorithm")

	signedInfoDigest := Hash(SigningMethods[signatureMethod].Hash, signedInfoC14n)

	//    log.Printf("SigAlg: %s %s %s %s\n", xp.QueryString(context, "local-name(.)"), xp.Query1(context, "saml:Issuer"), digestMethod, signatureMethod)

	ds, _ := base64.StdEncoding.DecodeString(signatureValue)

	for _, pub := range publicKeys {
		err = Verify(pub, SigningMethods[signatureMethod].Hash, signedInfoDigest[:], ds)
		if err == nil {
			return
		}
	}

	return
}

func Verify(pub crypto.PublicKey, algo crypto.Hash, digest, signature []byte) (err error) {
	switch pk := pub.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pk, algo, digest, signature)
	case ed25519.PublicKey:
		if !ed25519.Verify(pk, digest, signature) {
			err = errors.New("verifying ed25519 signature failed")
		}
	default:
		err = errors.New("unknown public key type")
	}
	return
}

// Sign the digest with the privvate key and algo
func Sign(digest, privatekey, pw []byte, algo string) (signaturevalue []byte, err error) {
	signFuncs := map[bool]func([]byte, []byte, []byte, string) ([]byte, error){true: signGoEleven, false: signGo}
	signaturevalue, err = signFuncs[bytes.HasPrefix(privatekey, []byte("hsm:"))](digest, privatekey, pw, algo)
	return
}

func signGo(digest, privatekey, pw []byte, algo string) (signaturevalue []byte, err error) {
	var priv interface{}
	if priv, err = Pem2PrivateKey(privatekey, pw); err != nil {
		return
	}
	switch pk := priv.(type) {
	case *rsa.PrivateKey:
		signaturevalue, err = rsa.SignPKCS1v15(rand.Reader, pk, config.CryptoMethods[algo].Hash, digest)
	case ed25519.PrivateKey:
		signaturevalue, err = pk.Sign(rand.Reader, digest, crypto.Hash(0))
	default:
		fmt.Println("unknown")
	}
	return
}

func signGoEleven(digest, privatekey, pw []byte, algo string) ([]byte, error) {
	data := append([]byte(config.CryptoMethods[algo].DerPrefix), digest...)
	return callHSM("sign", data, string(privatekey), "CKM_RSA_PKCS", "")
}

// Encrypt the context with the given publickey
// Hardcoded to aes256-cbc for the symetric part and
// rsa-oaep-mgf1p and sha1 for the rsa part
func (xp *Xp) Encrypt(context types.Node, publickey *rsa.PublicKey) (err error) {
	ects := xp.QueryDashP(nil, "saml:EncryptedAssertion/xenc:EncryptedData/@Type", "http://www.w3.org/2001/04/xmlenc#Element", context)
	xp.QueryDashP(ects, `xenc:EncryptionMethod[@Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"]`, "", nil)
	xp.QueryDashP(ects, `ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"]/ds:DigestMethod[@Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"]`, "", nil)

	sessionkey, ciphertext, err := encryptAESGCM([]byte(context.ToString(1, true)))
	if err != nil {
		return
	}
	encryptedSessionkey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, publickey, sessionkey, nil)
	if err != nil {
		return
	}

	xp.QueryDashP(ects, `ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue`, base64.StdEncoding.EncodeToString(encryptedSessionkey), nil)
	xp.QueryDashP(ects, `xenc:CipherData/xenc:CipherValue`, base64.StdEncoding.EncodeToString(ciphertext), nil)
	RmElement(context)
	return
}

// Decrypt decrypts the context using the given privatekey .
// The context element is removed
func (xp *Xp) Decrypt(encryptedAssertion types.Node, privatekey, pw []byte) (err error) {
	context := xp.Query(encryptedAssertion, "xenc:EncryptedData")[0]
	encryptionMethod := xp.Query1(context, "./xenc:EncryptionMethod/@Algorithm")
	keyEncryptionMethod := xp.Query1(context, "./ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm")
	digestMethod := xp.Query1(context, "./ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/ds:DigestMethod/@Algorithm")
	OAEPparams := xp.Query1(context, "./ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/xenc:OAEPparams")
	MGF := xp.Query1(context, "./ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/xenc11:MGF/@Algorithm")
	encryptedKey := xp.Query1(context, "./ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue")

	decrypt := decryptGCM
	digestAlgorithm := crypto.SHA1
	mgfAlgorithm := crypto.SHA1

	switch keyEncryptionMethod {
	case "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p":
		mgfAlgorithm = crypto.SHA1
	case "http://www.w3.org/2009/xmlenc11#rsa-oaep":
		switch MGF {
		case "http://www.w3.org/2009/xmlenc11#mgf1sha1":
			mgfAlgorithm = crypto.SHA1
		case "http://www.w3.org/2009/xmlenc11#mgf1sha256":
			mgfAlgorithm = crypto.SHA256
		default:
			return NewWerror("unsupported MGF", "MGF: "+MGF)
		}
	default:
		return NewWerror("unsupported keyEncryptionMethod", "keyEncryptionMethod: "+keyEncryptionMethod)
	}

	switch digestMethod {
	case "http://www.w3.org/2000/09/xmldsig#sha1":
		digestAlgorithm = crypto.SHA1
	case "http://www.w3.org/2001/04/xmlenc#sha256":
		digestAlgorithm = crypto.SHA256
	case "http://www.w3.org/2001/04/xmldsig-more#sha384":
		digestAlgorithm = crypto.SHA384
	case "http://www.w3.org/2001/04/xmlenc#sha512":
		digestAlgorithm = crypto.SHA512
	case "":
		digestAlgorithm = crypto.SHA1
	default:
		return NewWerror("unsupported digestMethod", "digestMethod: "+digestMethod)
	}

	switch encryptionMethod {
	case "http://www.w3.org/2001/04/xmlenc#aes128-cbc", "http://www.w3.org/2009/xmlenc11#aes192-cbc", "http://www.w3.org/2001/04/xmlenc#aes256-cbc":
		decrypt = decryptCBC
	case "http://www.w3.org/2009/xmlenc11#aes128-gcm", "http://www.w3.org/2009/xmlenc11#aes192-gcm", "http://www.w3.org/2009/xmlenc11#aes256-gcm":
		decrypt = decryptGCM
	default:
		return NewWerror("unsupported encryptionMethod", "encryptionMethod: "+encryptionMethod)
	}

	encryptedKeybyte, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encryptedKey))
	if err != nil {
		return Wrap(err)
	}

	OAEPparamsbyte, err := base64.StdEncoding.DecodeString(strings.TrimSpace(OAEPparams))
	if err != nil {
		return Wrap(err)
	}

	if digestAlgorithm != mgfAlgorithm {
		return errors.New("digestMethod != keyEncryptionMethod not supported")
	}

	var sessionkey []byte
	switch bytes.HasPrefix(privatekey, []byte("hsm:")) {
	case true:
		sessionkey, err = callHSM("decrypt", encryptedKeybyte, string(privatekey), "CKM_RSA_PKCS_OAEP", "CKM_SHA_1")
	case false:
		priv, err := Pem2PrivateKey(privatekey, pw)
		if err != nil {
			return Wrap(err)
		}
		sessionkey, err = rsa.DecryptOAEP(digestAlgorithm.New(), rand.Reader, priv.(*rsa.PrivateKey), encryptedKeybyte, OAEPparamsbyte)
		if err != nil {
			return Wrap(err)
		}
	}

	if err != nil {
		return Wrap(err)
	}

	switch len(sessionkey) {
	case 16, 24, 32:
	default:
		return fmt.Errorf("Unsupported keylength for AES %d", len(sessionkey))
	}

	ciphertext := xp.Query1(context, "./xenc:CipherData/xenc:CipherValue")
	ciphertextbyte, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ciphertext))
	if err != nil {
		return Wrap(err)
	}

	plaintext, err := decrypt([]byte(sessionkey), ciphertextbyte)
	if err != nil {
		return WrapWithXp(err, xp)
	}

	response, err := encryptedAssertion.ParentNode()
	if err != nil {
		return WrapWithXp(err, xp)
	}
	decryptedAssertionElement, err := response.ParseInContext(string(plaintext), 0)
	if err != nil {
		return WrapWithXp(err, xp)
	}

	_ = encryptedAssertion.AddPrevSibling(decryptedAssertionElement)
	RmElement(encryptedAssertion)

	return err
}

// Pem2PrivateKey converts a PEM encoded private key with an optional password to a *rsa.PrivateKey
func Pem2PrivateKey(privatekeypem, pw []byte) (pk interface{}, err error) {
	block, _ := pem.Decode(privatekeypem) // not used rest
	derbytes := block.Bytes
	if string(pw) != "-" {
		if derbytes, err = x509.DecryptPEMBlock(block, pw); err != nil {
			return nil, Wrap(err)
		}
	}
	if pk, err = x509.ParsePKCS1PrivateKey(derbytes); err != nil {
		if pk, err = x509.ParsePKCS8PrivateKey(derbytes); err != nil {
			return nil, Wrap(err)
		}
	}
	return
}

// encryptAESCBC encrypts the plaintext with a generated random key and returns both the key and the ciphertext using CBC
func encryptAESCBC(plaintext []byte) (key, ciphertext []byte, err error) {
	key = make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, key); err != nil {
		return
	}
	paddinglen := aes.BlockSize - len(plaintext)%aes.BlockSize

	plaintext = append(plaintext, bytes.Repeat([]byte{byte(paddinglen)}, paddinglen)...)
	ciphertext = make([]byte, aes.BlockSize+len(plaintext))

	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	return
}

// encryptAESGCM encrypts the plaintext with a generated random key and returns both the key and the ciphertext using GCM
func encryptAESGCM(plaintext []byte) (key, ciphertext []byte, err error) {
	key = make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, key); err != nil {
		return
	}

	iv := make([]byte, 12)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext = append(iv, aesgcm.Seal(nil, iv, plaintext, nil)...)
	return
}

// decryptGCM decrypts the ciphertext using the supplied key
func decryptGCM(key, ciphertext []byte) (plaintext []byte, err error) {
	if len(ciphertext) < 40 { // we want at least 12 bytes of actual data in addition to 12 bytes Initialization Vector and 16 bytes Authentication Tag
		return nil, errors.New("Not enough data to decrypt for AES-GCM")
	}

	iv := ciphertext[:12]
	ciphertext = ciphertext[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	plaintext, err = aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return
	}
	return
}

// decryptCBC decrypts the ciphertext using the supplied key
func decryptCBC(key, ciphertext []byte) (plaintext []byte, err error) {
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	paddinglen := int(ciphertext[len(ciphertext)-1])
	if paddinglen > aes.BlockSize || paddinglen == 0 {
		return nil, errors.New("decrypted plaintext is not padded correctly")
	}
	// remove padding
	plaintext = ciphertext[:len(ciphertext)-int(paddinglen)]
	return
}

func callHSM(function string, data []byte, privatekey, mech, digest string) (res []byte, err error) {
	type request struct {
		Data      string `json:"data"`
		Mech      string `json:"mech"`
		Digest    string `json:"digest"`
		Function  string `json:"function"`
		Sharedkey string `json:"sharedkey"`
	}

	/*	var response struct {
			Signed []byte `json:"signed"`
		}
	*/
	parts := strings.SplitN(strings.TrimSpace(privatekey), ":", 3)

	//	payload := request{
	payload := goeleven.Request{
		Data:      base64.StdEncoding.EncodeToString(data),
		Mech:      mech,
		Digest:    digest,
		Function:  function,
		Sharedkey: parts[1],
	}

	return goeleven.Dispatch(parts[2], payload)
	/*
		jsontxt, err := json.Marshal(payload)
		if err != nil {
			return nil, Wrap(err)
		}

		resp, err := http.Post(parts[2], "application/json", bytes.NewBuffer(jsontxt))
		if err != nil {
			return
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)

		err = json.Unmarshal(body, &response)
		if err != nil {
			return nil, Wrap(err)
		}
		return response.Signed, err
	*/
}

// Hash Perform a digest calculation using the given crypto.Hash
func Hash(h crypto.Hash, data string) []byte {
	digest := h.New()
	io.WriteString(digest, data)
	return digest.Sum(nil)
}

func (xp *Xp) DomSha1SumToBase64() string {
	hash := sha1.Sum([]byte(xp.C14n(nil, "")))
	return base64.StdEncoding.EncodeToString(append(hash[:]))
}

// PP - super simple Pretty Print - using JSON
func PP(i ...interface{}) {
	for _, e := range i {
		s, _ := json.MarshalIndent(e, "", "    ")
		config.Logger.Println(string(s))
	}
	return
}
