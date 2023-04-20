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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/goeleven"
	"x.config"
)

type (
	keyEncParams struct {
		digest, alg string
	}

	encParams struct {
		keySize   int
		mode, enc string
	}

	encryptionResult struct {
		EncryptedSessionkey, Iv, CipherText, AuthTag, OAEPparams   []byte
		EncryptionMethod, KeyEncryptionMethod, DigestMethod, Label string
		Alg, Enc                                                   string
	}
	HSMKey []byte
)

var (
	DigestMethods  = map[string]config.CryptoMethod{}
	SigningMethods = map[string]config.CryptoMethod{}

	KeyEncryptionMethods = map[string]keyEncParams{ //
		"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p": {"http://www.w3.org/2000/09/xmldsig#sha1", "RSA-OAEP"},
		"http://www.w3.org/2009/xmlenc11#rsa-oaep":        {"http://www.w3.org/2001/04/xmlenc#sha256", "RSA-OAEP-256"},
	}

	EncryptionMethods = map[string]encParams{
		"http://www.w3.org/2001/04/xmlenc#aes128-cbc": {128, "cbc", "A128CBC-HS256"},
		"http://www.w3.org/2001/04/xmlenc#aes192-cbc": {192, "cbc", "A192CBC-HS384"},
		"http://www.w3.org/2001/04/xmlenc#aes256-cbc": {256, "cbc", "A256CBC-HS512"},
		"http://www.w3.org/2009/xmlenc11#aes128-gcm":  {128, "gcm", "A128GCM"},
		"http://www.w3.org/2009/xmlenc11#aes192-gcm":  {192, "gcm", "A192GCM"},
		"http://www.w3.org/2009/xmlenc11#aes256-gcm":  {256, "gcm", "A256GCM"},
	}
)

func init() {
	for _, method := range config.CryptoMethods {
		DigestMethods[method.DigestMethod] = method
		SigningMethods[method.SigningMethod] = method
	}
}

// Sign the given context with the given private key - which is a PEM or hsm: key
// A hsm: key is a urn 'key' that points to a specific key/action in a goeleven interface to a HSM
// See https://github.com/wayf-dk/
func (xp *Xp) Sign(context, before types.Node, privatekey crypto.PrivateKey, cert, algo string) (err error) {
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

	signaturevalue, err := Sign(digest, privatekey, algo)
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
	signaturelist := xp.Query(context, "ds:Signature")
	if len(signaturelist) != 1 {
		return fmt.Errorf("no of signatures found != 1")
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

	dgm, ok := DigestMethods[digestMethod]
	if !ok {
		return fmt.Errorf("Unknown digestMethod")
	}

	nextsibling, _ := signature.NextSibling()
	context.RemoveChild(signature)

	contextDigest := Hash(dgm.Hash, xp.C14n(context, nsPrefix))

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

// Sign the digest with the privvate key and algo
func Sign(digest []byte, privatekey crypto.PrivateKey, algo string) (signaturevalue []byte, err error) {
    switch pk := privatekey.(type) {
    case *rsa.PrivateKey:
		signaturevalue, err = rsa.SignPKCS1v15(rand.Reader, pk, config.CryptoMethods[algo].Hash, digest)
	case ed25519.PrivateKey:
		signaturevalue, err = pk.Sign(rand.Reader, digest, crypto.Hash(0))
    case HSMKey:
        signaturevalue, err = signGoEleven(digest, pk, algo)
    default:
    	err = fmt.Errorf("Unsupported keytype %T", pk)
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

func signGoEleven(digest []byte, privatekey crypto.PrivateKey, algo string) ([]byte, error) {
	data := append([]byte(config.CryptoMethods[algo].DerPrefix), digest...)
	pk, _ := privatekey.(HSMKey)
	return callHSM("sign", data, pk, "CKM_RSA_PKCS", "")
}

func Jwe(cleartext []byte, publickey *rsa.PublicKey, encryptionAlgorithms []string) (jwe string, err error) {
	enc, err := BaseEncrypt(cleartext, publickey, encryptionAlgorithms, true)
	if err != nil {
		return
	}
	jwe = enc.Label + "." +
		base64.RawURLEncoding.EncodeToString(enc.EncryptedSessionkey) + "." +
		base64.RawURLEncoding.EncodeToString(enc.Iv) + "." +
		base64.RawURLEncoding.EncodeToString(enc.CipherText) + "." +
		base64.RawURLEncoding.EncodeToString(enc.AuthTag)

	return
}

func DeJwe(jwe string, privatekey crypto.PrivateKey) (jwt string, err error) {
	partsb64 := strings.Split(jwe, ".")
	if len(partsb64) == 3 { // jwt - we just accept it and continues
		return jwe, nil
	}
	enc := &encryptionResult{}
	parts := [5][]byte{}
	for i, partb64 := range partsb64 {
		parts[i], err = base64.RawURLEncoding.DecodeString(partb64)
		if err != nil {
			return
		}
	}
	var header map[string]string
	err = json.Unmarshal(parts[0], &header)
	if err != nil {
		return "", Wrap(err)
	}

	for kem, i := range KeyEncryptionMethods {
		if header["alg"] == i.alg {
			enc.KeyEncryptionMethod = kem
			enc.DigestMethod = i.digest
		}
	}

	for em, i := range EncryptionMethods {
		if header["enc"] == i.enc {
			enc.EncryptionMethod = em
		}
	}
	enc.Label = partsb64[0]
	enc.EncryptedSessionkey = parts[1]
	enc.Iv = parts[2]
	enc.CipherText = parts[3]
	enc.AuthTag = parts[4]

	jwtbyte, err := baseDecrypt(enc, privatekey)
	if err != nil {
		return
	}

	jwt = string(jwtbyte)

	return
}

func BaseEncrypt(cleartext []byte, publickey *rsa.PublicKey, encryptionAlgorithms []string, jwe bool) (enc *encryptionResult, err error) {
	enc = &encryptionResult{}

	// Append the defaults so we are sure we will find one ...
	algoDefaults := config.EncryptionAlgorithmsDefaults

	encryptionAlgorithms = append(encryptionAlgorithms, algoDefaults...)
	var encP encParams
	var keyEncP keyEncParams
	var ok bool

	for _, enc.KeyEncryptionMethod = range encryptionAlgorithms {
		if keyEncP, ok = KeyEncryptionMethods[enc.KeyEncryptionMethod]; ok {
			break
		}
	}

	if !ok {
		return nil, NewWerror("KeyEncryptionMethod not found: ", enc.KeyEncryptionMethod)
	}

	enc.DigestMethod = keyEncP.digest
	enc.Alg = keyEncP.alg

	for _, enc.EncryptionMethod = range encryptionAlgorithms {
		if encP, ok = EncryptionMethods[enc.EncryptionMethod]; ok {
			break
		}
	}

	if !ok {
		return nil, NewWerror("EnctyptionMethod not found: ", enc.EncryptionMethod)
	}

	enc.Enc = encP.enc

	var sessionkey []byte
	if jwe {
		headerMap := map[string]string{"alg": enc.Alg, "enc": enc.Enc, "kid": "wayf", "cty": "JWT"}
		headerJson, err := json.Marshal(headerMap)
		if err != nil {
			return nil, err
		}

		enc.Label = base64.RawURLEncoding.EncodeToString(headerJson)
	}

	encrypt := encryptAESGCM
	switch encP.mode {
	case "gcm":
		encrypt = encryptAESGCM
	case "cbc":
		encrypt = encryptAESCBC
	}

	sessionkey, enc.CipherText, enc.Iv, enc.AuthTag, err = encrypt(cleartext, []byte(enc.Label), encP.keySize)
	if err != nil {
		return
	}

	hash := config.CryptoMethods[enc.DigestMethod].Hash
	enc.EncryptedSessionkey, err = rsa.EncryptOAEP(hash.New(), rand.Reader, publickey, sessionkey, nil)
	if err != nil {
		return
	}
	return
}

func baseDecrypt(enc *encryptionResult, privatekey crypto.PrivateKey) (cleartext []byte, err error) {
	decrypt := decryptGCM
	digestAlgorithm := crypto.SHA256
	hsmDigestAlgorithm := "CKM_SHA_1"

	switch enc.DigestMethod {
	case "http://www.w3.org/2000/09/xmldsig#sha1":
		digestAlgorithm = crypto.SHA1
	case "http://www.w3.org/2001/04/xmlenc#sha256":
		digestAlgorithm = crypto.SHA256
		hsmDigestAlgorithm = "CKM_SHA256"
	default:
		return nil, NewWerror("unsupported digestMethod", "digestMethod: "+enc.DigestMethod)
	}

	switch enc.EncryptionMethod {
	case "http://www.w3.org/2001/04/xmlenc#aes128-cbc", "http://www.w3.org/2001/04/xmlenc#aes192-cbc", "http://www.w3.org/2001/04/xmlenc#aes256-cbc":
		decrypt = decryptCBC
	case "http://www.w3.org/2009/xmlenc11#aes128-gcm", "http://www.w3.org/2009/xmlenc11#aes192-gcm", "http://www.w3.org/2009/xmlenc11#aes256-gcm":
		decrypt = decryptGCM
	default:
		return nil, NewWerror("unsupported encryptionMethod", "encryptionMethod: "+enc.EncryptionMethod)
	}

	var sessionkey []byte
	switch pk := privatekey.(type) {
	case *rsa.PrivateKey:
		sessionkey, err = rsa.DecryptOAEP(digestAlgorithm.New(), rand.Reader, pk, enc.EncryptedSessionkey, enc.OAEPparams)
		if err != nil {
			return nil, Wrap(err)
		}
	case HSMKey:
		sessionkey, err = callHSM("decrypt", enc.EncryptedSessionkey, pk, "CKM_RSA_PKCS_OAEP", hsmDigestAlgorithm)
	default:
		return nil, fmt.Errorf("Unsupported privatekeytype: %t", pk)
	}

	if err != nil {
		return nil, Wrap(err)
	}

	switch len(sessionkey) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("Unsupported keylength for AES %d", len(sessionkey))
	}

	cipherText := append(enc.Iv, enc.CipherText...)
	cipherText = append(cipherText, enc.AuthTag...)
	cleartext, err = decrypt([]byte(sessionkey), cipherText, []byte(enc.Label))
	if err != nil {
		return nil, Wrap(err)
	}
	return
}

// Encrypt the context with the given publickey
func (xp *Xp) Encrypt(context types.Node, elementName string, publickey *rsa.PublicKey, encryptionAlgorithms []string) (err error) {
	cleartext := []byte(context.ToString(1, true))
	enc, err := BaseEncrypt(cleartext, publickey, encryptionAlgorithms, false)
	if err != nil {
		return
	}

	ects := xp.QueryDashP(nil, elementName+"/xenc:EncryptedData/@Type", "http://www.w3.org/2001/04/xmlenc#Element", nil)
	xp.QueryDashP(ects, `xenc:EncryptionMethod/@Algorithm`, enc.EncryptionMethod, nil)
	ecm := xp.QueryDashP(ects, `ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm`, enc.KeyEncryptionMethod, nil)
	xp.QueryDashP(ecm, `ds:DigestMethod/@Algorithm`, enc.DigestMethod, nil)

	if enc.DigestMethod == "http://www.w3.org/2001/04/xmlenc#sha256" {
		xp.QueryDashP(ecm, `xenc11:MGF[@Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"]`, "", nil)
	}

	xp.QueryDashP(ects, `ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue`, base64.StdEncoding.EncodeToString(enc.EncryptedSessionkey), nil)
	xp.QueryDashP(ects, `xenc:CipherData/xenc:CipherValue`, base64.StdEncoding.EncodeToString(append(append(enc.Iv, enc.CipherText...), enc.AuthTag...)), nil)
	RmElement(context)
	return
}

// Decrypt decrypts the context using the given privatekey .
// The context element is removed
func (xp *Xp) Decrypt(encryptedAssertion types.Node, privatekey crypto.PrivateKey) (err error) {
	context := xp.Query(encryptedAssertion, "xenc:EncryptedData")[0]
	mgfAlgorithm := xp.Query1(context, "./ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/xenc11:MGF/@Algorithm")
	digestMethod := xp.Query1(context, "./ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/ds:DigestMethod/@Algorithm")

	mgfAlgorithms := map[string]string{
		"": "http://www.w3.org/2000/09/xmldsig#sha1",
		"http://www.w3.org/2009/xmlenc11#mgf1sha1":   "http://www.w3.org/2000/09/xmldsig#sha1",
		"http://www.w3.org/2009/xmlenc11#mgf1sha256": "http://www.w3.org/2001/04/xmlenc#sha256",
	}

	if digestMethod != mgfAlgorithms[mgfAlgorithm] {
		return errors.New("digestMethod != keyEncryptionMethod not supported")
	}

	encryptedSessionkey, _ := base64.StdEncoding.DecodeString(xp.Query1(context, "./ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue"))
	oaepParams, _ := base64.StdEncoding.DecodeString(xp.Query1(context, "./ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/xenc:OAEPparams"))
	cipherText, _ := base64.StdEncoding.DecodeString(xp.Query1(context, "./xenc:CipherData/xenc:CipherValue"))

	enc := &encryptionResult{
		KeyEncryptionMethod: xp.Query1(context, "./ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm"),
		EncryptionMethod:    xp.Query1(context, "./xenc:EncryptionMethod/@Algorithm"),
		CipherText:          cipherText,
		DigestMethod:        digestMethod,
		OAEPparams:          oaepParams,
		EncryptedSessionkey: encryptedSessionkey,
	}

	cleartext, err := baseDecrypt(enc, privatekey)
	if err != nil {
		return
	}
	response, err := encryptedAssertion.ParentNode()
	if err != nil {
		return WrapWithXp(err, xp)
	}
	decryptedAssertionElement, err := response.ParseInContext(string(cleartext), 0)
	if err != nil {
		return WrapWithXp(err, xp)
	}

	_ = encryptedAssertion.AddPrevSibling(decryptedAssertionElement)
	RmElement(encryptedAssertion)

	return err
}

// encryptAESCBC encrypts the plaintext with a generated random key and returns both the key and the ciphertext using CBC
func encryptAESCBC(plaintext, label []byte, keySize int) (key, cipherText, iv, authTag []byte, err error) {
	key = make([]byte, keySize/8)
	if _, err = io.ReadFull(rand.Reader, key); err != nil {
		return
	}
	paddinglen := aes.BlockSize - len(plaintext)%aes.BlockSize

	plaintext = append(plaintext, bytes.Repeat([]byte{byte(paddinglen)}, paddinglen)...)
	cipherText = make([]byte, len(plaintext))

	iv = make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, plaintext)
	return
}

// encryptAESGCM encrypts the plaintext with a generated random key and returns both the key and the ciphertext using GCM
func encryptAESGCM(plaintext, label []byte, keySize int) (key, cipherText, iv, authTag []byte, err error) {
	key = make([]byte, keySize/8)
	if _, err = io.ReadFull(rand.Reader, key); err != nil {
		return
	}

	iv = make([]byte, 12)
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

	cipherWithTag := aesgcm.Seal(nil, iv, plaintext, label)

	split := len(cipherWithTag) - aesgcm.Overhead()
	cipherText = cipherWithTag[:split]
	authTag = cipherWithTag[split:]
	return
}

// decryptGCM decrypts the ciphertext using the supplied key
func decryptGCM(key, ciphertext, label []byte) (plaintext []byte, err error) {
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

	plaintext, err = aesgcm.Open(nil, iv, ciphertext, label)
	if err != nil {
		return
	}
	return
}

// decryptCBC decrypts the ciphertext using the supplied key
func decryptCBC(key, ciphertext, label []byte) (plaintext []byte, err error) {
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

func callHSM(function string, data []byte, privatekey HSMKey, mech, digest string) (res []byte, err error) {
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
	parts := strings.SplitN(strings.TrimSpace(string(privatekey)), ":", 3)

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
