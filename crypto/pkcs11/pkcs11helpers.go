/*
   Copyright The ocicrypt Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package pkcs11

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
	pkcs11uri "github.com/stefanberger/go-pkcs11uri"
	"gopkg.in/yaml.v2"
)

var (
	// OAEPLabel defines the label we use for OAEP encryption; this cannot be changed
	OAEPLabel = []byte("")
	// OAEPDefaultHash defines the default hash used for OAEP encryption; this cannot be changed
	OAEPDefaultHash = "sha256"

	// OAEPSha1Params describes the OAEP parameters with sha1 hash algorithm; needed by SoftHSM
	OAEPSha1Params = &pkcs11.OAEPParams{
		HashAlg:    pkcs11.CKM_SHA_1,
		MGF:        pkcs11.CKG_MGF1_SHA1,
		SourceType: pkcs11.CKZ_DATA_SPECIFIED,
		SourceData: OAEPLabel,
	}
	// OAEPSha256Params describes the OAEP parameters with sha256 hash algorithm
	OAEPSha256Params = &pkcs11.OAEPParams{
		HashAlg:    pkcs11.CKM_SHA256,
		MGF:        pkcs11.CKG_MGF1_SHA256,
		SourceType: pkcs11.CKZ_DATA_SPECIFIED,
		SourceData: OAEPLabel,
	}
	// OEPParams is an array Of OAEP parameters in order we will try to use them
	OAEPParams = []*pkcs11.OAEPParams{OAEPSha256Params, OAEPSha1Params}
)

// Pkcs11KeyFile describes the format of the pkcs11 (private) key file
type Pkcs11KeyFile struct {
	Pkcs11 struct {
		Uri string `yaml:"uri"`
	} `yaml:"pkcs11"`
}

// Pkcs11KeyFileObject is a representation of the Pkcs11KeyFile with the pkcs11 URI as an object
type Pkcs11KeyFileObject struct {
	Uri *pkcs11uri.Pkcs11URI
}

// ParsePkcs11KeyFile parses a pkcs11 key file holding a pkcs11 URI describing a private key.
// The file has the following yaml format:
// pkcs11:
//  - uri : <pkcs11 uri>
// An error is returned if the pkcs11 URI is malformed
func ParsePkcs11KeyFile(yamlstr []byte) (*Pkcs11KeyFileObject, error) {
	p11keyfile := Pkcs11KeyFile{}

	err := yaml.Unmarshal([]byte(yamlstr), &p11keyfile)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not unmarshal pkcs11 keyfile")
	}

	p11uri, err := pkcs11uri.New()
	if err != nil {
		return nil, errors.Wrapf(err, "Could not create Pkcs11URI object")
	}
	err = p11uri.Parse(p11keyfile.Pkcs11.Uri)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not parse Pkcs11URI from file")
	}

	return &Pkcs11KeyFileObject{Uri: &p11uri}, err
}

// Pkcs11Config describes the layout of a pkcs11 config file
// The file has the following yaml format:
// module-directories:
// - /usr/lib64/pkcs11/
// allowd-module-paths
// - /usr/lib64/pkcs11/libsofthsm2.so
type Pkcs11Config struct {
	ModuleDirectories  []string `yaml:"module-directories"`
	AllowedModulePaths []string `yaml:"allowed-module-paths"`
}

// ParsePkcs11ConfigFile parses a pkcs11 config file hat influences the module search behavior
// as well as the set of modules that users are allowed to use
func ParsePkcs11ConfigFile(yamlstr []byte) (Pkcs11Config, error) {
	p11conf := Pkcs11Config{}

	err := yaml.Unmarshal([]byte(yamlstr), &p11conf)
	if err != nil {
		return p11conf, errors.Wrapf(err, "Could not parse Pkcs11Config")
	}
	return p11conf, nil
}

// rsaPublicEncryptOAEP encrypts the given plaintext with the given *rsa.PublicKey; the
// environment variable OCICRYPT_OAEP_HASHALG can be set to 'sha1' to force usage of sha1 for OAEP (SoftHSM).
// This function is needed by clients who are using a public key file for pkcs11 encryption
func rsaPublicEncryptOAEP(pubKey *rsa.PublicKey, plaintext []byte) ([]byte, string, error) {
	var hashfunc hash.Hash
	hashalg := OAEPDefaultHash

	// for SoftHSM support we allow the user to choose sha1 as the hash algorithm
	switch strings.ToLower(os.Getenv("OCICRYPT_OAEP_HASHALG")) {
	case "sha1":
		hashfunc = sha1.New()
		hashalg = "sha1"
	default:
		hashfunc = sha256.New()
	}
	ciphertext, err := rsa.EncryptOAEP(hashfunc, rand.Reader, pubKey, plaintext, OAEPLabel)
	if err != nil {
		return nil, "", errors.Wrapf(err, "rss.EncryptOAEP failed")
	}

	return ciphertext, hashalg, nil
}

// pkcs11UriGetLoginParameters gets the parameters necessary for login from the Pkcs11URI
// PIN and module are mandatory; slot-id is optional and if not found -1 will be returned
func pkcs11UriGetLoginParameters(p11uri *pkcs11uri.Pkcs11URI) (string, string, int64, error) {
	pin, err := p11uri.GetPIN()
	if err != nil {
		return "", "", 0, errors.Wrap(err, "No PIN available in pkcs11 URI")
	}

	module, err := p11uri.GetModule()
	if err != nil {
		return "", "", 0, errors.Wrap(err, "No module available in pkcs11 URI")
	}

	slotid := int64(-1)

	slot, ok := p11uri.GetPathAttribute("slot-id", false)
	if ok {
		slotid, err = strconv.ParseInt(slot, 10, 64)
		if err != nil {
			return "", "", 0, errors.Wrap(err, "slot-id is not a valid number")
		}
		if slotid < 0 {
			return "", "", 0, fmt.Errorf("slot-id is a negative number")
		}
		if uint64(slotid) > 0xffffffff {
			return "", "", 0, fmt.Errorf("slot-id is larger than 32 bit")
		}
	}

	return pin, module, slotid, nil
}

// pkcs11UriGetKeyLabel gets the key label by retrieving the value of the 'object' attribute
func pkcs11UriGetKeyLabel(p11uri *pkcs11uri.Pkcs11URI) (string, error) {
	serial, ok := p11uri.GetPathAttribute("object", false)
	if !ok {
		return "", errors.New("No 'object' attribute found in pkcs11 URI")
	}
	return serial, nil
}

// pkcs11UriLogin uses the given pkcs11 URI to select the pkcs11 module (share libary) and to get
// the PIN to use for login; if the URI contains a slot-id, the given slot-id will be used, otherwise
// one slot after the other will be attempted and the first one where login succeeds will be used
func pkcs11UriLogin(p11uri *pkcs11uri.Pkcs11URI) (ctx *pkcs11.Ctx, session pkcs11.SessionHandle, err error) {
	pin, module, slotid, err := pkcs11UriGetLoginParameters(p11uri)
	if err != nil {
		return nil, 0, err
	}

	p11ctx := pkcs11.New(module)
	if p11ctx == nil {
		return nil, 0, errors.New("Please check module path, input is: " + module)
	}

	err = p11ctx.Initialize()
	if err != nil {
		p11Err := err.(pkcs11.Error)
		if p11Err != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			return nil, 0, errors.Wrap(err, "Initialize failed")
		}
	}

	if slotid >= 0 {
		session, err = p11ctx.OpenSession(uint(slotid), pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			return nil, 0, errors.Wrapf(err, "OpenSession to slot %d failed", slotid)
		}
		err = p11ctx.Login(session, pkcs11.CKU_USER, pin)
		if err != nil {
			_ = p11ctx.CloseSession(session)
			return nil, 0, errors.Wrap(err, "Could not login to device")
		}
	} else {
		slots, err := p11ctx.GetSlotList(true)
		if err != nil {
			return nil, 0, errors.Wrap(err, "GetSlotList failed")
		}

		loggedin := false
		for _, slot := range slots {
			session, err = p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
			if err != nil {
				continue
			}
			err = p11ctx.Login(session, pkcs11.CKU_USER, pin)
			if err == nil {
				loggedin = true
				break
			}
			_ = p11ctx.CloseSession(session)
		}
		if !loggedin {
			return nil, 0, errors.New("Could not log in to any slots")
		}
	}

	return p11ctx, session, nil
}

func pkcs11Logout(ctx *pkcs11.Ctx, session pkcs11.SessionHandle) {
	_ = ctx.Logout(session)
	_ = ctx.CloseSession(session)
	_ = ctx.Finalize()
	ctx.Destroy()
}

// findObject finds an object of the given class with the given label
func findObject(p11ctx *pkcs11.Ctx, session pkcs11.SessionHandle, class uint, label string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := p11ctx.FindObjectsInit(session, template); err != nil {
		return 0, errors.Wrap(err, "FindObjectsInit failed")
	}

	obj, _, err := p11ctx.FindObjects(session, 1)
	if err != nil {
		return 0, errors.Wrap(err, "FindObjects failed")
	}

	if err := p11ctx.FindObjectsFinal(session); err != nil {
		return 0, errors.Wrap(err, "FindObjectsFinal failed")
	}
	if len(obj) > 0 {
		return obj[0], nil
	}

	return 0, errors.Errorf("Could not find any object with the label '%s'", label)
}

// publicEncryptOAEP uses a public key described by a pkcs11 URI to OAEP encrypt the given plaintext
func publicEncryptOAEP(pubKey *pkcs11uri.Pkcs11URI, plaintext []byte) ([]byte, string, error) {
	p11ctx, session, err := pkcs11UriLogin(pubKey)
	if err != nil {
		return nil, "", err
	}
	defer pkcs11Logout(p11ctx, session)

	label, err := pkcs11UriGetKeyLabel(pubKey)
	if err != nil {
		return nil, "", err
	}

	p11PubKey, err := findObject(p11ctx, session, pkcs11.CKO_PUBLIC_KEY, label)
	if err != nil {
		return nil, "", err
	}

	hashalg := OAEPDefaultHash

	// SoftHSM only accepts sha1 for OAEP; nevertheless we try sha256 first, and fall back to sha1 otherwise
	for _, oaep := range OAEPParams {
		err = p11ctx.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, oaep)}, p11PubKey)
		if err == nil {
			if oaep.HashAlg == pkcs11.CKM_SHA_1 {
				hashalg = "sha1"
			}
			break
		}
	}
	if err != nil {
		return nil, "", errors.Wrap(err, "EncryptInit error")
	}

	ciphertext, err := p11ctx.Encrypt(session, plaintext)
	if err != nil {
		return nil, "", errors.Wrap(err, "Encrypt failed")
	}
	return ciphertext, hashalg, nil
}

// privateDecryptOAEP uses a pkcs11 URI describing a private key to OAEP decrypt a ciphertext
func privateDecryptOAEP(privKey *pkcs11uri.Pkcs11URI, ciphertext []byte, hashalg string) ([]byte, error) {
	p11ctx, session, err := pkcs11UriLogin(privKey)
	if err != nil {
		return nil, err
	}
	defer pkcs11Logout(p11ctx, session)

	label, err := pkcs11UriGetKeyLabel(privKey)
	if err != nil {
		return nil, err
	}

	p11PrivKey, err := findObject(p11ctx, session, pkcs11.CKO_PRIVATE_KEY, label)
	if err != nil {
		return nil, err
	}

	oaep := OAEPSha256Params
	switch hashalg {
	case "sha1":
		oaep = OAEPSha1Params
	}

	err = p11ctx.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, oaep)}, p11PrivKey)
	if err != nil {
		return nil, errors.Wrapf(err, "DecryptInit failed")
	}
	plaintext, err := p11ctx.Decrypt(session, ciphertext)
	if err != nil {
		return nil, errors.Wrapf(err, "Decrypt failed")
	}
	return plaintext, err
}

//
// The following part deals with the JSON formatted message for multiple pkcs11 recipients
//

// Pkcs11Blob holds the encrypted blobs for all recipients; this is what we will put into the image's annotations
type Pkcs11Blob struct {
	Recipients []Pkcs11Recipient `json:"recipients"`
}

// Pkcs11Recipient holds the b64-encoded and encrypted blob for a particular recipient
type Pkcs11Recipient struct {
	Blob string `json:"blob"`
	Hash string `json:"hash,omitempty"`
}

// EncryptMultiple encrypts for one or multiple pkcs11 devices; the public keys passed to this function
// may either be *rsa.PublicKey or *pkcs11uri.Pkcs11URI; the returned byte array is a JSON string of the
// following format:
// {
//   recipients: [  // recipient list
//     {
//        "blob": <base64 encoded RSA OAEP encrypted blob>
//        "hash": <hash used for OAEP other than 'sha256'>
//     } ,
//     {
//        "blob": <base64 encoded RSA OAEP encrypted blob>
//        "hash": <hash used for OAEP other than 'sha256'>
//     } ,
//     [...]
//   ]
// }
func EncryptMultiple(pubKeys []interface{}, data []byte) ([]byte, error) {
	var (
		ciphertext []byte
		err        error
		pkcs11blob Pkcs11Blob = Pkcs11Blob{}
		hashalg    string
	)

	for _, pubKey := range pubKeys {
		switch pkey := pubKey.(type) {
		case *rsa.PublicKey:
			ciphertext, hashalg, err = rsaPublicEncryptOAEP(pkey, data)
		case *pkcs11uri.Pkcs11URI:
			ciphertext, hashalg, err = publicEncryptOAEP(pkey, data)
		default:
			err = errors.Errorf("Unsupported key object type for pkcs11 public key")
		}
		if err != nil {
			return nil, err
		}

		if hashalg == OAEPDefaultHash {
			hashalg = ""
		}
		recipient := Pkcs11Recipient{
			Blob: base64.StdEncoding.EncodeToString(ciphertext),
			Hash: hashalg,
		}

		pkcs11blob.Recipients = append(pkcs11blob.Recipients, recipient)
	}
	return json.Marshal(&pkcs11blob)
}

// Decrypt tries to decrypt one of the recipients' blobs using a pkcs11 private key.
// The input pkcs11blobstr is a string with the following format:
// {
//   recipients: [  // recipient list
//     {
//        "blob": <base64 encoded RSA OAEP encrypted blob>
//        "hash": <hash used for OAEP other than 'sha256'>
//     } ,
//     {
//        "blob": <base64 encoded RSA OAEP encrypted blob>
//        "hash": <hash used for OAEP other than 'sha256'>
//     } ,
//     [...]
// }
func Decrypt(privKeys []*pkcs11uri.Pkcs11URI, pkcs11blobstr []byte) ([]byte, error) {
	pkcs11blob := Pkcs11Blob{}
	err := json.Unmarshal(pkcs11blobstr, &pkcs11blob)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not parse Pkcs11Blob")
	}

	// since we do trial and error, collect all encountered errors
	errs := ""

	for _, recipient := range pkcs11blob.Recipients {
		ciphertext, err := base64.StdEncoding.DecodeString(recipient.Blob)
		if err != nil || len(ciphertext) == 0 {
			// This should never happen... we skip over decoding issues
			errs += fmt.Sprintf("Base64 decoding failed: %s\n", err)
			continue
		}
		// try all keys until one works
		for _, privKey := range privKeys {
			plaintext, err := privateDecryptOAEP(privKey, ciphertext, recipient.Hash)
			if err == nil {
				return plaintext, nil
			}
			uri, _ := privKey.Format()
			errs += fmt.Sprintf("%s : %s\n", uri, err)
		}
	}

	return nil, errors.Errorf("Could not find a pkcs11 key for decryption:\n%s", errs)
}
