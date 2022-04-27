// +build cgo

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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/containers/ocicrypt/utils/softhsm"
)

var (
	SOFTHSM_SETUP = "../../scripts/softhsm_setup"
)

func getPkcs11Config(t *testing.T) *Pkcs11Config {
	// we need to provide a configuration file so that on the various distros
	// the libsofthsm2.so will be found by searching directories
	mdyaml := GetDefaultModuleDirectoriesYaml("")
	config := fmt.Sprintf("module-directories:\n"+
		"%s"+
		"allowed-module-paths:\n"+
		"%s", mdyaml, mdyaml)

	p11conf, err := ParsePkcs11ConfigFile([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	return p11conf
}

func TestParsePkcs11KeyFileGood(t *testing.T) {
	data := `pkcs11:
   uri: pkcs11:slot-id=2053753261?module-name=softhsm2&pin-value=1234
`
	if !IsPkcs11PrivateKey([]byte(data)) {
		t.Fatalf("YAML should have been detected as pkcs11 private key")
	}

	p11keyfileobj, err := ParsePkcs11KeyFile([]byte(data))
	if err != nil {
		t.Fatal(err)
	}

	p11conf := getPkcs11Config(t)
	p11keyfileobj.Uri.SetModuleDirectories(p11conf.ModuleDirectories)
	p11keyfileobj.Uri.SetAllowedModulePaths(p11conf.ModuleDirectories)

	module, err := p11keyfileobj.Uri.GetModule()
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasSuffix(module, "/libsofthsm2.so") {
		t.Fatalf("Unexpect module '%s'", module)
	}
}

func TestParsePkcs11KeyFileBad(t *testing.T) {
	data := `pkcs11:
   uri: foobar
`
	if IsPkcs11PrivateKey([]byte(data)) {
		t.Fatalf("Malformed pkcs11 key file should not have been detected as a pkcs11 private key")
	}

	_, err := ParsePkcs11KeyFile([]byte(data))
	if err == nil {
		t.Fatalf("Parsing the malformed pkcs11 key file should have failed")
	}

	// Missing URI
	data = `pkcs11:
`
	if IsPkcs11PrivateKey([]byte(data)) {
		t.Fatalf("Malformed pkcs11 key file should not have been detected as a pkcs11 private key")
	}

	_, err = ParsePkcs11KeyFile([]byte(data))
	if err == nil {
		t.Fatalf("Parsing the malformed pkcs11 key file should have failed")
	}
}

func TestPkcs11EncryptDecrypt(t *testing.T) {
	// We always need the query attributes  'pin-value' and 'module-name'
	// for SoftHSM2 the only other important attribute is 'object' (= the 'label')
	shsm := softhsm.NewSoftHSMSetup()
	p11pubkeyuristr, err := shsm.RunSoftHSMSetup(SOFTHSM_SETUP)
	if err != nil {
		t.Fatal(err)
	}
	defer shsm.RunSoftHSMTeardown(SOFTHSM_SETUP)

	data := `pkcs11:
    uri: ` + p11pubkeyuristr + `
module:
    env:
      SOFTHSM2_CONF: ` + shsm.GetConfigFilename()

	// deactivate the PIN value
	pubkeydata := strings.Replace(data, "pin-value", "unused", 1)

	p11pubkeyfileobj, err := ParsePkcs11KeyFile([]byte(pubkeydata))
	if err != nil {
		t.Fatal(err)
	}

	testinput := "Hello World!"

	p11conf := getPkcs11Config(t)
	p11pubkeyfileobj.Uri.SetModuleDirectories(p11conf.ModuleDirectories)
	p11pubkeyfileobj.Uri.SetAllowedModulePaths(p11conf.ModuleDirectories)

	// SoftHSM 2.6.1 only supports OAEP with sha1
	// https://github.com/opendnssec/SoftHSMv2/blob/7f99bedae002f0dd04ceeb8d86d59fc4a68a69a0/src/lib/SoftHSM.cpp#L3123-L3127
	os.Setenv("OCICRYPT_OAEP_HASHALG", "sha1")

	pubKeys := make([]interface{}, 1)
	pubKeys[0] = p11pubkeyfileobj
	p11json, err := EncryptMultiple(pubKeys, []byte(testinput))
	if err != nil {
		t.Fatal(err)
	}

	p11privkeyfileobj, err := ParsePkcs11KeyFile([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	p11privkeyfileobj.Uri.SetModuleDirectories(p11conf.ModuleDirectories)
	p11privkeyfileobj.Uri.SetAllowedModulePaths(p11conf.ModuleDirectories)

	privKeys := make([]*Pkcs11KeyFileObject, 1)
	privKeys[0] = p11privkeyfileobj
	plaintext, err := Decrypt(privKeys, p11json)
	if err != nil {
		t.Fatal(err)
	}

	if string(plaintext) != testinput {
		t.Fatalf("plaintext '%s' is not expected '%s'", plaintext, testinput)
	}
}

func TestPkcs11EncryptDecryptPubkey(t *testing.T) {
	// We always need the query attributes  'pin-value' and 'module-name'
	// for SoftHSM2 the only other important attribute is 'object' (= the 'label')
	shsm := softhsm.NewSoftHSMSetup()
	p11pubkeyuristr, err := shsm.RunSoftHSMSetup(SOFTHSM_SETUP)
	if err != nil {
		t.Fatal(err)
	}
	defer shsm.RunSoftHSMTeardown(SOFTHSM_SETUP)

	pubkeypem, err := shsm.RunSoftHSMGetPubkey(SOFTHSM_SETUP)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode([]byte(pubkeypem))
	if block == nil {
		t.Fatal("failed to parse PEM block containing the public key")
	}
	rsapubkey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	testinput := "Hello World!"

	// SoftHSM 2.6.1 only supports OAEP with sha1
	// https://github.com/opendnssec/SoftHSMv2/blob/7f99bedae002f0dd04ceeb8d86d59fc4a68a69a0/src/lib/SoftHSM.cpp#L3123-L3127
	os.Setenv("OCICRYPT_OAEP_HASHALG", "sha1")

	pubKeys := make([]interface{}, 1)
	pubKeys[0] = rsapubkey
	p11json, err := EncryptMultiple(pubKeys, []byte(testinput))
	if err != nil {
		t.Fatal(err)
	}

	data := `pkcs11:
    uri: ` + p11pubkeyuristr + `
module:
    env:
       SOFTHSM2_CONF: ` + shsm.GetConfigFilename()

	p11keyfileobj, err := ParsePkcs11KeyFile([]byte(data))
	if err != nil {
		t.Fatal(err)
	}

	p11conf := getPkcs11Config(t)
	p11keyfileobj.Uri.SetModuleDirectories(p11conf.ModuleDirectories)
	p11keyfileobj.Uri.SetAllowedModulePaths(p11conf.ModuleDirectories)

	// for SoftHSM we can just reuse the public key URI
	privKeys := make([]*Pkcs11KeyFileObject, 1)
	privKeys[0] = p11keyfileobj
	plaintext, err := Decrypt(privKeys, p11json)
	if err != nil {
		t.Fatal(err)
	}

	if string(plaintext) != testinput {
		t.Fatalf("plaintext '%s' is not expected '%s'", plaintext, testinput)
	}
}
