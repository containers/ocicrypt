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
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	pkcs11uri "github.com/stefanberger/go-pkcs11uri"
)

var (
	SOFTHSM_SETUP = "../../scripts/softhsm_setup"
)

func getPkcs11Config(t *testing.T) Pkcs11Config {
	// we need to provide a configuration file so that on the various distros
	// the libsofthsm2.so will be found by searching directories
	config := `module-directories:
 - /usr/lib64/pkcs11/  # Fedora
 - /usr/lib/softhsm/   # Ubuntu
`
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
}

func runSoftHSMSetup(t *testing.T) string {
	cmd := exec.Command(SOFTHSM_SETUP, "setup")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Println(out.String())
		t.Fatal(err)
	}

	o := out.String()
	idx := strings.Index(o, "pkcs11:")
	if idx < 0 {
		t.Fatalf("Could not find pkcs11 URI in output")
	}

	return strings.TrimRight(o[idx:], "\n ")
}

func runSoftHSMGetPubkey(t *testing.T) string {
	cmd := exec.Command(SOFTHSM_SETUP, "getpubkey")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Println(out.String())
		t.Fatal(err)
	}

	return out.String()
}

func runSoftHSMTeardown(t *testing.T) {
	cmd := exec.Command(SOFTHSM_SETUP, "teardown")
	_ = cmd.Run()
}

func TestPkcs11EncryptDecrypt(t *testing.T) {
	// We always need the query attributes  'pin-value' and 'module-name'
	// for SoftHSM2 the only other important attribute is 'object' (= the 'label')
	p11pubkeyuristr := runSoftHSMSetup(t)
	defer runSoftHSMTeardown(t)

	p11pubkeyuri := pkcs11uri.New()
	err := p11pubkeyuri.Parse(p11pubkeyuristr)
	if err != nil {
		t.Fatal(err)
	}

	testinput := "Hello World!"

	p11conf := getPkcs11Config(t)
	p11pubkeyuri.SetModuleDirectories(p11conf.ModuleDirectories)

	pubKeys := make([]interface{}, 1)
	pubKeys[0] = p11pubkeyuri
	p11json, err := EncryptMultiple(pubKeys, []byte(testinput))
	if err != nil {
		t.Fatal(err)
	}

	// for SoftHSM we can just reuse the public key URI
	privKeys := make([]*pkcs11uri.Pkcs11URI, 1)
	privKeys[0] = p11pubkeyuri
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
	p11pubkeyuristr := runSoftHSMSetup(t)
	defer runSoftHSMTeardown(t)

	pubkeypem := runSoftHSMGetPubkey(t)

	block, _ := pem.Decode([]byte(pubkeypem))
	if block == nil {
		t.Fatal("failed to parse PEM block containing the public key")
	}
	rsapubkey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	testinput := "Hello World!"

	os.Setenv("OCICRYPT_OAEP_HASHALG", "sha1")

	pubKeys := make([]interface{}, 1)
	pubKeys[0] = rsapubkey
	p11json, err := EncryptMultiple(pubKeys, []byte(testinput))
	if err != nil {
		t.Fatal(err)
	}

	p11pubkeyuri := pkcs11uri.New()
	err = p11pubkeyuri.Parse(p11pubkeyuristr)
	if err != nil {
		t.Fatal(err)
	}
	p11conf := getPkcs11Config(t)
	p11pubkeyuri.SetModuleDirectories(p11conf.ModuleDirectories)

	// for SoftHSM we can just reuse the public key URI
	privKeys := make([]*pkcs11uri.Pkcs11URI, 1)
	privKeys[0] = p11pubkeyuri
	plaintext, err := Decrypt(privKeys, p11json)
	if err != nil {
		t.Fatal(err)
	}

	if string(plaintext) != testinput {
		t.Fatalf("plaintext '%s' is not expected '%s'", plaintext, testinput)
	}
}
