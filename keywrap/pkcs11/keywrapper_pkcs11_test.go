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
	"github.com/containers/ocicrypt/config"
	"log"
	"os"
	"strings"
	"testing"
)

var (
	modulePath string
	modulePin  string
)

// init setup the module path and pin in system ENV
// like: ENC_PKCS11_PATH=/usr/local/lib/softhsm/libsofthsm.so
//       ENC_PKCS11_PIN=1234
// if don't have above env variables, skip PKCS11 testing
func init() {
	modulePath = os.Getenv("ENC_PKCS11_PATH")
	modulePin = os.Getenv("ENC_PKCS11_PIN")
}

func TestKeyWrapPkcs11Invalid(t *testing.T) {
	if modulePath == "" {
		t.Skip("Need set env variable [ENC_PKCS11_PATH] for module path.")
	}
	if modulePin == "" {
		t.Skip("Need set env variable [ENC_PKCS11_PIN] for module pin.")
	}

	cc, err := createInvalidPkcs11Cc()

	kw := NewKeyWrapper()

	data := []byte("This is some secret text")

	wk, err := kw.WrapKeys(cc.EncryptConfig, data)
	if err != nil {
		if strings.Contains(err.Error(), "Please check Module path") {
			return
		}
		log.Fatalf("unexpect error: %v", err)
	}

	ud, err := kw.UnwrapKey(cc.DecryptConfig, wk)
	if err != nil {
		return
	}

	if string(data) != string(ud) {
		return
	}

	t.Fatal("Successfully wrap for invalid crypto config")
}

func TestKeyWrapPkcs11Success(t *testing.T) {
	if modulePath == "" {
		t.Skip("Need set env variable [ENC_PKCS11_PATH] for module path.")
	}
	if modulePin == "" {
		t.Skip("Need set env variable [ENC_PKCS11_PIN] for module pin.")
	}

	cc, err := createValidPkcs11Cc()

	kw := NewKeyWrapper()

	data := []byte("This is some secret text")

	wk, err := kw.WrapKeys(cc.EncryptConfig, data)
	if err != nil {
		t.Fatal(err)
	}

	ud, err := kw.UnwrapKey(cc.DecryptConfig, wk)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != string(ud) {
		t.Fatal("Strings don't match")
	}
}

func createValidPkcs11Cc() (*config.CryptoConfig, error) {
	validPkcs11Ccs := &config.CryptoConfig{
		EncryptConfig: &config.EncryptConfig{
			Parameters: map[string][][]byte{
				"modules": {[]byte(modulePath)},
				"pins":    {[]byte(modulePin)},
			},
		},
		DecryptConfig: &config.DecryptConfig{
			Parameters: map[string][][]byte{
				"modules": {[]byte(modulePath)},
				"pins":    {[]byte(modulePin)},
			},
		},
	}
	return validPkcs11Ccs, nil
}

func createInvalidPkcs11Cc() (*config.CryptoConfig, error) {
	wrongPathPkcs11Ccs := &config.CryptoConfig{
		EncryptConfig: &config.EncryptConfig{
			Parameters: map[string][][]byte{
				// make error module path
				"modules": {[]byte(modulePath + ".err")},
				"pins":    {[]byte(modulePin)},
			},
		},
	}
	return wrongPathPkcs11Ccs, nil
}
