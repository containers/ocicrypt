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
	"fmt"
	"os"
	"testing"

	"github.com/containers/ocicrypt/config"
	"github.com/containers/ocicrypt/utils"
	"github.com/containers/ocicrypt/crypto/pkcs11"
	"github.com/containers/ocicrypt/utils/softhsm"
)

var (
	SOFTHSM_SETUP = "../../scripts/softhsm_setup"
)

func getPkcs11ConfigYaml(t *testing.T) []byte {
	// we need to provide a configuration file so that on the various distros
	// the libsofthsm2.so will be found by searching directories
	mdyamls := pkcs11.GetDefaultModuleDirectoriesYaml("")
	config := fmt.Sprintf("module-directories:\n"+
		"%s"+
		"allowed-module-paths:\n"+
		"%s", mdyamls, mdyamls)
	return []byte(config)
}

func createValidPkcs11Ccs(t *testing.T) ([]*config.CryptoConfig, *softhsm.SoftHSMSetup, error) {
	shsm := softhsm.NewSoftHSMSetup()
	pkcs11PubKeyUriStr, err := shsm.RunSoftHSMSetup(SOFTHSM_SETUP)
	if err != nil {
		return nil, shsm, err
	}
	pubKeyPem, err := shsm.RunSoftHSMGetPubkey(SOFTHSM_SETUP)
	if err != nil {
		return nil, shsm, err
	}
	pkcs11PrivKeyYaml := `
pkcs11:
  uri: ` + pkcs11PubKeyUriStr + `
module:
  env:
    SOFTHSM2_CONF: ` + shsm.GetConfigFilename()

	p11confYaml := getPkcs11ConfigYaml(t)

	validPkcs11Ccs := []*config.CryptoConfig{
		// Key 1
		{
			EncryptConfig: &config.EncryptConfig{
				Parameters: map[string][][]byte{
					"pkcs11-pubkeys": {[]byte(pubKeyPem)},
				},
				DecryptConfig: config.DecryptConfig{
					Parameters: map[string][][]byte{
						"pkcs11-yamls":  {[]byte(pkcs11PrivKeyYaml)},
						"pkcs11-config": {p11confYaml},
					},
				},
			},

			DecryptConfig: &config.DecryptConfig{
				Parameters: map[string][][]byte{
					"pkcs11-yamls":  {[]byte(pkcs11PrivKeyYaml)},
					"pkcs11-config": {p11confYaml},
				},
			},
		},
		// Key 2
		{
			EncryptConfig: &config.EncryptConfig{
				Parameters: map[string][][]byte{
					// public and private key YAMLs are identical
					"pkcs11-yamls": {[]byte(pkcs11PrivKeyYaml)},
				},
				DecryptConfig: config.DecryptConfig{
					Parameters: map[string][][]byte{
						"pkcs11-yamls":  {[]byte(pkcs11PrivKeyYaml)},
						"pkcs11-config": {p11confYaml},
					},
				},
			},

			DecryptConfig: &config.DecryptConfig{
				Parameters: map[string][][]byte{
					"pkcs11-yamls":  {[]byte(pkcs11PrivKeyYaml)},
					"pkcs11-config": {p11confYaml},
				},
			},
		},
	}
	return validPkcs11Ccs, shsm, nil
}

func createInvalidPkcs11Ccs(t *testing.T) ([]*config.CryptoConfig, *softhsm.SoftHSMSetup, error) {
	shsm := softhsm.NewSoftHSMSetup()
	pkcs11PubKeyUriStr, err := shsm.RunSoftHSMSetup(SOFTHSM_SETUP)
	if err != nil {
		return nil, shsm, err
	}
	pubKey2Pem, _, err := utils.CreateRSATestKey(2048, nil, true)
	if err != nil {
		return nil, shsm, err
	}
	pkcs11PrivKeyYaml := `
pkcs11:
  uri: ` + pkcs11PubKeyUriStr + `
module:
  env:
    SOFTHSM2_CONF: ` + shsm.GetConfigFilename()

	p11confYaml := getPkcs11ConfigYaml(t)

	invalidPkcs11Ccs := []*config.CryptoConfig{
		// Key 1
		{
			EncryptConfig: &config.EncryptConfig{
				Parameters: map[string][][]byte{
					"pkcs11-pubkeys": {[]byte(pubKey2Pem)},
				},
				DecryptConfig: config.DecryptConfig{
					Parameters: map[string][][]byte{
						"pkcs11-yamls":  {[]byte(pkcs11PrivKeyYaml)},
						"pkcs11-config": {p11confYaml},
					},
				},
			},

			DecryptConfig: &config.DecryptConfig{
				Parameters: map[string][][]byte{
					"pkcs11-yamls":  {[]byte(pkcs11PrivKeyYaml)},
					"pkcs11-config": {p11confYaml},
				},
			},
		},
	}
	return invalidPkcs11Ccs, shsm, nil
}

func TestKeyWrapPkcs11Success(t *testing.T) {
	validPkcs11Ccs, shsm, err := createValidPkcs11Ccs(t)
	defer shsm.RunSoftHSMTeardown(SOFTHSM_SETUP)
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv("OCICRYPT_OAEP_HASHALG", "sha1")

	for _, cc := range validPkcs11Ccs {
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
}

func TestKeyWrapPkcs11Invalid(t *testing.T) {
	invalidPkcs11Ccs, shsm, err := createInvalidPkcs11Ccs(t)
	defer shsm.RunSoftHSMTeardown(SOFTHSM_SETUP)
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv("OCICRYPT_OAEP_HASHALG", "sha1")

	for _, cc := range invalidPkcs11Ccs {
		kw := NewKeyWrapper()

		data := []byte("This is some secret text")

		wk, err := kw.WrapKeys(cc.EncryptConfig, data)
		if err != nil {
			t.Fatalf("Wrapping should have worked")
		}

		ud, err := kw.UnwrapKey(cc.DecryptConfig, wk)
		if err != nil {
			continue
		}

		if string(data) != string(ud) {
			t.Fatalf("Unwrapping should have failed already")
		}

		t.Fatal("Successfully wrapped and unwrapped with invalid crypto config")
	}
}
