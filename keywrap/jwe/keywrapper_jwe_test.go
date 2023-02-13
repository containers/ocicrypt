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

package jwe

import (
	"crypto/elliptic"
	"testing"

	"github.com/containers/ocicrypt/config"
	"github.com/containers/ocicrypt/utils"
	"github.com/go-jose/go-jose/v3"
)

var oneEmpty []byte

func createValidJweCcs() ([]*config.CryptoConfig, error) {

	jwePubKeyPem, jwePrivKeyPem, err := utils.CreateRSATestKey(2048, oneEmpty, true)
	if err != nil {
		return nil, err
	}

	jwePubKey2Pem, jwePrivKey2Pem, err := utils.CreateRSATestKey(1024, oneEmpty, true)
	if err != nil {
		return nil, err
	}

	jwePrivKey3Password := []byte("password")
	jwePubKey3Pem, jwePrivKey3PassPem, err := utils.CreateRSATestKey(2048, jwePrivKey3Password, true)
	if err != nil {
		return nil, err
	}

	jwePubKeyDer, jwePrivKeyDer, err := utils.CreateRSATestKey(2048, oneEmpty, false)
	if err != nil {
		return nil, err
	}

	jweEcPubKeyDer, jweEcPrivKeyDer, err := utils.CreateECDSATestKey(elliptic.P521())
	if err != nil {
		return nil, err
	}

	key, err := utils.CreateRSAKey(2048)
	if err != nil {
		return nil, err
	}

	jwePrivKeyJwk, err := jose.JSONWebKey{Key: key}.MarshalJSON()
	if err != nil {
		return nil, err
	}

	jwePubKeyJwk, err := jose.JSONWebKey{Key: &key.PublicKey}.MarshalJSON()
	if err != nil {
		return nil, err
	}

	validJweCcs := []*config.CryptoConfig{
		// Key 1
		{
			EncryptConfig: &config.EncryptConfig{
				Parameters: map[string][][]byte{
					"pubkeys": {jwePubKeyPem},
				},
				DecryptConfig: config.DecryptConfig{
					Parameters: map[string][][]byte{
						"privkeys":           {jwePrivKeyPem},
						"privkeys-passwords": {oneEmpty},
					},
				},
			},

			DecryptConfig: &config.DecryptConfig{
				Parameters: map[string][][]byte{
					"privkeys":           {jwePrivKeyPem},
					"privkeys-passwords": {oneEmpty},
				},
			},
		},

		// Key 2
		{
			EncryptConfig: &config.EncryptConfig{
				Parameters: map[string][][]byte{
					"pubkeys": {jwePubKey2Pem},
				},
				DecryptConfig: config.DecryptConfig{
					Parameters: map[string][][]byte{
						"privkeys":           {jwePrivKey2Pem},
						"privkeys-passwords": {oneEmpty},
					},
				},
			},

			DecryptConfig: &config.DecryptConfig{
				Parameters: map[string][][]byte{
					"privkeys":           {jwePrivKey2Pem},
					"privkeys-passwords": {oneEmpty},
				},
			},
		},

		// Key 1 without enc private key
		{
			EncryptConfig: &config.EncryptConfig{
				Parameters: map[string][][]byte{
					"pubkeys": {jwePubKeyPem},
				},
			},

			DecryptConfig: &config.DecryptConfig{
				Parameters: map[string][][]byte{
					"privkeys":           {jwePrivKeyPem},
					"privkeys-passwords": {oneEmpty},
				},
			},
		},

		// Key 2 without enc private key
		{
			EncryptConfig: &config.EncryptConfig{
				Parameters: map[string][][]byte{
					"pubkeys": {jwePubKey2Pem},
				},
			},

			DecryptConfig: &config.DecryptConfig{
				Parameters: map[string][][]byte{
					"privkeys":           {jwePrivKey2Pem},
					"privkeys-passwords": {oneEmpty},
				},
			},
		},

		// Key 3 with enc private key
		{
			EncryptConfig: &config.EncryptConfig{
				Parameters: map[string][][]byte{
					"pubkeys": {jwePubKey3Pem},
				},
			},

			DecryptConfig: &config.DecryptConfig{
				Parameters: map[string][][]byte{
					"privkeys":           {jwePrivKey3PassPem},
					"privkeys-passwords": {jwePrivKey3Password},
				},
			},
		},

		// Key (DER format)
		{
			EncryptConfig: &config.EncryptConfig{
				Parameters: map[string][][]byte{
					"pubkeys": {jwePubKeyDer},
				},
				DecryptConfig: config.DecryptConfig{
					Parameters: map[string][][]byte{
						"privkeys":           {jwePrivKeyDer},
						"privkeys-passwords": {oneEmpty},
					},
				},
			},

			DecryptConfig: &config.DecryptConfig{
				Parameters: map[string][][]byte{
					"privkeys":           {jwePrivKeyDer},
					"privkeys-passwords": {oneEmpty},
				},
			},
		},
		// Key (JWK format)
		{
			EncryptConfig: &config.EncryptConfig{
				Parameters: map[string][][]byte{
					"pubkeys": {jwePubKeyJwk},
				},
				DecryptConfig: config.DecryptConfig{
					Parameters: map[string][][]byte{
						"privkeys":           {jwePrivKeyJwk},
						"privkeys-passwords": {oneEmpty},
					},
				},
			},

			DecryptConfig: &config.DecryptConfig{
				Parameters: map[string][][]byte{
					"privkeys":           {jwePrivKeyJwk},
					"privkeys-passwords": {oneEmpty},
				},
			},
		},
		// EC Key (DER format)
		{
			EncryptConfig: &config.EncryptConfig{
				Parameters: map[string][][]byte{
					"pubkeys": {jweEcPubKeyDer},
				},
				DecryptConfig: config.DecryptConfig{
					Parameters: map[string][][]byte{
						"privkeys":           {jweEcPrivKeyDer},
						"privkeys-passwords": {oneEmpty},
					},
				},
			},

			DecryptConfig: &config.DecryptConfig{
				Parameters: map[string][][]byte{
					"privkeys":           {jweEcPrivKeyDer},
					"privkeys-passwords": {oneEmpty},
				},
			},
		},
	}
	return validJweCcs, nil
}

func createInvalidJweCcs() ([]*config.CryptoConfig, error) {

	jwePubKeyPem, _, err := utils.CreateRSATestKey(2048, oneEmpty, true)
	if err != nil {
		return nil, err
	}

	jwePubKey2Pem, _, err := utils.CreateRSATestKey(2048, oneEmpty, true)
	if err != nil {
		return nil, err
	}

	invalidJweCcs := []*config.CryptoConfig{
		// Client key 1 public with client 2 private decrypt
		{
			EncryptConfig: &config.EncryptConfig{
				Parameters: map[string][][]byte{
					"pubkeys": {jwePubKeyPem},
				},
			},
			DecryptConfig: &config.DecryptConfig{
				Parameters: map[string][][]byte{
					"privkeys":           {jwePubKey2Pem},
					"privkeys-passwords": {oneEmpty},
				},
			},
		},

		// Client key 1 public with no private key
		{
			EncryptConfig: &config.EncryptConfig{
				Parameters: map[string][][]byte{
					"pubkeys": {jwePubKeyPem},
				},
			},
			DecryptConfig: &config.DecryptConfig{
				Parameters: map[string][][]byte{},
			},
		},

		// Invalid Client key 1 private key
		{
			EncryptConfig: &config.EncryptConfig{
				Parameters: map[string][][]byte{
					"pubkeys": {jwePubKeyPem},
				},
			},
			DecryptConfig: &config.DecryptConfig{
				Parameters: map[string][][]byte{
					"privkeys":           {jwePubKeyPem},
					"privkeys-passwords": {oneEmpty},
				},
			},
		},
	}
	return invalidJweCcs, nil
}

func TestKeyWrapJweSuccess(t *testing.T) {
	validJweCcs, err := createValidJweCcs()
	if err != nil {
		t.Fatal(err)
	}

	for _, cc := range validJweCcs {
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

func TestKeyWrapJweInvalid(t *testing.T) {
	invalidJweCcs, err := createInvalidJweCcs()
	if err != nil {
		t.Fatal(err)
	}

	for _, cc := range invalidJweCcs {
		kw := NewKeyWrapper()

		data := []byte("This is some secret text")

		wk, err := kw.WrapKeys(cc.EncryptConfig, data)
		if err != nil {
			return
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
}
