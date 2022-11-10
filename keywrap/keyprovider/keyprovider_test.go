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

package keyprovider

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"github.com/containers/ocicrypt/config"
	keyprovider_config "github.com/containers/ocicrypt/config/keyprovider-config"
	keyproviderpb "github.com/containers/ocicrypt/utils/keyprovider"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

// TestRunner mocks binary executable for key wrapping and unwrapping
type TestRunner struct{}

// Mock annotation packet, which goes into container image manifest
type annotationPacket struct {
	KeyUrl     string `json:"key_url"`
	WrappedKey []byte `json:"wrapped_key"`
	WrapType   string `json:"wrap_type"`
}

// grpc server with mock api implementation for serving the clients with mock WrapKey and Unwrapkey grpc method implementations
type server struct {
	keyproviderpb.UnimplementedKeyProviderServiceServer
}

var encryptingKey []byte
var decryptingKey []byte

func init() {
	lis, _ := net.Listen("tcp", ":50051")
	s := grpc.NewServer()
	keyproviderpb.RegisterKeyProviderServiceServer(s, &server{})
	go func() {
		if err := s.Serve(lis); err != nil {
			fmt.Println(err)
		}
	}()
}

// Mock grpc method which returns the wrapped key encapsulated in annotation packet in grpc response for a given key in grpc request
func (*server) WrapKey(ctx context.Context, request *keyproviderpb.KeyProviderKeyWrapProtocolInput) (*keyproviderpb.KeyProviderKeyWrapProtocolOutput, error) {
	var keyP KeyProviderKeyWrapProtocolInput
	err := json.Unmarshal(request.KeyProviderKeyWrapProtocolInput, &keyP)
	if err != nil {
		return nil, err
	}
	c, _ := aes.NewCipher(encryptingKey)
	gcm, _ := cipher.NewGCM(c)
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	wrappedKey := gcm.Seal(nonce, nonce, keyP.KeyWrapParams.OptsData, nil)

	jsonString, _ := json.Marshal(annotationPacket{
		KeyUrl:     "https://key-provider/key-uuid",
		WrappedKey: wrappedKey,
		WrapType:   "AES",
	})

	protocolOuputSerialized, _ := json.Marshal(KeyProviderKeyWrapProtocolOutput{
		KeyWrapResults: KeyWrapResults{Annotation: jsonString},
	})

	return &keyproviderpb.KeyProviderKeyWrapProtocolOutput{
		KeyProviderKeyWrapProtocolOutput: protocolOuputSerialized,
	}, nil
}

// Mock grpc method which returns the unwrapped key encapsulated in grpc response for a given wrapped key encapsulated in annotation packet in grpc request
func (*server) UnWrapKey(ctx context.Context, request *keyproviderpb.KeyProviderKeyWrapProtocolInput) (*keyproviderpb.KeyProviderKeyWrapProtocolOutput, error) {
	var keyP KeyProviderKeyWrapProtocolInput
	err := json.Unmarshal(request.KeyProviderKeyWrapProtocolInput, &keyP)
	if err != nil {
		return nil, err
	}
	apkt := annotationPacket{}
	err = json.Unmarshal(keyP.KeyUnwrapParams.Annotation, &apkt)
	if err != nil {
		return nil, err
	}
	ciphertext := apkt.WrappedKey

	c, _ := aes.NewCipher(decryptingKey)
	gcm, _ := cipher.NewGCM(c)
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	unwrappedKey, err := gcm.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		return nil, err
	}

	protocolOuputSerialized, _ := json.Marshal(KeyProviderKeyWrapProtocolOutput{
		KeyUnwrapResults: KeyUnwrapResults{OptsData: unwrappedKey},
	})
	return &keyproviderpb.KeyProviderKeyWrapProtocolOutput{
		KeyProviderKeyWrapProtocolOutput: protocolOuputSerialized,
	}, nil
}

// Mock Exec Command for wrapping and unwrapping executables
func (r TestRunner) Exec(cmdName string, args []string, input []byte) ([]byte, error) {
	if cmdName == "/usr/lib/keyprovider-1-wrapkey" {
		var keyP KeyProviderKeyWrapProtocolInput
		err := json.Unmarshal(input, &keyP)
		if err != nil {
			return nil, err
		}
		c, _ := aes.NewCipher(encryptingKey)
		gcm, _ := cipher.NewGCM(c)

		nonce := make([]byte, gcm.NonceSize())
		_, err = io.ReadFull(rand.Reader, nonce)
		if err != nil {
			return nil, err
		}
		wrappedKey := gcm.Seal(nonce, nonce, keyP.KeyWrapParams.OptsData, nil)

		jsonString, _ := json.Marshal(annotationPacket{
			KeyUrl:     "https://key-provider/key-uuid",
			WrappedKey: wrappedKey,
			WrapType:   "AES",
		})

		return json.Marshal(KeyProviderKeyWrapProtocolOutput{
			KeyWrapResults: KeyWrapResults{
				Annotation: jsonString,
			},
		})
	} else if cmdName == "/usr/lib/keyprovider-1-unwrapkey" {
		var keyP KeyProviderKeyWrapProtocolInput
		err := json.Unmarshal(input, &keyP)
		if err != nil {
			return nil, err
		}
		apkt := annotationPacket{}
		err = json.Unmarshal(keyP.KeyUnwrapParams.Annotation, &apkt)
		if err != nil {
			return nil, err
		}
		ciphertext := apkt.WrappedKey

		c, _ := aes.NewCipher(decryptingKey)
		gcm, _ := cipher.NewGCM(c)
		nonceSize := gcm.NonceSize()
		nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
		unwrappedKey, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, err
		}

		return json.Marshal(KeyProviderKeyWrapProtocolOutput{
			KeyUnwrapResults: KeyUnwrapResults{OptsData: unwrappedKey},
		})
	}
	return nil, errors.New("unkown protocol")
}

func TestKeyWrapKeyProviderCommandSuccess(t *testing.T) {
	testConfigFile := "config.json"
	os.Setenv("OCICRYPT_KEYPROVIDER_CONFIG", testConfigFile)
	//Config File with executable for key wrap
	configFile1 := `{"key-providers": {
                "keyprovider-1": {
					"cmd": {
					   "path": "/usr/lib/keyprovider-1-wrapkey",
					   "args": []
					}
                }
        }}
        `
	//Config File with executable for key unwrap
	configFile2 := `{"key-providers": {
                "keyprovider-1": {
					"cmd": {
					   "path": "/usr/lib/keyprovider-1-unwrapkey",
					   "args": []
					}
                }
        }}
        `
	configFile, _ := os.OpenFile(testConfigFile, os.O_CREATE|os.O_WRONLY, 0644)
	_, err := configFile.Write([]byte(configFile1))
	assert.NoError(t, err)
	configFile.Close()

	optsData := []byte("data to be encrypted")

	ic, _ := keyprovider_config.GetConfiguration()
	keyWrapper := NewKeyWrapper("keyprovider-1", ic.KeyProviderConfig["keyprovider-1"])

	parameters := make(map[string][][]byte)
	parameters["keyprovider-1"] = nil
	ec := config.EncryptConfig{
		Parameters:    parameters,
		DecryptConfig: config.DecryptConfig{},
	}
	encryptingKey = []byte("passphrasewhichneedstobe32bytes!")
	decryptingKey = []byte("passphrasewhichneedstobe32bytes!")
	runner = TestRunner{}
	keyWrapOutput, err := keyWrapper.WrapKeys(&ec, optsData)
	assert.NoError(t, err)

	configFile, _ = os.OpenFile(testConfigFile, os.O_CREATE|os.O_WRONLY, 0644)
	_, err = configFile.Write([]byte(configFile2))
	assert.NoError(t, err)
	configFile.Close()

	ic, _ = keyprovider_config.GetConfiguration()
	keyWrapper = NewKeyWrapper("keyprovider-1", ic.KeyProviderConfig["keyprovider-1"])
	dp := make(map[string][][]byte)
	dp["keyprovider-1"] = append(dp["keyprovider-1"], []byte("Supported Protocol"))

	dc := config.DecryptConfig{
		Parameters: dp,
	}
	keyUnWrapOutput, err := keyWrapper.UnwrapKey(&dc, keyWrapOutput)
	assert.NoError(t, err)
	assert.Equal(t, optsData, keyUnWrapOutput)
	os.Remove(testConfigFile)
}

func TestKeyWrapKeyProviderCommandFail(t *testing.T) {
	testConfigFile := "config.json"
	os.Setenv("OCICRYPT_KEYPROVIDER_CONFIG", testConfigFile)
	//Config File with executable for key wrap
	configFile1 := `{"key-providers": {
                "keyprovider-1": {
					"cmd": {
					   "path": "/usr/lib/keyprovider-1-wrapkey",
					   "args": []
					}
                },
		        "keyprovider-2": {
					"cmd": {
					   "path": "/usr/lib/keyprovider-2-wrapkey",
					   "args": []
					}
                }
        }}
        `
	//Config File with executable for key unwrap
	configFile2 := `{"key-providers": {
                  "keyprovider-1": {
                      "cmd": {
					      "path": "/usr/lib/keyprovider-1-unwrapkey",
                          "args": []
					   }
                    },
		           "keyprovider-2": {
					"cmd": {
					   "path": "/usr/lib/keyprovider-2-unwrapkey",
					   "args": []
					}
                }
        }}
        `
	configFile, _ := os.OpenFile(testConfigFile, os.O_CREATE|os.O_WRONLY, 0644)
	_, err := configFile.Write([]byte(configFile1))
	assert.NoError(t, err)
	configFile.Close()

	optsData := []byte("data to be encrypted")
	ic, _ := keyprovider_config.GetConfiguration()
	keyWrapper := NewKeyWrapper("keyprovider-1", ic.KeyProviderConfig["keyprovider-1"])

	parameters := make(map[string][][]byte)
	parameters["keyprovider-1"] = nil
	ec := config.EncryptConfig{
		Parameters:    parameters,
		DecryptConfig: config.DecryptConfig{},
	}
	encryptingKey = []byte("passphrasewhichneedstobe32bytes!")
	decryptingKey = []byte("wrongphrasewhichneedstobe32bytes")
	runner = TestRunner{}
	keyWrapOutput, err := keyWrapper.WrapKeys(&ec, optsData)
	assert.NoError(t, err)

	configFile, _ = os.OpenFile(testConfigFile, os.O_CREATE|os.O_WRONLY, 0644)
	_, err = configFile.Write([]byte(configFile2))
	assert.NoError(t, err)
	configFile.Close()

	dp := make(map[string][][]byte)
	dp["keyprovider-1"] = append(dp["keyprovider-1"], []byte("Supported Protocol"))

	dc := config.DecryptConfig{
		Parameters: dp,
	}
	keyUnWrapOutput, _ := keyWrapper.UnwrapKey(&dc, keyWrapOutput)
	assert.Nil(t, keyUnWrapOutput)
	os.Remove(testConfigFile)
}

func TestKeyWrapKeyProviderGRPCSuccess(t *testing.T) {
	path := "config.json"
	os.Setenv("OCICRYPT_KEYPROVIDER_CONFIG", path)
	filecontent := `{"key-providers": {
                "keyprovider-1": {
                   "grpc": "localhost:50051"
                },
	            "keyprovider-2": {
                   "grpc": "localhost:3990"
                },
                "keyprovider-3": {
                   "cmd": {
					   "path": "/usr/lib/keyprovider-2-unwrapkey",
					   "args": []
					}
                }

        }}
        `
	tempFile, _ := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	_, err := tempFile.Write([]byte(filecontent))
	assert.NoError(t, err)
	tempFile.Close()

	optsData := []byte("data to be encrypted")

	ic, _ := keyprovider_config.GetConfiguration()
	keyWrapper := NewKeyWrapper("keyprovider-1", ic.KeyProviderConfig["keyprovider-1"])

	parameters := make(map[string][][]byte)
	parameters["keyprovider-1"] = nil
	ec := config.EncryptConfig{
		Parameters:    parameters,
		DecryptConfig: config.DecryptConfig{},
	}

	runner = TestRunner{}
	encryptingKey = []byte("passphrasewhichneedstobe32bytes!")
	decryptingKey = encryptingKey
	keyWrapOutput, err := keyWrapper.WrapKeys(&ec, optsData)
	assert.NoError(t, err)

	dp := make(map[string][][]byte)
	dp["keyprovider-1"] = append(dp["keyprovider-1"], []byte("Supported Protocol"))

	dc := config.DecryptConfig{
		Parameters: dp,
	}
	keyUnWrapOutput, err := keyWrapper.UnwrapKey(&dc, keyWrapOutput)
	assert.NoError(t, err)
	assert.Equal(t, optsData, keyUnWrapOutput)
	os.Remove(path)
}
