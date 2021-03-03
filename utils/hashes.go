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

package utils

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
)

// GetInitalPreviousLayersDigest returns the initial value for previousLayersDigest
func GetInitialPreviousLayersDigest() []byte {
	digest := sha256.Sum256(nil)
	return digest[:]
}

// GetNewLayersDigest calculates the new layer digest from the previousLayersDigest and the layerDigest.
func GetNewLayersDigest(previousLayersDigest []byte, layerDigest digest.Digest) ([]byte, error) {
	newDigest := sha256.New()
	// never returns an error but linter requires us to look at it
	_, err := newDigest.Write(previousLayersDigest)
	if err != nil {
		return nil, err
	}

	digest, err := hex.DecodeString(layerDigest.Encoded())
	if err != nil {
		return nil, errors.Wrap(err, "Hex decoding digest failed")
	}
	_, err = newDigest.Write(digest)
	return newDigest.Sum(nil), err
}
