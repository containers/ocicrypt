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

package softhsm

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
)

// RunSoftHSMSetup runs 'softhsm_setup setup' and returns the public key that was displayed
func RunSoftHSMSetup(softhsmSetup string) (string, error) {
	cmd := exec.Command(softhsmSetup, "setup")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", errors.Wrapf(err, "%s setup failed: %s", softhsmSetup, out.String())
	}

	o := out.String()
	idx := strings.Index(o, "pkcs11:")
	if idx < 0 {
		return "", errors.New("Could not find pkcs11 URI in output")
	}

	return strings.TrimRight(o[idx:], "\n "), nil
}

// RunSoftHSMGetPubkey runs 'softhsm_setup getpubkey' and returns the public key
func RunSoftHSMGetPubkey(softhsmSetup string) (string, error) {
	cmd := exec.Command(softhsmSetup, "getpubkey")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", errors.Wrapf(err, "%s getpubkey failed: %s", softhsmSetup, out.String())
	}

	return out.String(), nil
}

// RunSoftHSMTeardown runs 'softhsm_setup teardown
func RunSoftHSMTeardown(softhsmSetup string) {
	cmd := exec.Command(softhsmSetup, "teardown")
	_ = cmd.Run()
}
