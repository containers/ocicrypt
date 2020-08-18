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
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
)

type SoftHSMSetup struct {
	statedir string
}

func NewSoftHSMSetup() *SoftHSMSetup {
	return &SoftHSMSetup{}
}

// GetConfigFilename returns the path to the softhsm configuration file; this function
// may only be called after RunSoftHSMSetup
func (s *SoftHSMSetup) GetConfigFilename() string {
	return s.statedir + "/softhsm2.conf"
}

// RunSoftHSMSetup runs 'softhsm_setup setup' and returns the public key that was displayed
func (s *SoftHSMSetup) RunSoftHSMSetup(softhsmSetup string) (string, error) {
	statedir, err := ioutil.TempDir("", "ocicrypt")
	if err != nil {
		return "", errors.Wrapf(err, "Could not create temporary directory fot softhsm state")
	}
	s.statedir = statedir

	cmd := exec.Command(softhsmSetup, "setup")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Env = append(cmd.Env, "SOFTHSM_SETUP_CONFIGDIR="+s.statedir)
	err = cmd.Run()
	if err != nil {
		os.RemoveAll(s.statedir)
		return "", errors.Wrapf(err, "%s setup failed: %s", softhsmSetup, out.String())
	}

	o := out.String()
	idx := strings.Index(o, "pkcs11:")
	if idx < 0 {
		os.RemoveAll(s.statedir)
		return "", errors.New("Could not find pkcs11 URI in output")
	}

	return strings.TrimRight(o[idx:], "\n "), nil
}

// RunSoftHSMGetPubkey runs 'softhsm_setup getpubkey' and returns the public key
func (s *SoftHSMSetup) RunSoftHSMGetPubkey(softhsmSetup string) (string, error) {
	cmd := exec.Command(softhsmSetup, "getpubkey")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Env = append(cmd.Env, "SOFTHSM_SETUP_CONFIGDIR="+s.statedir)
	err := cmd.Run()
	if err != nil {
		return "", errors.Wrapf(err, "%s getpubkey failed: %s", softhsmSetup, out.String())
	}

	return out.String(), nil
}

// RunSoftHSMTeardown runs 'softhsm_setup teardown
func (s *SoftHSMSetup) RunSoftHSMTeardown(softhsmSetup string) {
	cmd := exec.Command(softhsmSetup, "teardown")
	cmd.Env = append(cmd.Env, "SOFTHSM_SETUP_CONFIGDIR="+s.statedir)
	_ = cmd.Run()

	os.RemoveAll(s.statedir)
}
