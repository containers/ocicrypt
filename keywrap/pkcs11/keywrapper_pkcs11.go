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
	"github.com/containers/ocicrypt/keywrap"
	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
	"strings"
)

var (
	KeyLabel   = "imgenc"
	OAEPParams = &pkcs11.OAEPParams{
		HashAlg:    pkcs11.CKM_SHA_1,
		MGF:        pkcs11.CKG_MGF1_SHA1,
		SourceType: pkcs11.CKZ_DATA_SPECIFIED,
		SourceData: nil,
	}
)

type pkcs11KeyWrapper struct {
}

func NewKeyWrapper() keywrap.KeyWrapper {
	return &pkcs11KeyWrapper{}
}

func (kw pkcs11KeyWrapper) GetAnnotationID() string {
	return "org.opencontainers.image.enc.keys.experimental.pkcs11"
}

func (kw pkcs11KeyWrapper) WrapKeys(ec *config.EncryptConfig, optsData []byte) ([]byte, error) {
	if len(ec.Parameters["modules"]) == 0 || len(ec.Parameters["pins"]) == 0 {
		return nil, nil
	}
	p11ctx, session, err := loginDevice(ec.Parameters["modules"], ec.Parameters["pins"])
	defer closeModule(p11ctx, session)
	// no recipients
	if err != nil {
		return nil, err
	}

	pub, err := getPublickey(KeyLabel, p11ctx, session)
	if err != nil {
		return nil, err
	}

	err = p11ctx.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, OAEPParams)}, pub)
	if err != nil {
		return nil, errors.Wrap(err, "Module EncryptInit error")
	}

	encrypt, err := p11ctx.Encrypt(session, optsData)
	if err != nil {
		return nil, errors.Wrap(err, "Encrypt with Module failed")
	}

	return encrypt, nil
}

func (kw pkcs11KeyWrapper) UnwrapKey(dc *config.DecryptConfig, encrypted []byte) (plain []byte, err error) {
	p11ctx, session, err := loginDevice(dc.Parameters["modules"], dc.Parameters["pins"])
	defer closeModule(p11ctx, session)

	priv, err := findObject(p11ctx, session, pkcs11.CKO_PRIVATE_KEY, KeyLabel)
	if err != nil {
		return nil, err
	}

	err = p11ctx.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, OAEPParams)}, priv)
	if err != nil {
		return nil, errors.Wrap(err, "Decrypt init failed")
	}
	plain, err = p11ctx.Decrypt(session, encrypted)

	if err != nil {
		return nil, errors.Wrap(err, "Decrypt failed")
	}

	return
}

func (kw pkcs11KeyWrapper) NoPossibleKeys(dcparameters map[string][][]byte) bool {
	return len(kw.GetPrivateKeys(dcparameters)) == 0
}

// GetPrivateKeys return private key handle
func (kw pkcs11KeyWrapper) GetPrivateKeys(dcparameters map[string][][]byte) [][]byte {
	return dcparameters["modules"]
}

// GetKeyIdsFromWrappedKeys converts the base64 encoded Packet to uint64 keyIds;
// We cannot do this with pkcs11
func (kw pkcs11KeyWrapper) GetKeyIdsFromPacket(packet string) ([]uint64, error) {
	return nil, nil
}

// GetRecipients converts the wrappedKeys to an array of recipients
// We cannot do this with pkcs11
func (kw pkcs11KeyWrapper) GetRecipients(packet string) ([]string, error) {
	return []string{"[pkcs11]"}, nil
}

// getPublickey get module public key, generate a rsa key if it doesn't exist
// TODO: experimental, use RSA Key for wrap/unwrap
func getPublickey(label string, p *pkcs11.Ctx, sh pkcs11.SessionHandle) (pub pkcs11.ObjectHandle, err error) {
	pub, err = findObject(p, sh, pkcs11.CKO_PUBLIC_KEY, label)
	if err != nil {
		pub, _, err = generateRSAKeyPair(p, sh, label, true)
	}
	return
}

func findObject(p *pkcs11.Ctx, sh pkcs11.SessionHandle, class uint, label string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := p.FindObjectsInit(sh, template); err != nil {
		return 0, errors.Wrap(err, "FindObjectsInit")
	}
	obj, _, err := p.FindObjects(sh, 1)
	if err != nil {
		return 0, errors.Wrap(err, "FindObjects")
	}
	if err := p.FindObjectsFinal(sh); err != nil {
		return 0, errors.Wrap(err, "FindObjectsFinal")
	}
	if len(obj) > 0 {
		return obj[0], nil
	}
	return 0, errors.New("Not Found Object")
}

func generateRSAKeyPair(p *pkcs11.Ctx, session pkcs11.SessionHandle, tokenLabel string, tokenPersistent bool) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}
	pbk, pvk, err := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		return 0, 0, errors.Wrap(err, "Failed to generate keypair")
	}

	return pbk, pvk, nil
}

// loginDevice login Device
func loginDevice(modules [][]byte, pins [][]byte) (ctx *pkcs11.Ctx, session pkcs11.SessionHandle, err error) {
	if len(pins) == 0 {
		return nil, 0, errors.New("Need input module pin")
	}
	pin := string(pins[0])
	pin = strings.TrimSpace(pin)

	if len(modules) > 1 {
		return nil, 0, errors.New("Just support single module")
	}
	module := string(modules[0])
	module = strings.TrimSpace(module)
	ctx = pkcs11.New(module)
	if ctx == nil {
		return nil, 0, errors.New("Please check Module path, input is: " + module)
	}

	err = ctx.Initialize()
	if err != nil {
		p11Err := err.(pkcs11.Error)
		if p11Err != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			return nil, 0, errors.Wrap(err, "Device Initialize failed")
		}
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, 0, errors.Wrap(err, "Get Slots failed")
	}

	var logged = false
	if len(slots) > 0 {
		for _, slot := range slots {
			session, err = ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
			if err != nil {
				return nil, 0, errors.Wrap(err, "Open Session failed")
			}
			err = ctx.Login(session, pkcs11.CKU_USER, pin)
			if err == nil {
				logged = true
				break
			}
		}
	}
	if !logged {
		return ctx, 0, errors.Wrap(err, "Login failed")
	}
	return ctx, session, nil
}

func closeModule(ctx *pkcs11.Ctx, session pkcs11.SessionHandle) {
	ctx.Logout(session)
	ctx.CloseSession(session)
	ctx.Destroy()
	ctx.Finalize()
}
