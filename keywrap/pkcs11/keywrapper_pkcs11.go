package pkcs11

import (
	"fmt"
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
	return "org.opencontainers.image.enc.keys.pkcs11"
}

func (kw pkcs11KeyWrapper) WrapKeys(ec *config.EncryptConfig, optsData []byte) ([]byte, error) {
	// no recipients
	if len(ec.Parameters["modules"]) == 0 || len(ec.Parameters["pin"]) == 0 {
		return nil, nil
	}
	p11ctx, session, err := loginDevice(ec.Parameters["modules"], ec.Parameters["pin"])
	if err != nil {
		return nil, err
	}

	pub, _ := getRSA(KeyLabel, p11ctx, session)

	err = p11ctx.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, OAEPParams)}, pub)
	encrypt, err := p11ctx.Encrypt(session, optsData)
	if err != nil {
		return nil, errors.Wrap(err, "Encrypt with Module failed")
	}

	closeModule(p11ctx, session)
	return encrypt, nil
}

func (kw pkcs11KeyWrapper) UnwrapKey(dc *config.DecryptConfig, encrypted []byte) (plain []byte, err error) {
	p11ctx, session, err := loginDevice(dc.Parameters["modules"], dc.Parameters["pin"])

	priv, err := findObject(p11ctx, session, pkcs11.CKO_PRIVATE_KEY, KeyLabel)

	err = p11ctx.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, OAEPParams)}, priv)
	if err != nil {
		return nil, errors.Wrap(err, "Decrypt init failed")
	}
	plain, err = p11ctx.Decrypt(session, encrypted)

	if err != nil {
		return nil, errors.Wrap(err, "Decrypt failed")
	}

	closeModule(p11ctx, session)
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

// getRSA generate a rsa key if it doesn't exist
func getRSA(label string, p *pkcs11.Ctx, sh pkcs11.SessionHandle) (pub, priv pkcs11.ObjectHandle) {
	pub, err := findObject(p, sh, pkcs11.CKO_PUBLIC_KEY, label)
	if err != nil {
		pub, priv = generateRSAKeyPair(p, sh, label, true)
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

func generateRSAKeyPair(p *pkcs11.Ctx, session pkcs11.SessionHandle, tokenLabel string, tokenPersistent bool) (pkcs11.ObjectHandle, pkcs11.ObjectHandle) {
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
	pbk, pvk, e := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if e != nil {
		fmt.Printf("failed to generate keypair: %s\n", e.Error())
	}

	return pbk, pvk
}

// loginDevice login Device and use the slot[0]
func loginDevice(modules [][]byte, pins [][]byte) (ctx *pkcs11.Ctx, session pkcs11.SessionHandle, err error) {
	if len(pins) == 0 {
		return nil, 0, errors.New("Need input module pin")
	}
	pin := string(pins[0])
	pin = strings.TrimSpace(pin)

	if len(modules) > 1 {
		return nil, 0, errors.New("Just support *one* module")
	}
	module := string(modules[0])
	module = strings.TrimSpace(module)
	if module == "" {
		return nil, 0, errors.New("Please check Module path, input is: " + module)
	}

	ctx = pkcs11.New(module)
	err = ctx.Initialize()
	if err != nil {
		return nil, 0, errors.Wrap(err, "Device Initialize failed")
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
	defer ctx.CloseSession(session)
	defer ctx.Logout(session)
	defer ctx.Destroy()
	defer ctx.Finalize()
}
