# OCIcrypt with Enterprise PKCS #11 on IBM CryptoExpress

Note: This is a tutorial on using IBM CryptoExpress as an example of use of the ocicrypt library. This is not an endorsement or recommendation to use IBM CryptoExpress.

OCIcrypt supports the use of an experimental PKCS #11-based protocol.
The [main documentation on this topic](https://github.com/containers/ocicrypt/blob/main/docs/pkcs11.md) explains how to use this with SoftHSM2, a software emulation of a hardware security module (HSM).
However, it is also possible to use an [IBM CryptoExpress HSM](https://www.ibm.com/security/cryptocards) in Enterprise PKCS #11 (EP11) mode, available for IBM Z and x64, together with the [openCryptoki library](https://github.com/opencryptoki/opencryptoki).
This document provides some tips on how to set this up compared to the SoftHSM2 setup.

This guide focuses on EP11 mode, but this should also be possible to accomplish in CCA mode and even in Accelerator mode (despite the unavailability of Secure Keys in the latter).

The steps in this tutorial were tested with Ubuntu 20.04 on an IBM z15 LPAR with a CEX7S Crypto Card (IBM 4769).

## Setup pre-requirements

On Linux on IBM Z & LinuxONE, you can check your hardware with `lszcrypt` from [s390-tools](https://github.com/ibm-s390-linux/s390-tools) (package name varies among Linux distributions).
You might have to `modprobe ap` if the appropriate module is not loaded.
For Enterprise PKCS #11, you should have an online `EP11-Coproc`, which might already be configured.
Otherwise, you must first assign adapters and domains in the Support Element/Hardware Management Console, and/or configure them as EP11 (`CEX?P`) rather than CCA or accelerator.
Administrator certificates and master keys must also be set up.
For more information, see IBM's documentation on [Preparing](https://www.ibm.com/docs/en/linux-on-systems?topic=stack-preparing-crypto-express-ep11-coprocessor) and [Setting a master key on the Crypto Express EP11 coprocessor](https://www.ibm.com/docs/en/linux-on-systems?topic=stack-setting-master-key-crypto-express-ep11-coprocessor).

## Software requirements

From your distribution, install e.g.
```
apt install -y gnutls-bin opencryptoki p11-kit
```

Additionally, you will need the EP11 host library (`libep11` or `ep11-host` depending on package format), which is not in any distribution.
You can get it from [the software downloads for cryptographic hardware](https://www.ibm.com/security/cryptocards/pciecc4/software) and install it with `dpkg -i`/`rpm -i`.

## openCryptoki configuration

Register openCryptoki as a module for p11-kit by entering the path of the `libopencryptoki.so` file (location varies among Linux distributions), e.g.
```
cat << EOF | sudo tee /etc/pkcs11/modules/opencryptoki.module
module: /usr/lib/s390x-linux-gnu/pkcs11/libopencryptoki.so
EOF
```

Depending on the hardware you have available, you should now see an entry with a model name of `IBM EP11Tok` in the output of
```
p11tool --list-tokens
```

(requires root to see all), e.g.
```
...
Token 4:
        URL: pkcs11:model=IBM%20EP11Tok;manufacturer=IBM%20Corp.;serial=93AAA1XX22347171;token=IBM%20OS%20PKCS%2311
        Label: IBM OS PKCS#11
        Type: Generic token
        Flags: RNG, Requires login, Uninitialized
        Manufacturer: IBM Corp.
        Model: IBM EP11Tok
        Serial: 93AAA1XX22347171
        Module: /usr/lib/s390x-linux-gnu/pkcs11/libopencryptoki.so
```

You will need the appropriate `URL:` field throughout the process.
All entries listed by `pkcsconf -t` should also be here.
You can customize the configuration in `/etc/opencryptoki`, e.g. to assign specific adapters to openCryptoki (and, consequently, p11) slots.
You will have to `systemctl restart pkcsslotd` thereafter.
Again, see the [IBM Documentation](https://www.ibm.com/docs/en/linux-on-systems?topic=315-configuring-opencryptoki-ep11-support) for more information.

## Preparing the token with a PIN

All tokens require a PIN to use (similar to SoftHSM2).
Assuming the URL from above (yours will be different!), it is set with:
```
p11tool --initialize-pin 'pkcs11:model=IBM%20EP11Tok;manufacturer=IBM%20Corp.;serial=93AAA1XX22347171;token=IBM%20OS%20PKCS%2311'
```

This will require the Security Officer PIN, which is 87654321 by default (although it should be changed in a production environment).

## Continuing as usual

From here on out, the steps are identical with the steps documented in the SoftHSM2 PKCS #11 tutorial.
Continue at ["Now create the private RSA key"](https://github.com/containers/ocicrypt/blob/main/docs/pkcs11.md#now-create-the-private-rsa-key), using the appropriate URL as above.

### Some things to watch out for

- The `module-name` should be `opencryptoki` rather than `softhsm2`.
- You will not need the `SOFTHSM2_CONF` entry in the key configuration.
- `OCICRYPT_CONFIG` can be set to `internal`.
