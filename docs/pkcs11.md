# Ocicrypt Pkcs11 (Experimental)

Ocicrypt supports the use of an experimental pkcs11-based protocol. This allows the ability to encrypt a container image so that it can be decrypted by a key which resides in a Hardware Security Module (HSM). In this document, we will go through a tutorial on how to setup and use this capability with a software emulated HSM, SoftHSM. See [this guide](https://github.com/containers/ocicrypt/blob/main/docs/cex-ep11.md) on how to do this with an IBM CryptoExpress HSM instead.

This tutorial is done on Ubuntu.

# Setting up SoftHSM

## Requirements

On top of the generic ocicrypt requirements, install the following packages:
```
sudo apt install -y softhsm2 p11-kit gnutls-bin
```


## Create SoftHSM Configuration

We will setup the configurations and folders for SoftHSM. We will use the home directory to store this configuration.

### Create config directories and sub directories
```
mkdir -p ${HOME}/.config/softhsm2/tokens
```
### Write configuration file
```
cat > ${HOME}/.config/softhsm2/softhsm2.conf <<EOF
directories.tokendir = ${HOME}/.config/softhsm2/tokens
objectstore.backend = file
log.level = DEBUG
slots.removable = false
EOF
```


# Creating a pkcs11 key in SoftHSM

To create a key, we need to first create a token, and then generate the private key for the token.

# Create token for SoftHSM

Set the configuration file to the one created above. All subsequent commands should be run with this environment variable set.
```
export SOFTHSM2_CONF=${HOME}/.config/softhsm2/softhsm2.conf
```

Create a token
```
softhsm2-util --init-token --free --label mytoken --pin my-pin --so-pin my-pin
```
The output should look like the following:
```
Slot 0 has a free/uninitialized token.
The token has been initialized and is reassigned to slot 1151822331
```

We can then verify the token is created.

```
p11tool --list-tokens
```

Output:
```
Token 0:
	URL: pkcs11:model=p11-kit-trust;manufacturer=PKCS%2311%20Kit;serial=1;token=System%20Trust
	Label: System Trust
	Type: Trust module
	Flags: uPIN uninitialized
	Manufacturer: PKCS#11 Kit
	Model: p11-kit-trust
	Serial: 1
	Module: p11-kit-trust.so


Token 1:
	URL: pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=ee777786c4a769fb;token=mytoken
	Label: mytoken
	Type: Generic token
	Flags: RNG, Requires login
	Manufacturer: SoftHSM project
	Model: SoftHSM v2
	Serial: ee777786c4a769fb
	Module: /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
```

We will find the token that we created with label mytoken and copy the "Token URI", which is refers to the `URL` field of a token. In this case, the pkcs url is `pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=ee777786c4a769fb;token=mytoken`. We note that this is the token for `SoftHSM v2` (the later token).

# Now create the private RSA key

Next we have to create a private key for this token. 

Note: For p11tool commands we need the `GNUTLS_PIN` env. variable (could also pass via command line but this is more secure). For this tutorial, we will use the environment variable.

Run
```
export GNUTLS_PIN=my-pin
```

We will now create a key pair for this associated token in the HSM.

Note: ALWAYS  protect pkcs11 URIs with single quotes. (i.e. '<uri>'), If you are not using the `GNUTLS_PIN` environment variable, when prompted for the pin, enter the pin used above (in our example, it is `my-pin`).

Run
```
p11tool --login --generate-privkey=rsa --label imagekey 'pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=ee777786c4a769fb;token=mytoken'
```

The output will be contain the associated public key for the generated private key. Take note of this. We will store it as `pubkey.pem`
```
warning: no --outfile was specified and the generated public key will be printed on screen.
Generating an RSA key...
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAxDDWvGOBdUhqvujrk3ty
WRGNKOP2VR0TQW1uUP6bECLpqFIPljf8HzniNR28MscP5fp/qsU6XwoMZWJh0VDK
rzh0MzRAoSi0XMMtdYqoKjpWJxZWkTsahhjv2N/2khduvoIFwfL9Xoy+AjWP01no
EFC1ctXv0jP6V+HkSfW3GQVYMg35ix5UKBeHdhI1GAA0Y0V1w+O1CJONtHBVbtb1
ts9nU3Eq5LUujHVYJJ8YbnfXU7AQQ7mVUgsA0S6A9YT0FY7ljU5K47zCYwO++q+i
ui6lGabbiCNjJhiUrhQTCyeOqaKLYfxBAWOuuBLKnWaKnL2baC1h0A5H9AHcPQYh
fRHARf8SJ4Zo+aWEFMTK8xStlg5aHHhm1dKVUKamIf6rDJoMOI1HczzkKXe20whU
G+rQj80brlTKVXtAlPLlb7zgM9YI3fPXlGSqgbVHakYiN7Hkj26c+1gwK9dShZ3p
Ecq2jPcQiQpyOEr2xppwmPa5daJm00Syr3wuXxu4J0+HAgMBAAE=
-----END PUBLIC KEY-----
```

We now need to find the pkcs11 URI of the private key by using the URI of the token
```
p11tool --login --list-privkeys 'pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=ee777786c4a769fb;token=mytoken'
```

The output will be like the following:
```
Token 'mytoken' with URL 'pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=ee777786c4a769fb;token=mytoken' requires user PIN
Enter PIN:
Object 0:
	URL: pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=ee777786c4a769fb;token=mytoken;id=%A9%8B%58%89%89%C7%A9%01%59%5A%85%9D%5D%6A%FF%C3%E4%57%E2%16;object=imagekey;type=private
	Type: Private key (RSA-3072)
	Label: imagekey
	Flags: CKA_WRAP/UNWRAP; CKA_PRIVATE; CKA_NEVER_EXTRACTABLE; CKA_SENSITIVE;
	ID: a9:8b:58:89:89:c7:a9:01:59:5a:85:9d:5d:6a:ff:c3:e4:57:e2:16
```

Now take the "URL" field from the object above "pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=ee777786c4a769fb;token=mytoken;id=%A9%8B%58%89%89%C7%A9%01%59%5A%85%9D%5D%6A%FF%C3%E4%57%E2%16;object=imagekey;type=private",
and append "?pin-value=my-pin&module-name=softhsm2" to it, getting the following. We will be using this in the next step. We refer to this as "KEY_URI".

```
pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=ee777786c4a769fb;token=mytoken;id=%A9%8B%58%89%89%C7%A9%01%59%5A%85%9D%5D%6A%FF%C3%E4%57%E2%16;object=imagekey;type=private?pin-value=my-pin&module-name=softhsm2
```


# Setting up PKCS11 for ocicrypt


# Configuring pkcs11 modules for ocicrypt users

In order to use pkcs11 with the ocicrypt library, there are several configuration and key conventions that need to be noted. 

Encrypting/decrypting with ocicrypt's pkcs11 keywrap module consists of two parts. One is the metadata of the key to use for encryption/decryption (i.e. similar to how keys are passed in via using other ocicrypt protocols such as  jwe:, pkcs11:), and configuring the HSM modules on the host.

## Creating pkcs11 key configuration. 

This is the representation of the key that the key-wrap module will use to talk to the HSM. It can be passed in like any other protocol key, i.e. pkcs11:myPkcs11Key.yaml. Note that this key can act as a private key and public key for ocicrypt. It is also possible to encrypt with a regular public key (as was output in the above step when generating the key).

```
cat > myPkcs11Key.yaml <<EOF
pkcs11:
  uri: pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=ee777786c4a769fb;token=mytoken;id=%A9%8B%58%89%89%C7%A9%01%59%5A%85%9D%5D%6A%FF%C3%E4%57%E2%16;object=imagekey;type=private?pin-value=my-pin&module-name=softhsm2
module:
  env:
    SOFTHSM2_CONF: ${HOME}/.config/softhsm2/softhsm2.conf
EOF
```

## Configuring HSM modules

Because communication with HSM modules are usually done with a external module, there is an additional configuration to tell the user of ocicrypt how to talk to the HSM modules on the host. This is also important to configure correctly so that only authorized modules are run. 

This configuration is done via an environment variable `OCICRPYT_CONFIG`. Here is the behavior of this configuration:
- If the environment variable is not set, it indicates that no HSM modules should be allowed
- If the environment variable is set to "internal", it uses policy that allows to access most pkcs11 modules. It holds default module search paths that should cover many distros ([details here](https://github.com/containers/ocicrypt/blob/2ddd51f10d6d15ce99e020ec35729ea741d32f2a/crypto/pkcs11/pkcs11helpers.go#L134))
- Else, it is treated as a filepath, where it contains the configuration of where modules are, and which are allowed. More details on how to configure this can be seen [here](https://github.com/containers/ocicrypt/blob/master/config/pkcs11config/config.go#L38).



# Encrpyting/Decrypting examples

We will show how this can be used with users of ocicrypt. After performing the steps above, we are ready to encrypt/decrypt with the pkcs11 protocol. The capabilities that the tools provide will be:

- Encrypting an image with ocicrypt pkcs11 protocol using a public key (PEM)
- Encrypting an image with ocicrypt pkcs11 protocol using a pkcs11 key configuration (requires HSM access)
- Decrypting an image with ocicrypt pkcs11 protocol using a pkcs11 key configuration (requires HSM access)

We will go through 3 consumers of the ocicrypt library.
- [containerd/imgcrypt](http://github.com/containerd/imgcrypt)
- [skopeo](https://github.com/containers/skopeo)
- [buildah](https://github.com/containers/buildah)

NOTE: only builds that use ocicrypt v1.1.0 and above will have pkcs11 experimental support.


We remember that we created two files above, pubkey.pem and `myPkcs11Key.yaml`. For the following command executions, we assume that the plaintext image has already been downloaded. We are using the image `docker.io/library/alpine:latest`.


## containerd/imgcrypt

With containerd imgcrypt, the tool to encrypt/decrypt images is `ctr-enc`. 

### Encryping with Public Key

```
$ OCICRYPT_CONFIG=internal ./bin/ctr-enc images encrypt --recipient pkcs11:myPkcs11Key.yaml docker.io/library/alpine:latest alpine.enc.pkcs11key:latest
Encrypting docker.io/library/alpine:latest to alpine.enc.pkcs11key:latest
Note: Pkcs11 support is currently experimental
```

### Encryping with PKCS11 Key Configuration

```
$ OCICRYPT_CONFIG=internal ./bin/ctr-enc images encrypt --recipient pkcs11:pubkey.pem docker.io/library/alpine:latest alpine.enc.pkcs11pubkey:latest
Encrypting docker.io/library/alpine:latest to alpine.enc.pkcs11pubkey:latest
Note: Pkcs11 support is currently experimental
```


### Decrypting with both images encrypted above with PKCS11 Key Configuration 

```
$ OCICRYPT_CONFIG=internal ./bin/ctr-enc images decrypt --key myPkcs11Key.yaml alpine.enc.pkcs11key:latest alpine.dec.pkcs11key:latest
Decrypting alpine.enc.pkcs11key:latest to alpine.dec.pkcs11key:latest

$ OCICRYPT_CONFIG=internal ./bin/ctr-enc images decrypt --key myPkcs11Key.yaml alpine.enc.pkcs11pubkey:latest alpine.dec.pkcs11pubkey:latest
Decrypting alpine.enc.pkcs11pubkey:latest to alpine.dec.pkcs11pubkey:latest
```

## skopeo

### Encryping with Public Key

```
$ OCICRYPT_CONFIG=internal skopeo copy --encryption-key pkcs11:pubkey.pem oci:alpine:latest oci:alpine_enc_pkcs11pubkey:latest
Calling create crypto config
Getting image source signatures
Copying blob df20fa9351a1 done
Copying config 0f5f445df8 done
Writing manifest to image destination
Storing signatures
```

### Encryping with PKCS11 Key Configuration

```
$ OCICRYPT_CONFIG=internal skopeo copy --encryption-key pkcs11:myPkcs11Key.yaml  oci:alpine:latest oci:alpine_enc_pkcs11key:latest
Calling create crypto config
Getting image source signatures
Copying blob df20fa9351a1 done
Copying config 0f5f445df8 done
Writing manifest to image destination
Storing signatures
```


### Decrypting with both images encrypted above with PKCS11 Key Configuration 

```
$ OCICRYPT_CONFIG=internal skopeo copy --decryption-key myPkcs11Key.yaml  oci:alpine_enc_pkcs11pubkey:latest oci:alpine_dec_pkcs11pubkey:latest
Getting image source signatures
Copying blob 32176ff73954 done
Copying config 0f5f445df8 done
Writing manifest to image destination
Storing signatures


$ OCICRYPT_CONFIG=internal skopeo copy --decryption-key myPkcs11Key.yaml  oci:alpine_enc_pkcs11key:latest oci:alpine_dec_pkcs11key:latest
Getting image source signatures
Copying blob 31c20e72694c done
Copying config 0f5f445df8 done
Writing manifest to image destination
Storing signatures
```

## buildah


### Encryping with Public Key
```
$ OCICRYPT_CONFIG=internal ./bin/buildah push --encryption-key pkcs11:pubkey.pem docker.io/library/alpine:latest oci:alpine_enc_pkcs11pubkey:latest
Getting image source signatures
Copying blob 50644c29ef5a done
Copying config 0f5f445df8 done
Writing manifest to image destination
Storing signatures
```
### Encryping with PKCS11 Key Configuration
```
$ OCICRYPT_CONFIG=internal ./bin/buildah push --encryption-key pkcs11:myPkcs11Key.yaml  docker.io/library/alpine:latest oci:alpine_enc_pkcs11key:latest
Getting image source signatures
Copying blob 50644c29ef5a done
Copying config 0f5f445df8 done
Writing manifest to image destination
Storing signatures
```

### Decrypting with both images encrypted above with PKCS11 Key Configuration 
```
$ OCICRYPT_CONFIG=internal ./bin/buildah pull --decryption-key myPkcs11Key.yaml  oci:alpine_enc_pkcs11pubkey:latest
Getting image source signatures
Copying blob dc5e8c1e77b5 done
Copying config 0f5f445df8 done
Writing manifest to image destination
Storing signatures
0f5f445df8ccbd8a062ad3d02d459e8549d9998c62a5b7cbf77baf68aa73bf5b

$ OCICRYPT_CONFIG=internal ./bin/buildah pull --decryption-key myPkcs11Key.yaml  oci:alpine_enc_pkcs11key:latest
Getting image source signatures
Copying blob 9f61ec599643 done
Copying config 0f5f445df8 done
Writing manifest to image destination
Storing signatures
0f5f445df8ccbd8a062ad3d02d459e8549d9998c62a5b7cbf77baf68aa73bf5b
```
