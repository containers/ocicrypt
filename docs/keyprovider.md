# Ocicrypt keyprovider protocol

Ocicrypt supports the use of a key-provider protocol. This allows the ability to encrypt and decrypt container image using the key that can be retrieved from any key management service.
The config file consists for list of protocols that can be used for either encryption or decryption. User can implement either a binary executable or grpc server for fetching the wrapped(during image encryption) or unwrapped key(during image decryption) using any key management service.

## Example of config file

```code
    {
        "key-providers": {
            "isecl": {
                "path": "/usr/lib/ocicrypt-isecl",
                "args": []
            },
            "keyprotect": {
                "path": "/usr/lib/ocicrypt-keyprotect",
                "args": []
            },
            "keyvault": {
                "grpc": "localhost:50051"
            }
        }
    }
```

## Encrpyting/Decrypting examples

1. Build a sample golang application/binary -> https://gist.github.com/lumjjb/5ade3e3cb7d8613c0989bfb41569fe59

2. Configure the ${HOME}/ocirypt.conf like below
```code
    $ cat /home/vagrant/ocicrypt.conf
    {
        "key-providers": {
            "simplecrypt": {
                "cmd": {
                    "path":"/home/vagrant/simplecrypt",
                    "args": []
                }
            }
        }
    }   
```

3. Prepare a sample image to encrypt or use an already built image from any public/private registry by pulling it into local repository and Image should be oci complaint
```code
    $ skopeo copy docker://docker.io/library/alpine:latest oci:alpine
    Getting image source signatures
    Copying blob 05e7bc50f07f done
    Copying config 5c41fd95ee done
    Writing manifest to image destination
    Storing signatures
```

4. Encrypt the image as shown below
```code
    $ OCICRYPT_KEYPROVIDER_CONFIG=/home/vagrant/ocicrypt.conf bin/skopeo copy --encryption-key provider:simplecrypt:abc  oci:alpine oci:encrypted
    Getting image source signatures
    Copying blob 05e7bc50f07f done
    Copying config 5c41fd95ee done
    Writing manifest to image destination
    Storing signatures
```

5. Decrypt the image as shown below
```code
    $ OCICRYPT_KEYPROVIDER_CONFIG=/home/vagrant/ocicrypt.conf bin/skopeo copy --decryption-key provider:simplecrypt:extra-params oci:encrypted oci:decrypted
    
    Getting image source signatures
    Copying blob 4029b2314db9 done
    Copying config 5c41fd95ee done
    Writing manifest to image destination
    Storing signatures
```
