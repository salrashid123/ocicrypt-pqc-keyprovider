## OCICrypt Container Image Post Quantum Cryptography Provider

Basic [OCICrypt KeyProvider](https://github.com/containers/ocicrypt/blob/main/docs/keyprovider.md) for post quantum cryptography (PQC)

This repo includes a prebuilt and customizeable keyprovider which can be used to encrypt OCI Containers.

[OCICrypt](https://github.com/containers/ocicrypt) includes specifications to encrypt an OCI Container image and within that, the keyprovider protocol allows wrapping of the actual key used to encrypt the layer to an external binary.

The binary in this question accepts a keyprovider request and inturn wraps the layer symmetric encryption key using a hosted KMS key.

Basically, a Post Quantum `ML-KEM` keypair wraps the symmetric key that is used to encrypt the layer itself.

The private key can be either based off of

* a raw PEM file accessible by the provider

or

* a key on a `KM`S system (eg, [GCP KMS](https://docs.cloud.google.com/kms/docs/key-encapsulation-mechanisms))

This sample is based off of the [simple-oci-keyprovider](https://github.com/lumjjb/simple-ocicrypt-keyprovider.git) repo which demonstrates the protocol involved.

For more information, see 

- [Advancing container image security with encrypted container images](https://developer.ibm.com/articles/advancing-image-security-encrypted-container-images/)
- [Enabling advanced key usage and management in encrypted container images](https://developer.ibm.com/articles/enabling-advanced-key-usage-and-management-in-encrypted-container-images/)
- [Container Image Encryption & Decryption in the CoCo project](https://medium.com/kata-containers/confidential-containers-and-encrypted-container-images-fc4cdb332dec)

This repo build on top of

* [Go-PQC-Wrapping - Go library for encrypting data using Post Quantum Cryptography (PQC)](https://github.com/salrashid123/go-pqc-wrapping)

Anyway, this repo shows basic OCI container encryption using both files and GCP KMS

* [Setup Baseline](#setup-baseline)
* [Setup Binary OCI PQC provider](#setup-binary-oci-pqc-provider)
* [Setup gRPC OCI PQC provider](#setup-grpc-oci-pqc-provider)

![images/encrypted.png](images/encrypted.png)

---

## Setup

Showing how this works involves a number of steps so its not that much of a quickstart but once its setup, you can skip to the "encrypt/decrypt" section below.

install

* [skopeo](https://github.com/containers/skopeo/blob/main/install.md)
* docker
* [imgcrypt](https://github.com/containerd/imgcrypt.git)
* [nerdctl](https://github.com/containerd/nerdctl)

## Build plugin

(or download the binary from the "releases" page)

```bash
cd plugin
go build -o /tmp/pqc_oci_crypt .
```

---

## QuickStart

### Run local Registry

Run a local docker registry just to test

```bash
cd example

docker run  -p 5000:5000 -v `pwd`/certs:/certs \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/localhost.crt \
  -e REGISTRY_HTTP_TLS_KEY=/certs/localhost.key  docker.io/registry:2
```

### Using ML-KEM Files

Note, if you just want to test with the built-in MLKEM keypairs in this repo, skip this step and go to the `Encrypt` section below

If you just wanted generate a new ML KEM Public/private PEM key files

```bash
cd example/

### make sure you have openssl setup, if not you can use the docker image below
$ openssl -version
    OpenSSL 3.5.0-dev  (Library: OpenSSL 3.5.0-dev )

### if you don't have that version of openssl, you can use this docker image from
#####  https://github.com/salrashid123/pqc_scratchpad?tab=readme-ov-file#docker-images
# mkdir /tmp/pqc
# docker run -v /dev/urandom:/dev/urandom  -v /tmp/pqc:/tmp/pqc -ti salrashid123/openssl-pqs:3.5.0-dev    

### generate ML-KEM-768
openssl genpkey  -algorithm mlkem768 \
   -provparam ml-kem.output_formats=bare-seed \
   -out /tmp/pqc/priv-ml-kem-768-bare-seed.pem

openssl pkey  -in /tmp/pqc/priv-ml-kem-768-bare-seed.pem  -pubout -out /tmp/pqc/pub-ml-kem-768.pem
cp /tmp/pqc/pub-ml-kem-768.pem certs/pub-ml-kem-768.pem
cp /tmp/pqc/priv-ml-kem-768-bare-seed.pem certs/priv-ml-kem-768-bare-seed.pem
```

#### Encrypt

In a new shell, specify the path to the config file by applying the b64encoded public key PEM format directly

```bash
cd example/
export PQPUB=`openssl enc -base64 -A -in certs/pub-ml-kem-768.pem`
envsubst < "ocicrypt_encrypt.tmpl" > "ocicrypt.json"
```

the json that is applied looks like this:

```json
{
  "key-providers": {
    "pqccrypt": {
      "cmd": {
        "path": "/tmp/pqc_oci_crypt",
        "args": [   
          "--pqcURI","pqc://pq?pub=$PQPUB"       
        ]
      }
    }
  }
}
```

then

```bash
cd example/
export OCICRYPT_KEYPROVIDER_CONFIG=`pwd`/ocicrypt.json
export SSL_CERT_FILE=`pwd`/certs/tls-ca-chain.pem

# add to /etc/hosts
# 127.0.0.1 registry.domain.com

## using dockerhub
skopeo copy --encrypt-layer=-1 \
  --encryption-key="provider:pqccrypt:pqc://pq?pub=$PQPUB" \
   docker://docker.io/salrashid123/app docker://registry.domain.com:5000/app:encrypted
```

The last layer on the image shjould be encrypted 

```bash
skopeo inspect docker://registry.domain.com:5000/app:encrypted
```

#### Decrypt

To decrypt via files, the ocicrypt config would look like

```json
{
  "key-providers": {
    "pqccrypt": {
      "cmd": {
        "path": "/tmp/pqc_oci_crypt",
        "args": [   
          "--pqcURI","pqc://pq?pub=$PQPUB",
          "--pqcKeyURI","pqc://pq?key=$KEY_PATH"
        ]
      }
    }
  }
}
```

you can create it like this:

```bash
cd example/
export KEY_PATH="file:///`pwd`/certs/priv-ml-kem-768-bare-seed.pem"
export PQPUB=`openssl enc -base64 -A -in certs/pub-ml-kem-768.pem`
envsubst < "ocicrypt_decrypt.tmpl" > "ocicrypt.json"
```

finally, decrypt

```bash
skopeo copy \
  --decryption-key=provider:pqccrypt:pqc://pq?key=file://`pwd`/certs/priv-ml-kem-768-bare-seed.pem \
   docker://registry.domain.com:5000/app:encrypted docker://registry.domain.com:5000/app:decrypted
```

### Using KMS

If you want to use GCP KMS where the private key exists only in GCP, first create a key pair

```bash
cd example/
gcloud kms keyrings create kem_kr --location=global

gcloud kms keys create kem_key_1 \
    --keyring kem_kr \
    --location global \
    --purpose "key-encapsulation" \
    --default-algorithm ml-kem-768 \
    --protection-level "software"

mkdir /tmp/kmspqc

gcloud kms keys versions get-public-key 1 \
    --key kem_key_1 \
    --keyring kem_kr \
    --location global  \
    --output-file /tmp/kmspqc/kem_pub.nist \
    --public-key-format nist-pqc


docker run -v /dev/urandom:/dev/urandom  -v /tmp/kmspqc:/tmp/kmspqc -ti salrashid123/openssl-pqs:3.5.0-dev    

$ { echo -n "MIIEsjALBglghkgBZQMEBAIDggShAA==" | base64 -d ; cat /tmp/kmspqc/kem_pub.nist; } \
   | openssl pkey -inform DER -pubin -pubout -out /tmp/kmspqc/pub-ml-kem-768-kms.pem
```

#### Encrypt

To encrypt, set the ocicrypt config file:

```bash
export PQPUB=`openssl enc -base64 -A -in /tmp/kmspqc/pub-ml-kem-768-kms.pem`   
envsubst < "ocicrypt-kms_encrypt.tmpl" > "ocicrypt.json"

skopeo copy --encrypt-layer=-1 \
  --encryption-key="provider:pqccrypt:pqc://pq?pub=$PQPUB" \
   docker://docker.io/salrashid123/app docker://registry.domain.com:5000/app:encrypted
```

Inspect the decrypted image

```bash
skopeo inspect docker://registry.domain.com:5000/app:decrypted
```

#### Decrypt

To decrypt via kms, you need access to the private key via GCP `Application Default Credentials` file by setting the startup argument `--adc`.

You can use this setting to direct the GCP encryption to use [Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation) or if omitted the default environment ADC is used

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/svc_account.json
export PROJECT_ID=`gcloud config get-value core/project`    

envsubst < "ocicrypt-kms_decrypt.tmpl" > "ocicrypt.json"

skopeo copy \
  --decryption-key=provider:pqccrypt:"pqc://pq?key=gcpkms://projects/$PROJECT_ID/locations/global/keyRings/kem_kr/cryptoKeys/kem_key_1/cryptoKeyVersions/1"   \
   docker://registry.domain.com:5000/app:encrypted docker://registry.domain.com:5000/app:decrypted
```

---

### gRPC OCI PQC provider

Included in this repo is a grpc service which you can use as the key provider.

Basically, its the same as calling the binary except that it calls a gRPC server you run separately.

Note, the existing implementation _does not use TLS_!.  You would definitely want to secure access to this service.

To use, start the server


#### Using Files

```bash
cd example/

export KEY_PATH="file:///`pwd`/certs/priv-ml-kem-768-bare-seed.pem"
export PQPUB=`openssl enc -base64 -A -in certs/pub-ml-kem-768.pem`
export GOOGLE_APPLICATION_CREDENTIALS=/home/srashid/gcp_misc/certs/cicd-test-sa.json
export PROJECT_ID=`gcloud config get-value core/project`   

cd grpc/
go run server.go  --pqcURI="pqc://pq?pub=$PQPUB" \
  --pqcKeyURI="pqc://pq?key=$KEY_PATH" \
  --adc="$GOOGLE_APPLICATION_CREDENTIALS"

cd example/
export SSL_CERT_FILE=certs/tls-ca-chain.pem

skopeo copy --encrypt-layer -1 \
  --encryption-key=provider:grpc-keyprovider:pqccrypt:pqc://pq?pub=$PQPUB \
   docker://docker.io/salrashid123/app docker://registry.domain.com:5000/app:encrypted

skopeo copy --dest-tls-verify=false \
  --decryption-key=provider:grpc-keyprovider:pqc://pq?pub=$PQPUB \
    docker://registry.domain.com:5000/app:encrypted docker://registry.domain.com:5000/app:decrypted
```


#### Using KMS

```bash
cd example/

export PQPUB=`openssl enc -base64 -A -in /tmp/kmspqc/pub-ml-kem-768-kms.pem`
export GOOGLE_APPLICATION_CREDENTIALS=/home/srashid/gcp_misc/certs/cicd-test-sa.json
export PROJECT_ID=`gcloud config get-value core/project`   
export KEY_PATH="gcpkms://projects/$PROJECT_ID/locations/global/keyRings/kem_kr/cryptoKeys/kem_key_1/cryptoKeyVersions/1"


cd grpc/
go run server.go  --pqcURI="pqc://pq?pub=$PQPUB" \
  --pqcKeyURI="pqc://pq?key=$KEY_PATH" \
  --adc="$GOOGLE_APPLICATION_CREDENTIALS"

cd example/
export SSL_CERT_FILE=certs/tls-ca-chain.pem

skopeo copy --encrypt-layer -1 \
  --encryption-key=provider:grpc-keyprovider:pqccrypt:pqc://pq?pub=$PQPUB \
   docker://docker.io/salrashid123/app docker://registry.domain.com:5000/app:encrypted

skopeo copy --dest-tls-verify=false \
  --decryption-key=provider:grpc-keyprovider:pqc://pq?pub=$PQPUB \
    docker://registry.domain.com:5000/app:encrypted docker://registry.domain.com:5000/app:decrypted
```




set the `OCICRYPT_KEYPROVIDER_CONFIG` file to use

```json
{
  "key-providers": {
    "kmscrypt": {
    "grpc-keyprovider": {
      "grpc": "localhost:50051"
    }
  }
}
```

Finally invoke the endpoints (note `provider:grpc-keyprovider` is used below)



### Using containerd

To use `containerd` can decrypt and run the image automatically, you first need to configure a stream processor pointing to the decryption functions.

Basically, when containerd detects an encrypted image, it will expect an external process to provide the decrypted image layer.

To do this, we will need [imgcrypt](https://github.com/containerd/imgcrypt.git) installed as well.

As a demo, configure ocicrypt kms to use an `adc` file path (you must first have the json file downloaded and IAM permissions for that service account to decrypt an image)

```bash
cd example/
export OCICRYPT_KEYPROVIDER_CONFIG=`pwd`/ocicrypt.json
export SSL_CERT_FILE=`pwd`/certs/tls-ca-chain.pem

export PROJECT_ID=`gcloud config get-value core/project`
```

the `ocicrypt.json` file will include `adc=`:

```json
{
  "key-providers": {
    "pqccrypt": {
      "cmd": {
        "path": "/tmp/kms_oci_crypt",
        "args": [
          "--adc", "/path/to/service_account.json",
          "--pqcKeyURI", "pqc://pq?key=gcpkms://projects/core-eso/locations/global/keyRings/kem_kr/cryptoKeys/kem_key_1/cryptoKeyVersions/1"             
        ]
      }
    },
    "grpc-keyprovider": {
      "grpc": "localhost:50051"
    }
  }
}
```

* then install [imgcrypt](https://github.com/containerd/imgcrypt.git)

```bash
git clone git clone https://github.com/containerd/imgcrypt.git
cd imgcrypt
make
sudo make install  ##    install to /usr/local/bin/ctd-decoder
```

* install [nerdctl](https://github.com/containerd/nerdctl)


* build kms_oci_crypt 

```bash
cd plugin
go build -o /tmp/kms_oci_crypt .
```

* encrypt the raw image from dockerhub to your local registry

```bash
skopeo copy --encrypt-layer=-1 \
  --encryption-key=provider:kmscrypt:gcpkms://projects/$PROJECT_ID/locations/global/keyRings/ocikeyring/cryptoKeys/key1 \
   docker://docker.io/salrashid123/app docker://registry.domain.com:5000/app:encrypted
```

* start `containerd`

Note, that to avoid conflicts the system's containerd, the config specifies to use the socket and config in the /tmp/ folder:

edit `example/config.toml` the stream processor to point to your config file:

```conf
[stream_processors]
  [stream_processors."io.containerd.ocicrypt.decoder.v1.tar.gzip"]
    accepts = ["application/vnd.oci.image.layer.v1.tar+gzip+encrypted"]
    returns = "application/vnd.oci.image.layer.v1.tar+gzip"
    path = "/usr/local/bin/ctd-decoder"
    env = ["OCICRYPT_KEYPROVIDER_CONFIG=/path/to/ocicrypt-kms-keyprovider/example/ocicrypt.json"]
       
  [stream_processors."io.containerd.ocicrypt.decoder.v1.tar"]
    accepts = ["application/vnd.oci.image.layer.v1.tar+encrypted"]
    returns = "application/vnd.oci.image.layer.v1.tar"
    path = "/usr/local/bin/ctd-decoder"
    env = ["OCICRYPT_KEYPROVIDER_CONFIG=/path/to/ocicrypt-kms-keyprovider/example/ocicrypt.json"]
```

now start containerd

```bash
sudo /usr/bin/containerd -c config.toml
```

*  to run the image

```bash
### clean all images
sudo  nerdctl --insecure-registry  --debug-full  --address /tmp/run/containerd/containerd.sock system prune --all

### dun the encrypted image which will get decrypted on the fly
sudo  nerdctl --insecure-registry  --debug-full \
   --address /tmp/run/containerd/containerd.sock run -ti \
    registry.domain.com:5000/app:encrypted
```


---

### Encryption Format

If you want to see the wrapped encryption hierarchy,  a manifest's last layer is encrypted:

```json
{
    "Name": "registry.domain.com:5000/app",
    "Digest": "sha256:ab66723904080079204d937d12d37535aaed396e455c231309ce77ab8466593a",
    "RepoTags": [
        "encrypted",
        "decrypted"
    ],
    "Created": "2025-10-14T02:53:18.980326736-04:00",
    "DockerVersion": "",
    "Labels": null,
    "Architecture": "amd64",
    "Os": "linux",
    "Layers": [
        "sha256:dd5ad9c9c29f04b41a0155c720cf5ccab28ef6d353f1fe17a06c579c70054f0a",
        "sha256:960043b8858c3c30f1d79dcc49adb2804fd35c2510729e67685b298b2ca746b7",
        "sha256:b4ca4c215f483111b64ec6919f1659ff475d7080a649d6acd78a6ade562a4a63",
        "sha256:eebb06941f3e57b2e40a0e9cbd798dacef9b04d89ebaa8896be5f17c976f8666",
        "sha256:02cd68c0cbf64abe9738767877756b33f50fff5d88583fdc74b66beffa77694b",
        "sha256:d3c894b5b2b0fa857549aeb6cbc38b038b5b2828736be37b6d9fff0b886f12fd",
        "sha256:b40161cd83fc5d470d6abe50e87aa288481b6b89137012881d74187cfbf9f502",
        "sha256:46ba3f23f1d3fb1440deeb279716e4377e79e61736ec2227270349b9618a0fdd",
        "sha256:4fa131a1b726b2d6468d461e7d8867a2157d5671f712461d8abd126155fdf9ce",
        "sha256:01f38fc88b34d9f2e43240819dd06c8b126eae8a90621c1f2bc5042fed2b010a",
        "sha256:50891eb6c2e685b267299b99d8254e5b0f30bb7756ee2813f187a29a0a377247",
        "sha256:c4cd914051cf67617ae54951117708987cc63ce15f1139dee59abf80c198b74e",
        "sha256:ddc9bffd9ec055efa68358f5e2138ed78a2226694db2b8e1fb46c4ae84bae5ad",
        "sha256:7fa7a09a6ecadc2ba8ba9f217d1b2a6c83f3c75e5b90300d86f59f61833ffc92"
    ],
    "LayersData": [
        {
            "MIMEType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "Digest": "sha256:dd5ad9c9c29f04b41a0155c720cf5ccab28ef6d353f1fe17a06c579c70054f0a",
            "Size": 83932,
            "Annotations": null
        },
        {
            "MIMEType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "Digest": "sha256:960043b8858c3c30f1d79dcc49adb2804fd35c2510729e67685b298b2ca746b7",
            "Size": 20322,
            "Annotations": null
        },
        {
            "MIMEType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "Digest": "sha256:b4ca4c215f483111b64ec6919f1659ff475d7080a649d6acd78a6ade562a4a63",
            "Size": 599551,
            "Annotations": null
        },
        {
            "MIMEType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "Digest": "sha256:eebb06941f3e57b2e40a0e9cbd798dacef9b04d89ebaa8896be5f17c976f8666",
            "Size": 284,
            "Annotations": null
        },
        {
            "MIMEType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "Digest": "sha256:02cd68c0cbf64abe9738767877756b33f50fff5d88583fdc74b66beffa77694b",
            "Size": 188,
            "Annotations": null
        },
        {
            "MIMEType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "Digest": "sha256:d3c894b5b2b0fa857549aeb6cbc38b038b5b2828736be37b6d9fff0b886f12fd",
            "Size": 112,
            "Annotations": null
        },
        {
            "MIMEType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "Digest": "sha256:b40161cd83fc5d470d6abe50e87aa288481b6b89137012881d74187cfbf9f502",
            "Size": 382,
            "Annotations": null
        },
        {
            "MIMEType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "Digest": "sha256:46ba3f23f1d3fb1440deeb279716e4377e79e61736ec2227270349b9618a0fdd",
            "Size": 345,
            "Annotations": null
        },
        {
            "MIMEType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "Digest": "sha256:4fa131a1b726b2d6468d461e7d8867a2157d5671f712461d8abd126155fdf9ce",
            "Size": 122108,
            "Annotations": null
        },
        {
            "MIMEType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "Digest": "sha256:01f38fc88b34d9f2e43240819dd06c8b126eae8a90621c1f2bc5042fed2b010a",
            "Size": 5209711,
            "Annotations": null
        },
        {
            "MIMEType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "Digest": "sha256:50891eb6c2e685b267299b99d8254e5b0f30bb7756ee2813f187a29a0a377247",
            "Size": 1889065,
            "Annotations": null
        },
        {
            "MIMEType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "Digest": "sha256:c4cd914051cf67617ae54951117708987cc63ce15f1139dee59abf80c198b74e",
            "Size": 921781,
            "Annotations": null
        },
        {
            "MIMEType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "Digest": "sha256:ddc9bffd9ec055efa68358f5e2138ed78a2226694db2b8e1fb46c4ae84bae5ad",
            "Size": 4156535,
            "Annotations": null
        },
        {
            "MIMEType": "application/vnd.oci.image.layer.v1.tar+gzip+encrypted",
            "Digest": "sha256:7fa7a09a6ecadc2ba8ba9f217d1b2a6c83f3c75e5b90300d86f59f61833ffc92",
            "Size": 135,
            "Annotations": {
                "org.opencontainers.image.enc.keys.provider.pqccrypt": "eyJrZXlfdXJsIjoicHFjOi8vcHE/cHViPUxTMHRMUzFDUlVkSlRpQlFWVUpNU1VNZ1MwVlpMUzB0TFMwS1RVbEpSWE5xUVV4Q1oyeG5hR3RuUWxwUlRVVkNRVWxFWjJkVGFFRk1jbUZNVVU5YWVXOUdha3MzY2tSbE1XSXdRV1F5Tm14bE1rUkRVelJoVFU5amN3cGxjRlJ3UTBnMGVtNXVWRlZFY0NzM2IzbEliRWRLYVVsa1NrWlVTMjl5U25SRWRXaEpUREJDYzNCaVdHUmpUMGQ2ZVRGalRsUTNha2c0VWxST2RDOUJDbmx5ZFdKT1p6aEtTM1pRU0VSc2QzSnhielpoZDI5WFlsSXdabFJ2YVdNMmEzcFVia2d2YWpGSk16UnJhV3BoYVZCTVIycFNUVnBMZVZkTFVtTmFSVGdLVkZCcWFsbG1UMXBaYkhKVWMxb3JSMmxsTnpKTlR6QTJkRzlwTkVwQlFUWllkbU55YTNGcmVsTnViMWxPZHpsc1JVOXFOMWxRTVd4U1kydHNRWFJFYXdwRVoxb3plRGgwUkVGMVdHeGxjRXBWZFVreVIxRXlkSHB3ZEdsVlkwTkRVMlpyY0Rodk4zZGhlbTFOVmxOQlkwZDViRmh2U1RGVWIwaHRRMWRSWW00MENrbzJZVWhIVkVaYVRHTXdaM3BuT1V0bldVWllRbEZqTUZCS2FtRnBVMHBSZW1VNFJuTm1kMnhCYlZaS2JFRkhVbTV2THpGUVRqWnVjV3BZVVVoa1dtZ0tTa3BHZVZkT1NqaE9Ua05YUWxOWldsbHVRVmQxWlhZMmVXSTVlVzFVU2tWTFREZFVkR0ZOV0U5SlFrbDZOazk2ZVZoVlNHMVFkREpUVm1WeVNtaHliQXBQTlUxNmNuWmtOMGRsTlZWbU9FWlNValJEWVhGbllXeDNUM2MxYVdac04wUkRhalpyWjNsdmJXWTVXR2Q0VWpaVVRIVnpVMHRvVVhGNWJEWlFiekZhQ25ocVVsWlpNREk0WnpJck1GQTNSMjU1YTNrMlowSmFWbnBuZFZkNVVVTnpUREZEVFVWWVEwRlhZamRaWlhkWWFHTnBUMmRtY1VNMlFUY3JZa2N6TXpVS2RrVlVOa28xY0RCSWFqQkRWalZEV2xsT2JXTnJNako2WVZneFJGUnRjbTlPYTFkTFNYRjNibTlIYUhkV1REQlNUVk40YVUwNFVIZEtaMW8zWW10aGNBcE1TakZZV1ZRM2JsbEZjbUZqYVdaTGNsWnhWMngwV2paMU5ESlJZMjVNYUZrd2QyeDRiemszVlVsbFZIWTVTVXBTWTNaeFJHVk1ZazFFYjNsWFRWZFdDbUkyTlZaTGVuQlVTbXB1VEdSeU5VTjNVMlJHYTJkRFdIQnlXVEZVYVhOWlZXdDJjMjExZFZaeVIxY3lSa3RxVFVwclpubG1kWFJoUnpaVmEweHNVMkVLWm5OcmIyNTBUMHRKSzNadlNVTnRiVXRoV0hwVEswdFRUazByV1ZreVNIQm9UbVZyUWlzMk0zWXdWMDFPZEVwaFUyWjFRMjByVW5wQ2JUSkxhRlU1YXdwdmFqaHVTSEJ1UkVwUkx6WklXR2x3VG1KMFdWcEdORVpKSzFoaFdDdGlRbGRRWTFOSVoyaEVlRkZPUTBOYVZrbHBRM1E0VVVGdVozYzFWMk53TkZwTENtRnJVR05qVkVOaVRUTlNkMjVPVjJod2F6ZDVVU3RpVFVnNU4zTkRUelZHVjBFemJrWlhiVzF0TkV0U1JITk9jWHBRVldOMllscG5ibWQ1Y1ZOV1psRUtTVWRDU0V0dGNsaE1iVWhxYjNneWNWSlNTMnB6TUN0Q2VXSXlOMlZRUzNGdVluQk5VVUp1V2sxWmEzcGhXVGM0VUdJck5ubHJVREJxWmt3eGRVcDZRZ3BVWWsxUmQxSk9WRXRXWVdOTU4zWkxSMlF6YUZCdFl6UnVNVWRGVEZGV1ZrcElRVFo0VWtsd2VtaEpSbWQxWnpCbk4xZFlTamMyYm14c1YxTlFjR1pUQ25oa1FVVXdTbWhvU1ZneE4xa3hVbnBUWkdsM1JGUndPRXhXY2pWTk9UbFhRM0ZIVTIxcE0yNVRWa3N6ZGtoRlNsQlFSVVZGUjJvMFVFUlJTbXg1TUhJS1NYVkxiRlJwVEd0VVMwUk1SbWxEWjBVNFNXaEtMMDk1U0hCV1NGSnhUM2QxWjBWRlFuRm5jVzlxYlRWNFYydGlaVUpJTlU5R2RXcHFjME5FVmtKdFFncExibmsxUWtrNFkzWTJVR2xLU0VSR1ZIRlBObE14WjBWbmNVNVRUamRyTTNwMVMyZE1PRmN5YkhKTlNGbGpOMjFIYnpOTWJsQkRXVlpuYVdOak1VVk5Da2xJVERWd2JVcGphamwyVVhWbGJFVnVZMk55V0dwTVEyazBkV05IZDBOSVFYUlVVVXgzVUdsc2N6bEZXV3RxV0ZsUmFISlNURWRLWm1zM1VsQTVla1FLZUVscWNteFZia2hOZG5KQ2IxbGhZbFZwYjBaQlMyOVNhVlF4ZVZVMGJUWjBkekZWVVhwNGNrSmtWRGhDWjNCSlJXTXJWV0ZaVDB0RlkyWjZlVEZST0FwTWNITlNUVXhXVVVkdVUwVm5ZMDAyWWpsUU1rbFRWSHBrVnpGTlFqZHpXbk5PZEZSUE1tUkRVMlJqVVVGT1owZG9kMUJ6ZG1SU1VYbHZVREZXWkRrMkNrMVFkbXBGVVZGcmF5OVpOV1JwV0c1WWVtdDRlbGhaTjBjeE9FRldTVGQ1YWs5amFFVTFUWGRyV0VGd1ZISTFXSFZFWlVkMVJqUkJVelp2UjFaaVoyNEtaMWRoVFZGV01sTkVTMDFZYlRCS2EwTkxOR2RMUjBacWJFZ3hVMVJQVUV0aFVFSm5XVnBGYjFOVFVVVlVhRVJEYVVaVmNIUnBjMVZFZGpsWmMzaE9hd3BYVm05T1VWRk1SZ290TFMwdExVVk9SQ0JRVlVKTVNVTWdTMFZaTFMwdExTMD0iLCJ3cmFwcGVkX2tleSI6ImV5SmphWEJvWlhKMFpYaDBJam9pYVcxcVlWSllMMHQzY0ZSV1YzVXdTaTl6ZDJ0RVJVa3liWFk0U0VoRWNqWnRZWEZVV2pnNWVYaFFkbGxhY0U5c1NFRXpZWHBPUTFoUVVHVXJUbmt4T1RWS01YVlBjVTVUVm14aWNtYzFXR1JaZGpKRllsQXpWVWQ1T0c1c2VUTlZTamRQVFZGWGQyVmpibkkzZUZab1dYWlRjMDFSU1dSc2FFTmtaRUp1V1hsSWNtdEtaWEZEYXpsbU4zcElZbFpvVG14cGFIaDViWFF4YlVKUll6SnZWRGxXYUROUWExQmxOVE12VDJoT1EzUjZURTVEUzNKamFXbFNXVEZqUTNsdlNtMW9kVmx2YjB4SmJ5czRjU3N4YWs1TE5taFJOM2xhV1ZobFRVdHlZelF4TkVSQmRtYzJSQzgxU1ZOaWEwdFNSMjVhTVdSSVRreG5PQzkxTVVaTlMybGpUakJUUlUxU1dIRXpkM3BuZWxKVFptTTViMjR3UFNJc0lDSnBkaUk2SWtkTldFVmFNWFp2ZWl0V1drWlVhRllpTENBaWEyVjVTVzVtYnlJNmV5SjNjbUZ3Y0dWa1MyVjVJam9pWlhsS01scFlTbnBoVnpsMVNXcHZlRXhEUVdsa1NHeDNXbE5KTmtsdE1YTllNblJzWWxZNE0wNXFaMmxNUTBGcFlUSldkRkV5YkhkaFIxWjVWa2RXTkdSRFNUWkpiRXBSVEROYWJtVkZkRWRhYmtGM1ZsVndRbFY2VmxoWGJGSkRXbFJPZW1JeFNrcFhWa3BQWVVoS1YxSkhjRlZSV0UwMVZrVnZNRTlIYzNsaFYyaDRXVE5DWVZRd1NreFRSV3cyVjFSS1lWbFhPVmxYYXpGaFVXdGpNV0pXVWxCaFEzUjBZVEkxUzFOWVVUQlRiVll3VTBSSk1rOUViR2xVVlU1cllrZFNTMWRXVmxGalJHUmFWRWh2ZGxSV1VsWlpWR2Q2V2xWT01tSXpjRzVoU0ZZelZHNUtVMVl6VG10VU0wRjNZVEpTZVdKNldsZGhXR2MxVFd4b1NWRnFhRXBYUkdSVFltMDRlV1ZxWkZOamFtUTBWVEo0TmxOcVp6Tk9NVXBHWlZka2MxSnNRWGhPTVhCNlRqSktjMVJGU201WlZWSkZWa2R3YjB3d1pFcGpRM1JVVFZkb2NXSnNjRWxOVlZwYVkwUlZOR0pJYkVWUlV6bE5VMFpDTUZWcVRtMVZWekY1V1hwa1dXUkhWbmxNTURGVlpHMW9TMWRWZEhaV1NFVXdXV3BTYkdSSGR6RlNNbXhXWWpKd01FOVZNVk5sVkdoMVRXcGtXR1ZxVWtWYVYwbHlVMFV4UmxaWWFFeFdTRnBFVDBkc2QwMUVhSFJXV0ZaTlRVYzVjbFF6WjNKYWVtUnBXVEJTU1UxVk9VeGhWV2hJVGpGYU0xTXphRmxUZWsxNVVtcENkMHN4V1haVlYyeFFZVlYwVjFKWWIzZFVTR04zVTNwa1JtUldTbFZUUTNSV1VrUldZV1I2VGsxaVYwWTBWbFZLU1ZSVVNqVk9Wa3BWVERJMWEwc3dWazVPTUdoT1UwUk9iVTFHU2xGUFJYY3dVVE5hVlUxSVVUUmxSRTVoV2pKd1ZsWnJkM2RTTTJ3MVlrVk5NRTVIU21sa2JXUnRVWHBuZVZNeWRIbGlWMmh1VVRGS1RrNUlhekJaVnpnMFkwZHdXbFJJY0ZoTk0xcDZUVEZhY1dSRVVsTlhWMDVIVFZaV1dWSlZVbTFrTVdodlVWVjRVMDFVUmtKT1dFNWhWMVpLUTJNeFdsSmhSbkJoVDFVeE0xbHRSa3RSVkZVelZEQmFORlJ0ZERWYVdHUTBWRWRPYUUxV1JteGxiazR5WkVoWk1WVXhZekJPV0ZKTFdWZEdkRkZ1VWxoVU0xcEpWbXh3VEdKcVpGTlRWRm8xVFZSRk1rOVhkSFZTYTNocFZHczFXbEZWYUd0VFJscDBVVmhTUms0eFVsVlZNalZYWkRKT2JFMXRhSFJPUjFwMFpIcGFkRlJXUm5OUFJUQXhaREpWTVZSck5VOVdXR2hTV2toT2NGWnVhRFJpVlZVellrZDBORkY2Umtsa1JVWjJaVVZvWVU1RlVrUmxWVXBFV2xkWmNsb3pXa1prYkdoVllVaHNXVnB1YkRKTE1GRjJXVmM1U1dGSFRUUlRibFpVVGxOMGRHUldTbFZOTTJ4eVRucHNTRkpFYUhCVlYwNTJVbFpvVTFkV1ZtOWpibWhRV2pCa2NHSnNXa2xoTTJoRlkwaGtSRXQ2Vm05aU0yZDRZek5rY0dReFJsQlBWVll3WW5wV1YxcElaR2xPZWtwSFZWUldhVTB3Um5SaWVYUnhVbTFOTUZvd01WRmtNMXBEVmtaS1QxcHVaRlpOUlhocllWUlJOV1JVUW1sVWVUZzFUbXRhU0ZsVVduTmpVM1JGVlZVMVJVd3dXbnBaVkVreFZqSkZjbFF3U2pWYVUzUkpaRWRzTUZwWWNEUmhibkJ6WXpJNWJWSkVRbmRqYVRneFVrWmFlVlF6VVhKU2JteEVWRWM1U0ZaVlJuQmpNVTVaVTBoS1ZWSnJSblJWTURsQ1YwaENOR0pWTVhsU1ZXaEVVMnBLZUZkdE9YSmxVemxEVG0xU2NWbDZRbGhhUmxrd1RtNVNZV05JVlhsbFJFcGhVVlJPYlZaSWNIcGlhM0JwWkVkU1UxWjZZelJTU0dSV1UxYzFiV0p1V2s5V01sWjVWSHBLV1U5SFRreGhNRVoxVTNwUk1GRlhOWEJqYmtweVZHcEdVVll4UmpKV2JHeHFVV3hrV1ZwRldURlVlbHB6VkVSU1JsWnNjRlZhV0VZMFkycG9RMlJWWkVOTmJUVkhaRlU1VDJWc2JFTlRTSEJNVlZOMGFVMTZiSGhXYmxKRldsUmFNRlV6V21wTk1WWnJZbXhHVlUxdGFGQkxNVlp5WlVkV1ZGSlhhRWRTYTNSSFVYcFdTbFV6Y0VaaVJURlVVVEZzYVdWclkzaGtNVkpRV2pCbk0xRXhjRE5XTWpGVFdWZEpkMUl5TlhkWmEwNHdaVlpvZFZvd2RISmtSVTVZVkZkek5HVkZhR2xXU0VadVlucHJlbFl6V21GUmJFRnlVa1ZXV1U1WE5UTlNNMlJQWW01b2FHSkVUWGhPTUVwdVlrZE9hMDlYYXpWYVJYQlFWakpvVDFveGNGQmpWRXBLVjFSVk1GWXlZekZhTWxacVZsWm9TVmRFV1RGV1JsWlVaVWMxV1U1NlRubE9iWGQ0Wld0T1NHTnVhRUpSTWxwMVRqRk9XazFHY0V4VE0wSnpXbFZvZUZaclpHcFpWVXAyVFVWR2NXSnJjRkJOYmtwQ1VWaE9WV0pZVmtka1IyeHRZa2R3YTFVeU9IZFBRemxJVDFWS2RsbHJkRmhpYlhCMFQxVmFkMVZHVWpCWmFsSnpVbTVGZVZkV1RuaFRXR1F4V1d0b2IxWnVjSGhOVlRGVFZHNVNSR0ZzUlRWT01Xd3dWVEJ3V1dNeGNHNVhSekZvU3pGQ1NGVXdhSEpPTTA1TlVWVm9NR013VWxoaGVteDZUbFJCTW1GRVNsSlZSR3g0VWpKV01rc3pTazloTW5CUVRXc3hhMVV3TlU5aVJYQndWR3Q0UWxaWE1YcGFhbXhJVjIxSmVVd3pWalZqUlZaeFRVWk9WVlo2UW5GWmEyYzFXVE5LV0ZreGEzSlphekUwWVZSb1Qxb3llRE5pTTJoRllVZDRZVk5yWjNoalJURkpZVVYwU2xkWFRsSmtWa1p4VW1wbmVtVllSbHBOTUdneVlYcEdNRlpyTVVkUmJWVnlZM3BrVWxsVk9UWk5XSEJPVTFSYU1XUXhjRlJVUnpGc1dteHdUbGxZV1hoVGJWWjFaV3hLTmxvd1NtdGtiRkp6VFROc1VtRnVXalZrYTFKcFRsaFNUbVJxWkVsa2JHeEVaRWh2TldRelFqRk5WVkpMVmpGd1dsZFhhSEJYVjNCelZEQkdTMUp0Y0VOVFJ6bHJaVmN4ZWxGNlpHOWtWR3hJVmxjME1XUlViRlZhYkhCYVQwWldSMXB1VFRWVVJWWldWakk0ZW1SNldsbFNSM0EwVW0xc2VWa3dhSGhPTUVwb1YxVldOVTFZYUVoaFYwcHFVRk5KYzBsRFNqTmpiVVozWTBkV2ExVnRSak5UTWxZMVNXcHZhVk42U2xKVVZsb3haRVZXZVZGdVdrdFJibFp2VlZkR2IxSXlVVFJPYTFwU1kxUnNjMWRIYkZOV01WWlhaRlUxV1ZVeWJFaE9SbEpPWkZkS1ZHTjZaREpOUld4TllrUktOVmxyV1RWTlUzUlhWVlZ2TkZscmVIRmFSMjl5VEhsMFExZHNXblphYkVwVlVUQnJhV1pSUFQwaWZYMD0iLCJ3cmFwX3R5cGUiOiJBRVMifQ==",
                "org.opencontainers.image.enc.pubopts": "eyJjaXBoZXIiOiJBRVNfMjU2X0NUUl9ITUFDX1NIQTI1NiIsImhtYWMiOiJQbXF0QTdsWDhzaGttU2hPUVE0NU8wM3hRbzhFeDFUeitoaFBoa3VkK3Q0PSIsImNpcGhlcm9wdGlvbnMiOnt9fQ=="
            }
        }
    ],
    "Env": [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"
    ]
}
```

where if you base64 decode `"org.opencontainers.image.enc.keys.provider.pqccrypt"`:

yields

```json
{
  "key_url": "pqc://pq?pub=LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJRXNqQUxCZ2xnaGtnQlpRTUVCQUlEZ2dTaEFMcmFMUU9aeW9Gaks3ckRlMWIwQWQyNmxlMkRDUzRhTU9jcwplcFRwQ0g0em5uVFVEcCs3b3lIbEdKaUlkSkZUS29ySnREdWhJTDBCc3BiWGRjT0d6eTFjTlQ3akg4UlROdC9BCnlydWJOZzhKS3ZQSERsd3JxbzZhd29XYlIwZlRvaWM2a3pUbkgvajFJMzRraWphaVBMR2pSTVpLeVdLUmNaRTgKVFBqallmT1pZbHJUc1orR2llNzJNTzA2dG9pNEpBQTZYdmNya3FrelNub1lOdzlsRU9qN1lQMWxSY2tsQXREawpEZ1ozeDh0REF1WGxlcEpVdUkyR1EydHpwdGlVY0NDU2ZrcDhvN3dhem1NVlNBY0d5bFhvSTFUb0htQ1dRYm40Cko2YUhHVEZaTGMwZ3pnOUtnWUZYQlFjMFBKamFpU0pRemU4RnNmd2xBbVZKbEFHUm5vLzFQTjZucWpYUUhkWmgKSkpGeVdOSjhOTkNXQlNZWlluQVd1ZXY2eWI5eW1USkVLTDdUdGFNWE9JQkl6Nk96eVhVSG1QdDJTVmVySmhybApPNU16cnZkN0dlNVVmOEZSUjRDYXFnYWx3T3c1aWZsN0RDajZrZ3lvbWY5WGd4UjZUTHVzU0toUXF5bDZQbzFaCnhqUlZZMDI4ZzIrMFA3R255a3k2Z0JaVnpndVd5UUNzTDFDTUVYQ0FXYjdZZXdYaGNpT2dmcUM2QTcrYkczMzUKdkVUNko1cDBIajBDVjVDWllObWNrMjJ6YVgxRFRtcm9Oa1dLSXF3bm9HaHdWTDBSTVN4aU04UHdKZ1o3YmthcApMSjFYWVQ3bllFcmFjaWZLclZxV2x0WjZ1NDJRY25MaFkwd2x4bzk3VUllVHY5SUpSY3ZxRGVMYk1Eb3lXTVdWCmI2NVZLenBUSmpuTGRyNUN3U2RGa2dDWHByWTFUaXNZVWt2c211dVZyR1cyRktqTUprZnlmdXRhRzZVa0xsU2EKZnNrb250T0tJK3ZvSUNtbUthWHpTK0tTTk0rWVkySHBoTmVrQis2M3YwV01OdEphU2Z1Q20rUnpCbTJLaFU5awpvajhuSHBuREpRLzZIWGlwTmJ0WVpGNEZJK1hhWCtiQldQY1NIZ2hEeFFOQ0NaVklpQ3Q4UUFuZ3c1V2NwNFpLCmFrUGNjVENiTTNSd25OV2hwazd5UStiTUg5N3NDTzVGV0EzbkZXbW1tNEtSRHNOcXpQVWN2Ylpnbmd5cVNWZlEKSUdCSEttclhMbUhqb3gycVJSS2pzMCtCeWIyN2VQS3FuYnBNUUJuWk1Za3phWTc4UGIrNnlrUDBqZkwxdUp6QgpUYk1Rd1JOVEtWYWNMN3ZLR2QzaFBtYzRuMUdFTFFWVkpIQTZ4UklwemhJRmd1ZzBnN1dYSjc2bmxsV1NQcGZTCnhkQUUwSmhoSVgxN1kxUnpTZGl3RFRwOExWcjVNOTlXQ3FHU21pM25TVkszdkhFSlBQRUVFR2o0UERRSmx5MHIKSXVLbFRpTGtUS0RMRmlDZ0U4SWhKL095SHBWSFJxT3d1Z0VFQnFncW9qbTV4V2tiZUJINU9GdWpqc0NEVkJtQgpLbnk1Qkk4Y3Y2UGlKSERGVHFPNlMxZ0VncU5TTjdrM3p1S2dMOFcybHJNSFljN21HbzNMblBDWVZnaWNjMUVNCklITDVwbUpjajl2UXVlbEVuY2NyWGpMQ2k0dWNHd0NIQXRUUUx3UGlsczlFWWtqWFlRaHJSTEdKZms3UlA5ekQKeElqcmxVbkhNdnJCb1lhYlVpb0ZBS29SaVQxeVU0bTZ0dzFVUXp4ckJkVDhCZ3BJRWMrVWFZT0tFY2Z6eTFROApMcHNSTUxWUUduU0VnY002YjlQMklTVHpkVzFNQjdzWnNOdFRPMmRDU2RjUUFOZ0dod1BzdmRSUXlvUDFWZDk2Ck1QdmpFUVFray9ZNWRpWG5Yemt4elhZN0cxOEFWSTd5ak9jaEU1TXdrWEFwVHI1WHVEZUd1RjRBUzZvR1ZiZ24KZ1dhTVFWMlNES01YbTBKa0NLNGdLR0ZqbEgxU1RPUEthUEJnWVpFb1NTUUVUaERDaUZVcHRpc1VEdjlZc3hOawpXVm9OUVFMRgotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0=",
  "wrapped_key": "eyJjaXBoZXJ0ZXh0IjoiaW1qYVJYL0t3cFRWV3UwSi9zd2tERUkybXY4SEhEcjZtYXFUWjg5eXhQdllacE9sSEEzYXpOQ1hQUGUrTnkxOTVKMXVPcU5TVmxicmc1WGRZdjJFYlAzVUd5OG5seTNVSjdPTVFXd2VjbnI3eFZoWXZTc01RSWRsaENkZEJuWXlIcmtKZXFDazlmN3pIYlZoTmxpaHh5bXQxbUJRYzJvVDlWaDNQa1BlNTMvT2hOQ3R6TE5DS3JjaWlSWTFjQ3lvSm1odVlvb0xJbys4cSsxak5LNmhRN3laWVhlTUtyYzQxNERBdmc2RC81SVNia0tSR25aMWRITkxnOC91MUZNS2ljTjBTRU1SWHEzd3pnelJTZmM5b24wPSIsICJpdiI6IkdNWEVaMXZveitWWkZUaFYiLCAia2V5SW5mbyI6eyJ3cmFwcGVkS2V5IjoiZXlKMlpYSnphVzl1SWpveExDQWlkSGx3WlNJNkltMXNYMnRsYlY4M05qZ2lMQ0FpYTJWdFEybHdhR1Z5VkdWNGRDSTZJbEpRTDNabmVFdEdabkF3VlVwQlV6VlhXbFJDWlROemIxSkpXVkpPYUhKV1JHcFVRWE01VkVvME9Hc3lhV2h4WTNCYVQwSkxTRWw2V1RKYVlXOVlXazFhUWtjMWJWUlBhQ3R0YTI1S1NYUTBTbVYwU0RJMk9EbGlUVU5rYkdSS1dWVlFjRGRaVEhvdlRWUlZZVGd6WlVOMmIzcG5hSFYzVG5KU1YzTmtUM0F3YTJSeWJ6WldhWGc1TWxoSVFqaEpXRGRTYm04eWVqZFNjamQ0VTJ4NlNqZzNOMUpGZVdkc1JsQXhOMXB6TjJKc1RFSm5ZVVJFVkdwb0wwZEpjQ3RUTVdocWJscElNVVpaY0RVNGJIbEVRUzlNU0ZCMFVqTm1VVzF5WXpkWWRHVnlMMDFVZG1oS1dVdHZWSEUwWWpSbGRHdzFSMmxWYjJwME9VMVNlVGh1TWpkWGVqUkVaV0lyU0UxRlZYaExWSFpET0dsd01EaHRWWFZNTUc5clQzZ3JaemRpWTBSSU1VOUxhVWhITjFaM1MzaFlTek15UmpCd0sxWXZVV2xQYVV0V1JYb3dUSGN3U3pkRmRWSlVTQ3RWUkRWYWR6Tk1iV0Y0VlVKSVRUSjVOVkpVTDI1a0swVk5OMGhOU0RObU1GSlFPRXcwUTNaVU1IUTRlRE5hWjJwVlZrd3dSM2w1YkVNME5HSmlkbWRtUXpneVMydHliV2huUTFKTk5IazBZVzg0Y0dwWlRIcFhNM1p6TTFacWREUlNXV05HTVZWWVJVUm1kMWhvUVV4U01URkJOWE5hV1ZKQ2MxWlJhRnBhT1UxM1ltRktRVFUzVDBaNFRtdDVaWGQ0VEdOaE1WRmxlbk4yZEhZMVUxYzBOWFJLWVdGdFFuUlhUM1pJVmxwTGJqZFNTVFo1TVRFMk9XdHVSa3hpVGs1WlFVaGtTRlp0UVhSRk4xUlVVMjVXZDJObE1taHROR1p0ZHpadFRWRnNPRTAxZDJVMVRrNU9WWGhSWkhOcFZuaDRiVVUzYkd0NFF6RklkRUZ2ZUVoYU5FUkRlVUpEWldZclozWkZkbGhVYUhsWVpubDJLMFF2WVc5SWFHTTRTblZUTlN0dGRWSlVNM2xyTnpsSFJEaHBVV052UlZoU1dWVm9jbmhQWjBkcGJsWklhM2hFY0hkREt6Vm9iM2d4YzNkcGQxRlBPVVYwYnpWV1pIZGlOekpHVVRWaU0wRnRieXRxUm1NMFowMVFkM1pDVkZKT1puZFZNRXhrYVRRNWRUQmlUeTg1TmtaSFlUWnNjU3RFVVU1RUwwWnpZVEkxVjJFclQwSjVaU3RJZEdsMFpYcDRhbnBzYzI5bVJEQndjaTgxUkZaeVQzUXJSbmxEVEc5SFZVRnBjMU5ZU0hKVVJrRnRVMDlCV0hCNGJVMXlSVWhEU2pKeFdtOXJlUzlDTm1ScVl6QlhaRlkwTm5SYWNIVXllREphUVRObVZIcHpia3BpZEdSU1Z6YzRSSGRWU1c1bWJuWk9WMlZ5VHpKWU9HTkxhMEZ1U3pRMFFXNXBjbkpyVGpGUVYxRjJWbGxqUWxkWVpFWTFUelpzVERSRlZscFVaWEY0Y2poQ2RVZENNbTVHZFU5T2VsbENTSHBMVVN0aU16bHhWblJFWlRaMFUzWmpNMVZrYmxGVU1taFBLMVZyZUdWVFJXaEdSa3RHUXpWSlUzcEZiRTFUUTFsaWVrY3hkMVJQWjBnM1ExcDNWMjFTWVdJd1IyNXdZa04wZVZodVowdHJkRU5YVFdzNGVFaGlWSEZuYnprelYzWmFRbEFyUkVWWU5XNTNSM2RPYm5oaGJETXhOMEpuYkdOa09XazVaRXBQVjJoT1oxcFBjVEpKV1RVMFYyYzFaMlZqVlZoSVdEWTFWRlZUZUc1WU56TnlObXd4ZWtOSGNuaEJRMlp1TjFOWk1GcExTM0JzWlVoeFZrZGpZVUp2TUVGcWJrcFBNbkpCUVhOVWJYVkdkR2xtYkdwa1UyOHdPQzlIT1VKdllrdFhibXB0T1Vad1VGUjBZalJzUm5FeVdWTnhTWGQxWWtob1ZucHhNVTFTVG5SRGFsRTVOMWwwVTBwWWMxcG5XRzFoSzFCSFUwaHJOM05NUVVoMGMwUlhhemx6TlRBMmFESlJVRGx4UjJWMkszSk9hMnBQTWsxa1UwNU9iRXBwVGt4QlZXMXpaamxIV21JeUwzVjVjRVZxTUZOVVZ6QnFZa2c1WTNKWFkxa3JZazE0YVRoT1oyeDNiM2hFYUd4YVNrZ3hjRTFJYUV0SldXTlJkVkZxUmpnemVYRlpNMGgyYXpGMFZrMUdRbVVyY3pkUllVOTZNWHBOU1RaMWQxcFRURzFsWmxwTllYWXhTbVZ1ZWxKNlowSmtkbFJzTTNsUmFuWjVka1JpTlhSTmRqZElkbGxEZEhvNWQzQjFNVVJLVjFwWldXaHBXV3BzVDBGS1JtcENTRzlrZVcxelF6ZG9kVGxIVlc0MWRUbFVabHBaT0ZWR1puTTVURVZWVjI4emR6WllSR3A0Um1seVkwaHhOMEpoV1VWNU1YaEhhV0pqUFNJc0lDSjNjbUZ3Y0dWa1VtRjNTMlY1SWpvaVN6SlJUVloxZEVWeVFuWktRblZvVVdGb1IyUTROa1pSY1Rsc1dHbFNWMVZXZFU1WVUybEhORlJOZFdKVGN6ZDJNRWxNYkRKNVlrWTVNU3RXVVVvNFlreHFaR29yTHl0Q1dsWnZabEpVUTBraWZRPT0ifX0=",
  "wrap_type": "AES"
}
```


Now, the `wrapped_key` is includes the ml-kem shared secret.  That shared secret is used to encrypt the ciphertext itself

so to decode `wrapped_key`:

```json
{
  "ciphertext": "imjaRX/KwpTVWu0J/swkDEI2mv8HHDr6maqTZ89yxPvYZpOlHA3azNCXPPe+Ny195J1uOqNSVlbrg5XdYv2EbP3UGy8nly3UJ7OMQWwecnr7xVhYvSsMQIdlhCddBnYyHrkJeqCk9f7zHbVhNlihxymt1mBQc2oT9Vh3PkPe53/OhNCtzLNCKrciiRY1cCyoJmhuYooLIo+8q+1jNK6hQ7yZYXeMKrc414DAvg6D/5ISbkKRGnZ1dHNLg8/u1FMKicN0SEMRXq3wzgzRSfc9on0=",
  "iv": "GMXEZ1voz+VZFThV",
  "keyInfo": {
    "wrappedKey": "eyJ2ZXJzaW9uIjoxLCAidHlwZSI6Im1sX2tlbV83NjgiLCAia2VtQ2lwaGVyVGV4dCI6IlJQL3ZneEtGZnAwVUpBUzVXWlRCZTNzb1JJWVJOaHJWRGpUQXM5VEo0OGsyaWhxY3BaT0JLSEl6WTJaYW9YWk1aQkc1bVRPaCtta25KSXQ0SmV0SDI2ODliTUNkbGRKWVVQcDdZTHovTVRVYTgzZUN2b3pnaHV3TnJSV3NkT3Awa2RybzZWaXg5MlhIQjhJWDdSbm8yejdScjd4U2x6Sjg3N1JFeWdsRlAxN1pzN2JsTEJnYUREVGpoL0dJcCtTMWhqblpIMUZZcDU4bHlEQS9MSFB0UjNmUW1yYzdYdGVyL01UdmhKWUtvVHE0YjRldGw1R2lVb2p0OU1SeThuMjdXejREZWIrSE1FVXhLVHZDOGlwMDhtVXVMMG9rT3grZzdiY0RIMU9LaUhHN1Z3S3hYSzMyRjBwK1YvUWlPaUtWRXowTHcwSzdFdVJUSCtVRDVadzNMbWF4VUJITTJ5NVJUL25kK0VNN0hNSDNmMFJQOEw0Q3ZUMHQ4eDNaZ2pVVkwwR3l5bEM0NGJidmdmQzgyS2tybWhnQ1JNNHk0YW84cGpZTHpXM3ZzM1ZqdDRSWWNGMVVYRURmd1hoQUxSMTFBNXNaWVJCc1ZRaFpaOU13YmFKQTU3T0Z4Tmt5ZXd4TGNhMVFlenN2dHY1U1c0NXRKYWFtQnRXT3ZIVlpLbjdSSTZ5MTE2OWtuRkxiTk5ZQUhkSFZtQXRFN1RUU25Wd2NlMmhtNGZtdzZtTVFsOE01d2U1Tk5OVXhRZHNpVnh4bUU3bGt4QzFIdEFveEhaNERDeUJDZWYrZ3ZFdlhUaHlYZnl2K0QvYW9IaGM4SnVTNSttdVJUM3lrNzlHRDhpUWNvRVhSWVVocnhPZ0dpblZIa3hEcHdDKzVob3gxc3dpd1FPOUV0bzVWZHdiNzJGUTViM0FtbytqRmM0Z01Qd3ZCVFJOZndVMExkaTQ5dTBiTy85NkZHYTZscStEUU5EL0ZzYTI1V2ErT0J5ZStIdGl0ZXp4anpsc29mRDBwci81RFZyT3QrRnlDTG9HVUFpc1NYSHJURkFtU09BWHB4bU1yRUhDSjJxWm9reS9CNmRqYzBXZFY0NnRacHUyeDJaQTNmVHpzbkpidGRSVzc4RHdVSW5mbnZOV2VyTzJYOGNLa0FuSzQ0QW5pcnJrTjFQV1F2VlljQldYZEY1TzZsTDRFVlpUZXF4cjhCdUdCMm5GdU9OellCSHpLUStiMzlxVnREZTZ0U3ZjM1VkblFUMmhPK1VreGVTRWhGRktGQzVJU3pFbE1TQ1liekcxd1RPZ0g3Q1p3V21SYWIwR25wYkN0eVhuZ0trdENXTWs4eEhiVHFnbzkzV3ZaQlArREVYNW53R3dObnhhbDMxN0JnbGNkOWk5ZEpPV2hOZ1pPcTJJWTU0V2c1Z2VjVVhIWDY1VFVTeG5YNzNyNmwxekNHcnhBQ2ZuN1NZMFpLS3BsZUhxVkdjYUJvMEFqbkpPMnJBQXNUbXVGdGlmbGpkU28wOC9HOUJvYktXbmptOUZwUFR0YjRsRnEyWVNxSXd1YkhoVnpxMU1STnRDalE5N1l0U0pYc1pnWG1hK1BHU0hrN3NMQUh0c0RXazlzNTA2aDJRUDlxR2V2K3JOa2pPMk1kU05ObEppTkxBVW1zZjlHWmIyL3V5cEVqMFNUVzBqYkg5Y3JXY1krYk14aThOZ2x3b3hEaGxaSkgxcE1IaEtJWWNRdVFqRjgzeXFZM0h2azF0Vk1GQmUrczdRYU96MXpNSTZ1d1pTTG1lZlpNYXYxSmVuelJ6Z0JkdlRsM3lRanZ5dkRiNXRNdjdIdllDdHo5d3B1MURKV1pZWWhpWWpsT0FKRmpCSG9keW1zQzdodTlHVW41dTlUZlpZOFVGZnM5TEVVV28zdzZYRGp4RmlyY0hxN0JhWUV5MXhHaWJjPSIsICJ3cmFwcGVkUmF3S2V5IjoiSzJRTVZ1dEVyQnZKQnVoUWFoR2Q4NkZRcTlsWGlSV1VWdU5YU2lHNFRNdWJTczd2MElMbDJ5YkY5MStWUUo4YkxqZGorLytCWlZvZlJUQ0kifQ=="
  }
}
```


the `ciphertext` is the encrypted AES key used to encrypt the layer

decoding `wrappedKey`:

```json
{
  "version": 1,
  "type": "ml_kem_768",
  "kemCipherText": "RP/vgxKFfp0UJAS5WZTBe3soRIYRNhrVDjTAs9TJ48k2ihqcpZOBKHIzY2ZaoXZMZBG5mTOh+mknJIt4JetH2689bMCdldJYUPp7YLz/MTUa83eCvozghuwNrRWsdOp0kdro6Vix92XHB8IX7Rno2z7Rr7xSlzJ877REyglFP17Zs7blLBgaDDTjh/GIp+S1hjnZH1FYp58lyDA/LHPtR3fQmrc7Xter/MTvhJYKoTq4b4etl5GiUojt9MRy8n27Wz4Deb+HMEUxKTvC8ip08mUuL0okOx+g7bcDH1OKiHG7VwKxXK32F0p+V/QiOiKVEz0Lw0K7EuRTH+UD5Zw3LmaxUBHM2y5RT/nd+EM7HMH3f0RP8L4CvT0t8x3ZgjUVL0GyylC44bbvgfC82KkrmhgCRM4y4ao8pjYLzW3vs3Vjt4RYcF1UXEDfwXhALR11A5sZYRBsVQhZZ9MwbaJA57OFxNkyewxLca1Qezsvtv5SW45tJaamBtWOvHVZKn7RI6y1169knFLbNNYAHdHVmAtE7TTSnVwce2hm4fmw6mMQl8M5we5NNNUxQdsiVxxmE7lkxC1HtAoxHZ4DCyBCef+gvEvXThyXfyv+D/aoHhc8JuS5+muRT3yk79GD8iQcoEXRYUhrxOgGinVHkxDpwC+5hox1swiwQO9Eto5Vdwb72FQ5b3Amo+jFc4gMPwvBTRNfwU0Ldi49u0bO/96FGa6lq+DQND/Fsa25Wa+OBye+HtitezxjzlsofD0pr/5DVrOt+FyCLoGUAisSXHrTFAmSOAXpxmMrEHCJ2qZoky/B6djc0WdV46tZpu2x2ZA3fTzsnJbtdRW78DwUInfnvNWerO2X8cKkAnK44AnirrkN1PWQvVYcBWXdF5O6lL4EVZTeqxr8BuGB2nFuONzYBHzKQ+b39qVtDe6tSvc3UdnQT2hO+UkxeSEhFFKFC5ISzElMSCYbzG1wTOgH7CZwWmRab0GnpbCtyXngKktCWMk8xHbTqgo93WvZBP+DEX5nwGwNnxal317Bglcd9i9dJOWhNgZOq2IY54Wg5gecUXHX65TUSxnX73r6l1zCGrxACfn7SY0ZKKpleHqVGcaBo0AjnJO2rAAsTmuFtifljdSo08/G9BobKWnjm9FpPTtb4lFq2YSqIwubHhVzq1MRNtCjQ97YtSJXsZgXma+PGSHk7sLAHtsDWk9s506h2QP9qGev+rNkjO2MdSNNlJiNLAUmsf9GZb2/uypEj0STW0jbH9crWcY+bMxi8NglwoxDhlZJH1pMHhKIYcQuQjF83yqY3Hvk1tVMFBe+s7QaOz1zMI6uwZSLmefZMav1JenzRzgBdvTl3yQjvyvDb5tMv7HvYCtz9wpu1DJWZYYhiYjlOAJFjBHodymsC7hu9GUn5u9TfZY8UFfs9LEUWo3w6XDjxFircHq7BaYEy1xGibc=",
  "wrappedRawKey": "K2QMVutErBvJBuhQahGd86FQq9lXiRWUVuNXSiG4TMubSs7v0ILl2ybF91+VQJ8bLjdj+/+BZVofRTCI"
}
```

1. generate a random AES key `S1`
2. generate ML Kem shared secret `S2` and its corresponding encrypted form`kemCipherText`
3. use `S2` to encrypt `S1` then save the result as `wrappedRawKey`
4. generate a AES key, `S3` which is used to encrypt the OCI layer
5. use `S1` to encrypt the layer encryption key `S3`  and save as `ciphertext`    