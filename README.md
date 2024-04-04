# trtool

This is a tool to work with Sigstore [Trusted
Roots](https://github.com/sigstore/protobuf-specs/blob/5ef54068bb534152474c5685f5cd248f38549fbd/protos/sigstore_trustroot.proto#L82).

The trtool project aims to follow the Unix philosophy as much as
possible, which implies "Rule of Silence", if nothing unexpected
happens the program stays silent.

This project is still in pre-alpha.

## Examples

### Initialize a trust root

```shell
$ ./trtool init \
    -ca test_data/fulcio-chain.pem \
    -ca-start 2024-04-03T00:00:00Z \
    -ca-uri https://fulcio.test.foo | jq > tr.json
```

### Add an artifact signature transparency log

```shell
$ ./trtool add -f tr.json \
    -type tlog \
    -uri https://foo.bar \
    -pem test_data/rekor.pkcs1.pem \
    -start 2024-04-03T00:00:00Z | jq > tr2.json
```

### Add a certificate transparency log

```shell
$ ./trtool add -f tr2.json \
    -type ctlog \
    -uri https://ct.bar \
    -pem test_data/rekor.pkix.pem \
    -start 2024-04-03T00:00:00Z | jq > tr3.json
```

Inspect the final result
```json
{
  "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
  "tlogs": [
    {
      "baseUrl": "https://foo.bar",
      "hashAlgorithm": "SHA2_256",
      "publicKey": {
        "rawBytes": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyuEumAOUjCAEM2unKrmJohSqGzAH6+TsETWSPYsB98xDIO5zdL43LD/dpEXW9DnRdGYKnlDCLYyFYiR7/gToxmiZgprn45ZvNxQQDnwHuUdIVnfYvDV5nTSrqMW7WZ1bWckkw5P00BNVXLCWBW6KCGflcZODXd8Nrk8lWzl32iUbKh48WbumvfmcIBdrouXrJ/fzGV3OYLiIk9dMP6ux18cceJeeMyn2rTnSknOMQP95OsdOh0G22bSbQFtCnGeNW+TOXsA5q9w59V56/gqGZksOAqLcZu2IhLq33q8r6kh47t2kGcvBFi6QUuqzavT2zguEHdP7nQNCYzfioEo3zwIDAQAB",
        "keyDetails": "PKIX_RSA_PKCS1V15_2048_SHA256",
        "validFor": {
          "start": "2024-04-03T00:00:00Z"
        }
      },
      "logId": {
        "keyId": "/TKbCUU9CPkeXPLkZSBMayyIieby0t5s3hpm/mWvTDU="
      }
    }
  ],
  "certificateAuthorities": [
    {
      "subject": {
        "organization": "Umbrella Corporation",
        "commonName": "Root"
      },
      "uri": "https://fulcio.test.foo",
      "certChain": {
        "certificates": [
          {
            "rawBytes": "MIICCTCCAbCgAwIBAgIUHDmuvTRvs0QKLbLB0NzHRNv9uiowCgYIKoZIzj0EAwIwRzEdMBsGA1UEChMUVW1icmVsbGEgQ29ycG9yYXRpb24xJjAkBgNVBAMTHUZ1bGNpbyBJbnRlcm1lZGlhdGUgLSBvZmZsaW5lMB4XDTI0MDIwMzAwMDAwMFoXDTI1MDIwMjAwMDAwMFowRjEdMBsGA1UEChMUVW1icmVsbGEgQ29ycG9yYXRpb24xJTAjBgNVBAMTHEZ1bGNpbyBJbnRlcm1lZGlhdGUgLSBvbmxpbmUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASuVV0y56oOg+wDp1tuNqhO+kJN7v4LfWeybgXpymTS1iTJi9KG+C4vwHHIoDUm903ibl5hcrzHNfimhEIvGfUEo3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQURKRBGoDKyxxvYjKI1hf5XwgzqVUwHwYDVR0jBBgwFoAUSbfpoJQP5tM7K+6m+DH2rLIfnmowCgYIKoZIzj0EAwIDRwAwRAIgRl7ocUZySscxipHEsoR8pyq3CQq8eBtIk/ED9pfDVnACIBxf/2FPQ5OrGOtTvMATGobgVT7I47hq0ielUk4Ahu7X"
          },
          {
            "rawBytes": "MIIB3jCCAYOgAwIBAgIURCy5Zqzr3D6OLlWiCK4Wbd6nlXQwCgYIKoZIzj0EAwIwLjEdMBsGA1UEChMUVW1icmVsbGEgQ29ycG9yYXRpb24xDTALBgNVBAMTBFJvb3QwHhcNMjQwMjAzMDAwMDAwWhcNMjkwMjAxMDAwMDAwWjBHMR0wGwYDVQQKExRVbWJyZWxsYSBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdRnVsY2lvIEludGVybWVkaWF0ZSAtIG9mZmxpbmUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR1jMWmUFKDhsPSGJ5/JhIT/4Tu5jfhNPoxhvSHduDgypcVDHR1+0Z00sziPFO0xo6JcQ+Iy0LGHGatxNB7Al81o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUSbfpoJQP5tM7K+6m+DH2rLIfnmowHwYDVR0jBBgwFoAUD4GinE5klrSpTJF1qN/OOS3RdJkwCgYIKoZIzj0EAwIDSQAwRgIhAPKj4S458+h4ZGTEmew773VsnfQtg8QdnnkdMYrik1M5AiEAy31ef0w8KqhknNn6m3L1nLUxLfsQQ+KEyLYYpVQIfHE="
          },
          {
            "rawBytes": "MIIBojCCAUmgAwIBAgIUVDnTWXahSkBcdF4a07xIFFeur1YwCgYIKoZIzj0EAwIwLjEdMBsGA1UEChMUVW1icmVsbGEgQ29ycG9yYXRpb24xDTALBgNVBAMTBFJvb3QwHhcNMjQwMjAzMDAwMDAwWhcNMzQwMTMxMDAwMDAwWjAuMR0wGwYDVQQKExRVbWJyZWxsYSBDb3Jwb3JhdGlvbjENMAsGA1UEAxMEUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFElGoh/aqZ/RCy/IRd+7ZNggDS+cwRMMb501j5eH/qKH0k/mnY5Lq3duBX6BGD+Q5TtEo8tmQ24+Zy33QsUobmjRTBDMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgECMB0GA1UdDgQWBBQPgaKcTmSWtKlMkXWo3845LdF0mTAKBggqhkjOPQQDAgNHADBEAiBvOyX8IMiCTqMD1JC+qw8J3lqqmzaou4nwMbIlG8hbXAIgHaYjlnp7IMyJQ+nF6p/MXOK0Uh6S7vC6zRcVhBIbG1w="
          }
        ]
      },
      "validFor": {
        "start": "2024-04-03T00:00:00Z"
      }
    }
  ],
  "ctlogs": [
    {
      "baseUrl": "https://ct.bar",
      "hashAlgorithm": "SHA2_256",
      "publicKey": {
        "rawBytes": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyuEumAOUjCAEM2unKrmJohSqGzAH6+TsETWSPYsB98xDIO5zdL43LD/dpEXW9DnRdGYKnlDCLYyFYiR7/gToxmiZgprn45ZvNxQQDnwHuUdIVnfYvDV5nTSrqMW7WZ1bWckkw5P00BNVXLCWBW6KCGflcZODXd8Nrk8lWzl32iUbKh48WbumvfmcIBdrouXrJ/fzGV3OYLiIk9dMP6ux18cceJeeMyn2rTnSknOMQP95OsdOh0G22bSbQFtCnGeNW+TOXsA5q9w59V56/gqGZksOAqLcZu2IhLq33q8r6kh47t2kGcvBFi6QUuqzavT2zguEHdP7nQNCYzfioEo3zwIDAQAB",
        "keyDetails": "PKIX_RSA_PKCS1V15_2048_SHA256",
        "validFor": {
          "start": "2024-04-03T00:00:00Z"
        }
      },
      "logId": {
        "keyId": "/TKbCUU9CPkeXPLkZSBMayyIieby0t5s3hpm/mWvTDU="
      }
    }
  ]
}
```

### Verify the generated trust root

```shell
$ % ./trtool verify -f tr3.json
$ echo $?
0
```
