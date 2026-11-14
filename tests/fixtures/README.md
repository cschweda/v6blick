# Test fixtures

- `test-cert-a.pem`, `test-key-a.pem`, `test-cert-b.pem`, `test-key-b.pem`: two self-signed certificates and their keys, for the local test servers in `tests/`. They are for `v6blick.test`, `*.v6blick.test` and `localhost`, and run until 2126. The keys are public by being here; they protect nothing and must not be used for anything else.

Made with:

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 36500 \
  -subj "/CN=v6blick test certificate a" \
  -addext "subjectAltName=DNS:v6blick.test,DNS:*.v6blick.test,DNS:localhost" \
  -keyout test-key-a.pem -out test-cert-a.pem
```
