# ov
- this is a toy project for learning how to capture TLS client hello ja3 fingerprint using cilium/eBPF
  - based on [this repo](https://github.com/open-ch/ja3)
- build (you must prepare yourself the eBPF toolchain first)
```bash
# if you are a just user
just

# if not...
BPF_CLANG=clang-14 BPF_CFLAGS="-O2 -g -Wall -Werror" go generate -v ./...
cd ja3 && go build
```

# test
- you can launch a local https server for test
- generate a self-signed certificate by checking this [stackoverflow](https://stackoverflow.com/questions/10175812/how-to-generate-a-self-signed-ssl-certificate-using-openssl/41366949#41366949)
```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout example.key -out example.crt -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.net,IP:127.0.0.1"
```
- under the same dir, launch a simple python https server
```python
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

port = 4443
httpd = HTTPServer(('0.0.0.0', port), SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, keyfile='example.key', certfile="example.crt", server_side=True)

print("Server running on https://0.0.0.0:" + str(port))

httpd.serve_forever()
```
- and then send a http request
```
# here using HTTPie
http --verify=example.crt https://127.0.0.1:4443/
```
