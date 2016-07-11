# ms-ff-uag-tcp

Supposedly should work with MS FF UAG 2010

## Usage

```bash
./ms-ff-uag-tcp --domain fileaccess.example.com --cafile ./creds/-.example.com.pem --auth ./creds/auth.txt --dir //server/share/you --init --quiet 1
./ms-ff-uag-tcp --domain fileaccess.example.com --cafile ./creds/-.example.com.pem --auth ./creds/auth.txt --dir //server/share/you --server 127.0.0.1:8080 --quiet 1
./ms-ff-uag-tcp --domain fileaccess.example.com --cafile ./creds/-.example.com.pem --auth ./creds/auth.txt --dir //server/share/you --client 127.0.0.1:8080 --quiet 1
```
