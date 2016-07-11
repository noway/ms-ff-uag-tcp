# ms-ff-uag-tcp

Supposedly should work with MS FF UAG 2010

## Usage
1. Install
2. cp -a config-example config
3. vi config/creds.txt
4.
```bash
./ms-ff-uag-tcp --init --quiet 2
./ms-ff-uag-tcp --server 127.0.0.1:8080 --quiet 2
./ms-ff-uag-tcp --client 127.0.0.1:8080 --quiet 2
```
