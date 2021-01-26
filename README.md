# Secure Chat

Secure_Chat is a peer to peer chat program developed over python sockets.
The data sent over network is secured using RSA and AES encryption.
Every Session gets its own set of keys.

## Installation

```bash
pip3 install pycryptodome
```

## Usage

```bash

python3 main.py -l 127.0.0.1 65432 # to start listener
python3 main.py -c 127.0.0.1 65432 # to start client

```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/)