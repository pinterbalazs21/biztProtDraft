CTR exercise
============

During this exercise, we will use the following classes and functions:
- AES block cipher
- Random module to generate cryptographically strong random values
- `Util.Counter` module to create counters

These are useful references to the relevant parts of the PyCryptodome documentation:
- https://pycryptodome.readthedocs.io/en/latest/
- https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
- https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#ctr-mode
- https://pycryptodome.readthedocs.io/en/latest/src/util/util.html#crypto-util-counter-module
- https://pycryptodome.readthedocs.io/en/latest/src/random/random.html


CTR mode encryption utility app
-------------------------------

A skeleton of the app is provided as `aes-ctr-skeleton.py`. Make a copy of this file under the name `aes-ctr.py` and open it. 

The command line parameters are handled in the same way as in case of the CBC encryption utility.

As before, parts of the encryption and decryption part are given, but the code is incomplete. Your task is to complete it. 

In the encryption part, replace `___` with a function parameter or function name.

In the decryption part, almost everything is missing and you should write that part by following the instructions in the comments.

You can test your program by trying to decrypt the given file `test-ctr.crypted` with the key string `aes-ctr-test-key`:

```bash
$ python3 aes-ctr.py -d -o test-ctr.txt test-ctr.crypted "aes-ctr-test-key"
```
