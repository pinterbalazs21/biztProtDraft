CBC exercise
============

During this exercise, we will use the following classes and functions:
- AES block cipher
- `Util.Padding` module to pad and unpad messages when using CBC mode

These are useful references to the relevant parts of the PyCryptodome documentation:
- https://pycryptodome.readthedocs.io/en/latest/
- https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
- https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode


CBC mode encryption utility app
-------------------------------

A skeleton of the app is provided as `aes-cbc-skeleton.py`. Make a copy of this file under the name `aes-cbc.py` and open it. 

The code skeleton already contains the handling of command line parameters. Inspect what options and arguments are expected by the program and what constraints they need to satisfy for the program to run successfully.

Parts of the encryption and decryption are given, but the code is incomplete. Your task is to complete it. 

In the encryption part, only parameters or function names are missing, these missing items are marked with `___`, and you should replace `___` with the appropriate function parameter or function name.

In the decryption part, more stuff is missing and these missing parts are marked with `...` You should replace `...` with an entire function call or line of code.

When the program is completed, you can test it by trying to decrypt the given file `test-cbc.crypted` with the key string `aes-cbc-test-key`:

```bash
$ python3 aes-cbc.py -d -o test-cbc.txt test-cbc.crypted "aes-cbc-test-key"
```


