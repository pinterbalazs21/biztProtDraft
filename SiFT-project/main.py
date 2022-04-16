# This is a sample Python script.
from MTP import MTP
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')

    key = b'\x81\xce\xb8\xf2\xc0\x94\x00\x1a#\x82c\x15/o\x9eE\xf0W\xf5\xac\xf5%$\x1a\xd6(\x06\xc1\xa0\x8cI\x14'
    MTP_handler = MTP()
    payload = b'BATMAN'
    encrypted = MTP_handler.encriptAndAuth(key, b'\x00\x00', payload, 1, 12 + 16 +len(payload))
    dec = MTP_handler.decryptAndVerify(key, encrypted)
    print(dec)
# See PyCharm help at https://www.jetbrains.com/help/pycharm/
