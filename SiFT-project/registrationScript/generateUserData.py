import csv
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

userData = {
    "admin": "almakortezsemle",
    "a": "a",
    "alice": "aaa",
    "bob": "bbb",
    "charlie": "ccc"
}

userdatafile = '../userdata.csv'


def create_hash(pwd):  # same as in server login protocol, but generates salt itself
    salt = get_random_bytes(16)
    pwdhash = scrypt(pwd, salt, 16, N=2 ** 14, r=8, p=1)
    return pwdhash, salt


with open(userdatafile, 'w', newline='') as userdatacsv:
    userdatawriter = csv.writer(userdatacsv, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    for key in userData.keys():
        pwdhash, salt = create_hash(userData[key])
        userdatawriter.writerow([key, pwdhash.hex(), salt.hex()])
