import sys, getopt
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util import Padding
from Crypto import Random

statefile  = 'sndstate.txt'
outputfile = 'message.bin' # default output
inputfile  = None

try:
    opts, args = getopt.getopt(sys.argv[1:],'ho:', ['help', 'outputfile='])
except getopt.GetoptError:
    print('Error: Unknown option detected.')
    print('Type "send.py -h" for help.')
    sys.exit(1)

for opt, arg in opts:
    if opt in ('-h', '--help'):
        print('Usage:')
        print('  send.py [-o <outputfile>] <inputfile>')
        print('  send.py [--outputfile <outputfile>] <inputfile>')
        sys.exit(0)
    elif opt in ('-o', '--outputfile'):
        outputfile = arg

if len(args) < 1:
    print('Error: Input file name is missing.')
    print('Type "send.py -h" for help.')
    sys.exit(1)
else:
    inputfile = args[0]


# read the content of the state file
with open(statefile, 'rt') as sf:
    enckey = bytes.fromhex(sf.readline()[len("enckey: "):len("enckey: ")+32]) # type should be byte string
    mackey = bytes.fromhex(sf.readline()[len("mackey: "):len("mackey: ")+32]) # type should be byte string
    sndsqn = int(sf.readline()[len("sndsqn: "):], base=10) # type should be integer

# read the content of the input file into payload
with open(inputfile, 'rb') as inf:
    payload = inf.read()

# compute payload_length and padding_length, and set mac_length 
payload_length = len(payload)
padding_length = AES.block_size - payload_length%AES.block_size
mac_length = 32  # SHA256 hash value is 32 bytes long

# compute message length...
# header: 9 bytes
#    version: 2 bytes
#    type:    1 btye
#    length:  2 btyes
#    sqn:     4 bytes
# iv: AES.block_size
# payload: payload_length
# padding: padding_length
# mac: mac_length
msg_length = 9 + AES.block_size + payload_length + padding_length + mac_length

# create header
header_version = b'\x03\x06'                            # protocol version 3.6
header_type = b'\x01'                                   # message type 1
header_length = msg_length.to_bytes(2, byteorder='big') # message length (encoded on 2 bytes)
header_sqn = (sndsqn + 1).to_bytes(4, byteorder='big')  # next message sequence number (encoded on 4 bytes)
header = header_version + header_type + header_length + header_sqn 

# pad the payload and encrypt the padded payload with AES in CBC mode using a random iv
iv = Random.get_random_bytes(AES.block_size)
ENC = AES.new(enckey, AES.MODE_CBC, iv)
padded_payload = Padding.pad(payload, AES.block_size, style='iso7816')
encrypted_payload = ENC.encrypt(padded_payload)

# compute the mac on the header, iv, and encrypted payload
MAC = HMAC.new(mackey, digestmod=SHA256)
MAC.update(header + iv + encrypted_payload)
mac = MAC.digest()

# write out the header, iv, encrypted payload, and the mac
with open(outputfile, 'wb') as outf:
    outf.write(header + iv + encrypted_payload + mac)

# save state
state =  "enckey: " + enckey.hex() + '\n'
state += "mackey: " + mackey.hex() + '\n'
state += "sndsqn: " + str(sndsqn + 1)
with open(statefile, 'wt') as sf:
    sf.write(state)
