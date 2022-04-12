import sys, getopt
from Crypto.Cipher import AES
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
    key = bytes.fromhex(sf.readline()[len("key: "):len("key: ")+32]) # type should be byte string
    sqn = int(sf.readline()[len("sqn: "):], base=10) # type should be integer

# read the content of the input file into payload
with open(inputfile, 'rb') as inf:
    payload = inf.read()

# compute payload_length and set authtag_length
payload_length = len(payload)
authtag_length = 12 # we'd like to use a 12-byte long authentication tag 

# compute message length...
# header: 16 bytes
#    version: 2 bytes
#    type:    1 btye
#    length:  2 btyes
#    sqn:     4 bytes
#.   rnd:     7 bytes
# payload: payload_length
# authtag: authtag_length
msg_length = 16 + payload_length + authtag_length

# create header
header_version = b'\x03\x07'                            # protocol version 3.7
header_type = b'\x01'                                   # message type 1
header_length = msg_length.to_bytes(2, byteorder='big') # message length (encoded on 2 bytes)
header_sqn = (sqn + 1).to_bytes(4, byteorder='big')     # next message sequence number (encoded on 4 bytes)
header_rnd = Random.get_random_bytes(7)                 # 7-byte long random value
header = header_version + header_type + header_length + header_sqn + header_rnd

# encrypt the payload and compute the authentication tag over the header and the payload
# with AES in GCM mode using nonce = header_sqn + header_rnd
nonce = header_sqn + header_rnd
AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=authtag_length)
AE.update(header)
encrypted_payload, authtag = AE.encrypt_and_digest(payload)

# write out the header, the encrypted_payload, and the authtag
with open(outputfile, 'wb') as outf:
    outf.write(header + encrypted_payload + authtag)

# save state
state =  "key: " + key.hex() + '\n'
state += "sqn: " + str(sqn + 1)
with open(statefile, 'wt') as sf:
    sf.write(state)
