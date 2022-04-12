import sys, getopt
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util import Padding
from Crypto import Random

statefile  = 'rcvstate.txt'
inputfile  = 'message.bin' # default input
outputfile = None

try:
    opts, args = getopt.getopt(sys.argv[1:],'hi:', ['help', 'inputfile='])
except getopt.GetoptError:
    print('Error: Unknown option detected.')
    print('Type "receive.py -h" for help.')
    sys.exit(1)

for opt, arg in opts:
    if opt in ('-h', '--help'):
        print('Usage:')
        print('  receive.py [-i <inputfile>] [<outputfile>]')
        print('  receive.py [--inputfile <inputfile>] [<outputfile>]')
        sys.exit(0)
    elif opt in ('-i', '--inputfile'):
        inputfile = arg

if len(args) > 0:
    outputfile = args[0]


# TODO: read the content of the state file
with open(statefile, 'rt') as sf:
    enckey = ... # type should be byte string
    mackey = ... # type should be byte string
    rcvsqn = ... # type should be integer

# read the content of the input file into variable msg
with open(inputfile, 'rb') as inf:
    msg = inf.read()

# TODO: parse the message msg
header = msg[...]                              # header is 9 bytes long
iv = msg[...]                                  # iv is AES.block_size bytes long
mac = msg[...]                                 # last 32 bytes is the mac
encrypted_payload = msg[...]                   # encrypted payload is between iv and mac
header_version = header[...]                   # version is encoded on 2 bytes 
header_type = header[...]                      # type is encoded on 1 byte 
header_length = header[...]                    # msg length is encoded on 2 bytes 
header_sqn = header[...]                       # msg sqn is encoded on 4 bytes 

print("Message header:")
print("   - protocol version: " + header_version.hex() + " (" + str(header_version[0]) + "." + str(header_version[1]) + ")")
print("   - message type: " + header_type.hex() + " (" + str(int.from_bytes(header_type, byteorder='big')) + ")")
print("   - message length: " + header_length.hex() + " (" + str(int.from_bytes(header_length, byteorder='big')) + ")")
print("   - message sequence number: " + header_sqn.hex() + " (" + str(int.from_bytes(header_sqn, byteorder='big')) + ")")

# TODO: check the msg length
if len(msg) != ...:
    print("Warning: Message length value in header is wrong!")
    print("Processing is continued nevertheless...")

# TODO: check the sequence number
print("Expecting sequence number " + str(rcvsqn + 1) + " or larger...")
sndsqn = ... # the value of sqn in the header, should be of type integer 
if (sndsqn ... rcvsqn):
    print("Error: Message sequence number is too old!")
    print("Processing completed.")
    sys.exit(1)    
print("Sequence number verification is successful.")

# TODO: verify the mac
print("MAC verification is being performed...")
MAC = HMAC.new(...)
MAC.update(...)
computed_mac = MAC.digest()
print("MAC value received: " + mac.hex())
print("MAC value computed: " + computed_mac.hex())
if (...):
    print("Error: MAC verification failed!")
    print("Processing completed.")
    sys.exit(1)
print("MAC verified correctly.")

# TODO: decrypt the encrypted payload and remove padding
print("Decryption is attempted...")
ENC = AES.new(...)
try:
    padded_payload = ...
    payload = ...
except Exception as e:
    print("Error: Decryption failed!")
    print("Processing completed.")
    sys.exit(1)
print("Decryption was successful.")

# write the payload out
if outputfile:
    with open(outputfile, 'wb') as outf:
        outf.write(payload)
    print("Payload is saved to " + outputfile)
else:
    print("Payload received:")
    print(payload)

# TODO: save state
state =  "enckey: " + ... + '\n'
state += "mackey: " + ... + '\n'
state += "rcvsqn: " + ...
with open(statefile, 'wt') as sf:
    sf.write(state)
print("Receiving state is saved.")
print("Processing completed.")
