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


# read the content of the state file
with open(statefile, 'rt') as sf:
    enckey = bytes.fromhex(sf.readline()[len("enckey: "):len("enckey: ")+32]) # type should be byte string
    mackey = bytes.fromhex(sf.readline()[len("mackey: "):len("mackey: ")+32]) # type should be byte string
    rcvsqn = int(sf.readline()[len("rcvsqn: "):], base=10) # type should be integer

# read the content of the input file into variable msg
with open(inputfile, 'rb') as inf:
    msg = inf.read()

# parse the message msg
header = msg[0:9]                              # header is 9 bytes long
iv = msg[9:9+AES.block_size]                   # iv is AES.block_size bytes long
mac = msg[-32:]                                # last 32 bytes is the mac
encrypted_payload = msg[9+AES.block_size:-32]  # encrypted payload is between iv and mac
header_version = header[0:2]                   # version is encoded on 2 bytes 
header_type = header[2:3]                      # type is encoded on 1 byte 
header_length = header[3:5]                    # msg length is encoded on 2 bytes 
header_sqn = header[5:9]                       # msg sqn is encoded on 4 bytes 

print("Message header:")
print("   - protocol version: " + header_version.hex() + " (" + str(header_version[0]) + "." + str(header_version[1]) + ")")
print("   - message type: " + header_type.hex() + " (" + str(int.from_bytes(header_type, byteorder='big')) + ")")
print("   - message length: " + header_length.hex() + " (" + str(int.from_bytes(header_length, byteorder='big')) + ")")
print("   - message sequence number: " + header_sqn.hex() + " (" + str(int.from_bytes(header_sqn, byteorder='big')) + ")")

# check the msg length
if len(msg) != int.from_bytes(header_length, byteorder='big'):
    print("Warning: Message length value in header is wrong!")
    print("Processing is continued nevertheless...")

# check the sequence number
print("Expecting sequence number " + str(rcvsqn + 1) + " or larger...")
sndsqn = int.from_bytes(header_sqn, byteorder='big')
if (sndsqn <= rcvsqn):
    print("Error: Message sequence number is too old!")
    print("Processing completed.")
    sys.exit(1)    
print("Sequence number verification is successful.")

# verify the mac
print("MAC verification is being performed...")
MAC = HMAC.new(mackey, digestmod=SHA256)
MAC.update(header + iv + encrypted_payload)
computed_mac = MAC.digest()
print("MAC value received: " + mac.hex())
print("MAC value computed: " + computed_mac.hex())
if (computed_mac != mac):
    print("Error: MAC verification failed!")
    print("Processing completed.")
    sys.exit(1)
print("MAC verified correctly.")

# decrypt the encrypted payload and remove padding
print("Decryption is attempted...")
ENC = AES.new(enckey, AES.MODE_CBC, iv)
try:
    padded_payload = ENC.decrypt(encrypted_payload)
    payload = Padding.unpad(padded_payload, AES.block_size, style='iso7816')
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

# save state
state =  "enckey: " + enckey.hex() + '\n'
state += "mackey: " + mackey.hex() + '\n'
state += "rcvsqn: " + str(sndsqn)
with open(statefile, 'wt') as sf:
    sf.write(state)
print("Receiving state is saved.")
print("Processing completed.")
