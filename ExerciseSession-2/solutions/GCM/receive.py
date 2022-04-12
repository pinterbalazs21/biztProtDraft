import sys, getopt
from Crypto.Cipher import AES

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
    key = bytes.fromhex(sf.readline()[len("key: "):len("key: ")+32]) # type should be byte string
    rcvsqn = int(sf.readline()[len("sqn: "):], base=10) # type should be integer

# read the content of the input file into variable msg
with open(inputfile, 'rb') as inf:
    msg = inf.read()

# parse the message msg
header = msg[0:16]                # header is 16 bytes long
authtag = msg[-12:]               # last 12 bytes is the authtag
encrypted_payload = msg[16:-12]   # encrypted payload is between header and authtag
header_version = header[0:2]      # version is encoded on 2 bytes 
header_type = header[2:3]         # type is encoded on 1 byte 
header_length = header[3:5]       # msg length is encoded on 2 bytes 
header_sqn = header[5:9]          # msg sqn is encoded on 4 bytes 
header_rnd = header[9:16]         # random is encoded on 7 bytes 

print("Message header:")
print("   - protocol version: " + header_version.hex() + " (" + str(header_version[0]) + "." + str(header_version[1]) + ")")
print("   - message type: " + header_type.hex() + " (" + str(int.from_bytes(header_type, byteorder='big')) + ")")
print("   - message length: " + header_length.hex() + " (" + str(int.from_bytes(header_length, byteorder='big')) + ")")
print("   - message sequence number: " + header_sqn.hex() + " (" + str(int.from_bytes(header_sqn, byteorder='big')) + ")")
print("   - random value: " + header_rnd.hex())

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

# verify and decrypt the encrypted payload
print("Decryption and authentication tag verification is attempted...")
nonce = header_sqn + header_rnd
AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=12)
AE.update(header)
try:
    payload = AE.decrypt_and_verify(encrypted_payload, authtag)
except Exception as e:
    print("Error: Operation failed!")
    print("Processing completed.")
    sys.exit(1)
print("Operation was successful: message is intact, content is decrypted.")

# write payload out
if outputfile:
    with open(outputfile, 'wb') as outf:
        outf.write(payload)
    print("Payload is saved to " + outputfile)
else:
    print("Payload received:")
    print(payload)

# save state
state =  "key: " + key.hex() + '\n'
state += "sqn: " + str(sndsqn)
with open(statefile, 'wt') as sf:
    sf.write(state)
print("Receiving state is saved.")
print("Processing completed.")
