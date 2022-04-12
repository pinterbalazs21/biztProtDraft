import sys, getopt
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random

try:
    opts, args = getopt.getopt(sys.argv[1:],'hdo:', ['help', 'decode', 'outputfile='])
except getopt.GetoptError:
    print('Error: Unknown option detected.')
    print('Type "aes-ctr.py -h" for help.')
    sys.exit(1)

operation = 'encode' # default operation
keystring = None
outputfile = None

for opt, arg in opts:
    if opt in ('-h', '--help'):
        print('Usage:')
        print('  aes-ctr.py [-d -o <outputfile>] <inputfile> <keystring>')
        print('  aes-ctr.py [--decode --outputfile <outputfile>] <inputfile> <keystring>')
        sys.exit(0)
    elif opt in ('-d', '--decode'):
        operation = 'decode'
    elif opt in ('-o', '--outputfile'):
        outputfile = arg

if len(args) < 2:
    print('Error: Input file name or key string is missing.')
    print('Type "aes-ctr.py -h" for help.')
    sys.exit(1)
else:
    inputfile = args[0]
    keystring = args[1]

if not outputfile:
    outputfile = inputfile
    print('Warning: No output file name was given, input file will be overwritten.')

#print('Input file name:  ' + inputfile)
#print('Output file name: ' + outputfile)
#print('Key string: ' + keystring)
#print('Key bytes:  ' + hex(int.from_bytes(keystring.encode('ascii'), byteorder='big')))
#print('Operation: ' + operation)

# encryption
if operation == 'encode': 
    print('Encrypting...', end='')
    
    # read the content of the input file into a variable called plaintext
    ifile = open(inputfile, 'rb')
    plaintext = ifile.read()
    ifile.close()

    # generate a 64-bit random nonce to be used as a prefix of the counter
    nonce = Random.get_random_bytes(8)

    # create a counter object, set the nonce as its prefix and set the initial counter value to 0 
    ctr = Counter.new(64, prefix=nonce, initial_value=0)

    # create an AES-CTR cipher object
    key = keystring.encode('ascii')
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    
    # encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext)

    # write out the nonce and the ciphertext into the output file
    ofile = open(outputfile, "wb")
    ofile.write(nonce + ciphertext)
    ofile.close()

# decryption
else:
    print('Decrypting...', end='')

   # read the saved nonce and the ciphertext from the input file
    ifile = open(inputfile, 'rb')
    nonce = ifile.read(8)
    ciphertext = ifile.read()
    ifile.close()

    # intialize a counter with the nonce as prefix and initial counter value 0 
    ctr = Counter.new(64, prefix=nonce, initial_value=0)

    # create AES-CTR cipher object
    key = keystring.encode('ascii')
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    # decrypt ciphertext
    plaintext = cipher.decrypt(ciphertext)
    
    # write out the plaintext obtained into the output file
    ofile = open(outputfile, "wb")
    ofile.write(plaintext)
    ofile.close()

print('Done.')