import sys, getopt
from Crypto.Cipher import AES
from Crypto.Util import Padding

try:
    opts, args = getopt.getopt(sys.argv[1:],'hdo:', ['help', 'decode', 'outputfile='])
except getopt.GetoptError:
    print('Error: Unknown option detected.')
    print('Type "aes-cbc.py -h" for help.')
    sys.exit(1)

operation = 'encode' # default operation
keystring = None
outputfile = None

for opt, arg in opts:
    if opt in ('-h', '--help'):
        print('Usage:')
        print('  aes-cbc.py [-d -o <outputfile>] <inputfile> <keystring>')
        print('  aes-cbc.py [--decode --outputfile <outputfile>] <inputfile> <keystring>')
        sys.exit(0)
    elif opt in ('-d', '--decode'):
        operation = 'decode'
    elif opt in ('-o', '--outputfile'):
        outputfile = arg

if len(args) < 2:
    print('Error: Input file name or key string is missing.')
    print('Type "aes-cbc.py -h" for help.')
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

    # apply PKCS7 padding on the plaintext
    padded_plaintext = Padding.pad(plaintext, AES.block_size)
    
    # create an AES-CBC cipher object
    key = keystring.encode('ascii')
    cipher_CBC = AES.new(key, AES.MODE_CBC)
    iv = cipher_CBC.iv
    # also create an AES-ECB object for encrypting the IV
    cipher_ECB = AES.new(key, AES.MODE_ECB)

    # encrypt the padded plaintext in CBC mode
    ciphertext = cipher_CBC.encrypt(padded_plaintext)
    # encrypt the IV in ECB mode
    encrypted_iv = cipher_ECB.encrypt(iv)

    # write out the encrypted IV and the ciphertext to the output file
    ofile = open(outputfile, "wb")
    ofile.write(encrypted_iv + ciphertext)
    ofile.close()

# decryption
else:
    print('Decrypting...', end='')

    # read the encrypted IV and the ciphertext from the input file
    ifile = open(inputfile, 'rb')
    encrypted_iv = ifile.read(AES.block_size)
    ciphertext = ifile.read()
    ifile.close()

    # create 2 AES cipher objects, one for decrypting the IV and one for decrypting the payload
    # and initialize these cipher objects with the appropriate parameters 
    key = keystring.encode('ascii')
    cipher_ECB = AES.new(key, AES.MODE_ECB)
    iv = cipher_ECB.decrypt(encrypted_iv) 
    cipher_CBC = AES.new(key, AES.MODE_CBC, iv) 
    
    # decrypt the ciphertext and remove padding
    padded_plaintext = cipher_CBC.decrypt(ciphertext)
    plaintext = Padding.unpad(padded_plaintext, AES.block_size)
    
    # write out the plaintext into the output file
    ofile = open(outputfile, "wb")
    ofile.write(plaintext)
    ofile.close()
    
print('Done.')