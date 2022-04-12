import sys, getopt, getpass
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto import Random


def save_publickey(pubkey, pubkeyfile):
    with open(pubkeyfile, 'wb') as f:
        f.write(pubkey.export_key(format='PEM'))

def load_publickey(pubkeyfile):
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)
        sys.exit(1)

def save_keypair(keypair, privkeyfile):
    #The key pair contains the private key, so we want to save it protected with a passphrase
    #We use the getpass() function of the getpass class to input the passphrase from the user 
    passphrase = getpass.getpass('Enter a passphrase to protect the saved private key: ')

    #TODO: Export the key pair in PEM format protected with the passphrase and 
    #      save the result in the file privkeyfile 



def load_keypair(privkeyfile):
    #We will need the passphrase to get access to the private key 
    #TODO: Input the passphrase from the user 
    #passphrase = ... 

    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        #TODO: Import the key pair and return it
        #return ...
    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)

def newline(s):
    return s + b'\n'

# ----------------------------------
# processing command line parameters
# ----------------------------------

operation = None
pubkeyfile = None
privkeyfile = None
inputfile = None
outputfile = None
sign = False

#TODO: Inspect the code and try to understand what command line parameters will be expected...
try:
    opts, args = getopt.getopt(sys.argv[1:], 'hkedp:s:i:o:', ['help', 'kpg', 'enc', 'dec', 'pubkeyfile=', 'privkeyfile=', 'inputfile=', 'outputfile='])
except getopt.GetoptError:
    print('Usage:')
    print('  - RSA key pair generation:')
    print('    hybrid.py -k -p <pubkeyfile> -s <privkeyfile>')
    print('  - encryption with optional signature generation:')
    print('    hybrid.py -e -p <pubkeyfile> [-s <privkeyfile>] -i <inputfile> -o <outputfile>')
    print('  - decryption with optional signature verification:')
    print('    hybrid.py -d -s <privkeyfile> [-p <pubkeyfile>] -i <inputfile> -o <outputfile>')
    sys.exit(1)

#TODO: Inspect the code and try to understand how command line parameters are handled...
for opt, arg in opts:
    if opt in ('-h', '--help'):
        print('Usage:')
        print('  - RSA key pair generation:')
        print('    hybrid.py -k -p <pubkeyfile> -s <privkeyfile>')
        print('  - encryption with optional signature generation:')
        print('    hybrid.py -e -p <pubkeyfile> [-s <privkeyfile>] -i <inputfile> -o <outputfile>')
        print('  - decryption with optional signature verification:')
        print('    hybrid.py -d -s <privkeyfile> [-p <pubkeyfile>] -i <inputfile> -o <outputfile>')
        sys.exit(0)
    elif opt in ('-k', '--kpg'):
        operation = 'kpg'
    elif opt in ('-e', '--enc'):
        operation = 'enc'    
    elif opt in ('-d', '--dec'):
        operation = 'dec'    
    elif opt in ('-p', '--pubkeyfile'):
        pubkeyfile = arg
    elif opt in ('-s', '--privkeyfile'):
        privkeyfile = arg
    elif opt in ('-i', '--inputfile'):
        inputfile = arg
    elif opt in ('-o', '--outputfile'):
        outputfile = arg

#Handling missing or wrongly given parameters...

#TODO: Handle a wrongly given operation 
#if operation not in ...:
    print('Error: Operation must be -k (for key pair generation) or -e (for encryption) or -d (for decryption).')
    sys.exit(1)

#Handle a missing public key file... 
#Print an error if pubkeyfile is empty and the operation is 'enc' or 'kpg'
if (not pubkeyfile) and (operation == 'enc' or operation == 'kpg'):
    print('Error: Name of the public key file is missing.')
    sys.exit(1)

#TODO: Handle a missing private key file... 
#      Print an error if privkeyfile is empty and the operation is 'dec' or 'kpg'
#if ... and ...:
    print('Error: Name of the private key file is missing.')
    sys.exit(1)

#TODO: Handle a missing input file... 
#      Print an error if inputfile is empty and the operation is 'enc' or 'dec'
#if ... and ...:
    print('Error: Name of input file is missing.')
    sys.exit(1)

#TODO: Handle a missing output file...
#      Print an error if outputfile is empty and the operation is 'enc' or 'dec'
#if ... and ...:
    print('Error: Name of output file is missing.')
    sys.exit(1)

#If operation is 'enc' and a private key file is given, we also need to sign the output...
if (operation == 'enc') and privkeyfile: 
    sign = True

# -------------------
# key pair generation
# -------------------

if operation == 'kpg': 
    print('Generating a new 2048-bit RSA key pair...')
    #TODO: Generate a new 2048-bit RSA key pair
    #keypair = ...

    #TODO: Save the public part of the key pair in pubkeyfile
    #save_publickey(..., pubkeyfile)

    #Save the entire key pair in privkeyfile
    save_keypair(keypair, privkeyfile)
    print('Done.')

# ----------
# encryption
# ----------

elif operation == 'enc': 
    print('Encrypting...')

    #TODO: Load the public key from pubkeyfile and 
    #      create an RSA cipher object
    #pubkey = ...
    #RSAcipher = ...

    #Read the plaintext from the input file
    with open(inputfile, 'rb') as f: 
        plaintext = f.read()

    #TODO: Apply PKCS7 padding on the plaintext (we want to use AES)
    #padded_plaintext = ...
	
    #TODO: Generate a random symmetric key and create an AES cipher object in CBC mode
    #symkey = ... # we need a 256-bit (32-byte) AES key
    #AEScipher = ...

    #TODO: Store the IV of the AES cipher object in a variable (you'll need it later) 
    #iv = ...

    #TODO: Encrypt the padded plaintext with the AES cipher
    #ciphertext = ...

    #TODO: Encrypt the AES key with the RSA cipher
    #encsymkey = ...

    #Compute signature if needed
    #TODO: Inspect the code to understand how to generate a signature... 
    if sign:
        keypair = load_keypair(privkeyfile)
        signer = pss.new(keypair)
        hashfn = SHA256.new()
        hashfn.update(encsymkey+iv+ciphertext)
        signature = signer.sign(hashfn)

    #Write out the encrypted AES key, the IV, the ciphertext, 
    #and the signature in base64 encoding
    with open(outputfile, 'wb') as f:
        f.write(newline(b'--- ENCRYPTED AES KEY ---'))
        f.write(newline(b64encode(encsymkey)))
        f.write(newline(b'--- IV FOR CBC MODE ---'))
        f.write(newline(b64encode(iv)))
        f.write(newline(b'--- CIPHERTEXT ---'))
        f.write(newline(b64encode(ciphertext)))
        if sign:
            f.write(newline(b'--- SIGNATURE ---'))
            f.write(newline(b64encode(signature)))

    print('Done.')

# ----------
# decryption
# ----------

elif operation == 'dec':
    print('Decrypting...')

    #Read and parse the input...
    #TODO: Inspect the code to understand how the different parts of the ciphertext
    #      are recognized based on the delimiter lines and processed... 
    encsymkey = b''
    iv = b''
    ciphertext = b''

    with open(inputfile, 'rb') as f:        
        sep = f.readline()
        while sep:
            data = f.readline()
            data = data[:-1]   # removing \n from the end
            sep = sep[:-1]     # removing \n from the end

            if sep == b'--- ENCRYPTED AES KEY ---':
                encsymkey = b64decode(data)
            elif sep == b'--- IV FOR CBC MODE ---':
                iv = b64decode(data)
            elif sep == b'--- CIPHERTEXT ---':
                ciphertext = b64decode(data)
            elif sep == b'--- SIGNATURE ---':
                signature = b64decode(data)
                sign = True

            sep = f.readline()

    if (not encsymkey) or (not iv) or (not ciphertext):
        print('Error: Could not parse content of input file ' + inputfile)
        sys.exit(1)

    if sign and (not pubkeyfile):
        print('Error: Public key file is missing for  ' + inputfile)
        sys.exit(1)

    #Verify signature if needed...
    if sign:
        if not pubkeyfile:
            print('Error: Public key file is missing, signature cannot be verified.')
        else:
            #TODO: Write the signature verification code here...
            #      - load the public key from pubkeyfile
            #      - create an RSA PSS verifier object
            #      - create a SHA256 object
            #      - hash encsymkey+iv+ciphertext with SHA256
            #      - call the verify function of the verifier object in a try clause
            #      - if the signature is valid, then print a success message and go on
            #      - if the signature is invalid, then an excpetion is thrown, catch it and print 
            #        and error message, and then ask the user if he/she wants to continue nevetheless
            #...
            try:
                #...
            except (ValueError, TypeError):
                #...
                yn = input('Do you want to continue nevertheless (y/n)? ')
                if yn != 'y': 
                    sys.exit(1)

    #TODO:Load the private key (key pair) from privkeyfile and 
    #     create the RSA cipher object
    #keypair = ...
    #RSAcipher = ...

    #TODO: Decrypt the AES key and create the AES cipher object (CBC mode is used)
    #symkey = ...
    #AEScipher = ...	
	
    #TODO: Decrypt the ciphertext and remove padding
    #padded_plaintext = ...
    #plaintext = ...
	
    #Write out the plaintext into the output file
    with open(outputfile, 'wb') as f:
        f.write(plaintext)
	
    print('Done.')
