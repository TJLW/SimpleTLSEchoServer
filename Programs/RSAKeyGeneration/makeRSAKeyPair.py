# Make RSA Key Pair
#   Adopted from PyOpenSSL GitHub: https://github.com/pyca/pyopenssl/tree/master/examples

import sys
from OpenSSL import crypto
from certgen import *

# Require ID argument
if len(sys.argv) < 3:
    print('Usage: python makeRSAKeyPair.py ID SIZE [OPTIONS]')
    print('OPTIONS:')
    print('  -d <DirectoryPath>    Provide directory to save keys')
    sys.exit(1)

ID = sys.argv[1]
size = int(sys.argv[2])

# Options
keyPath = ''
for i in range(3,len(sys.argv)):
    # Output to specified directory instead of current directory
    if sys.argv[i] == '-d' and len(sys.argv) > i+1:
        keyPath = sys.argv[i+1]


privateKeyFilename = keyPath + '/' + ID + '.pkey'
publicKeyFilename = keyPath + '/' + ID + '.pubkey'

key = createKeyPair(crypto.TYPE_RSA, size)

print('Creating private key "' + privateKeyFilename)
with open(privateKeyFilename, 'w') as pkey:
    pkey.write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8')
    )

print('Creating public key "' + publicKeyFilename)
with open(publicKeyFilename, 'w') as pubkey:
    pubkey.write(
        crypto.dump_publickey(crypto.FILETYPE_PEM, key).decode('utf-8')
    )
