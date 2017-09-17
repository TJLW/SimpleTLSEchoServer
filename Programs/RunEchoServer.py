# RunEchoServer.py

import os
import select
import socket
import sys

import SCU


# Buffers
#   Key: connection object
clients = {}            # Client socket addresses
sessionKeys = {}        # Client session keys


# Removing client from buffers
def dropClient(connection, errors=None):
    if errors:
        print('Client %s left unexpectedly:' % (clients[connection],))
        print('  \n', errors)
    else:
        print('Client %s left politely\n' % (clients[connection],))
    del clients[connection]
    connection.close()


# Processes the data sent from clients
def processData(data, sessionKey):
    # Decrypt data
    response = SCU.decryptText(sessionKey, data, 'CBC', 'AES128')

    # Determine plaintext from response with length and padding characters removed
    plaintext = response.decode().split(':-:')[1].replace('0','')
    print('\n\tPlaintext: ' + str(plaintext))

    # Encrypt data for echo
    #   Returns: IV, cipher
    return SCU.encryptText(sessionKey, plaintext, 'CBC', 'AES128')


# ----------MAIN----------

# Check arguments
if len(sys.argv) < 2 or sys.argv[1] == '-h':
    print('Usage: python3 server.py PORT [options]')
    print(' Options:')
    print('\t-h                  Display this menu')
    sys.exit(1)

print('\n\nStarting Simple TLS Echo Server on port ' + sys.argv[1] + '...\n')

# Get options
# if len(sys.argv) > 2:
#     for optionIndex in range(2, len(sys.argv)):
#         # Enable option
#         if(sys.argv[optionIndex]) == "-[option]":
#             optionBool = True;

# Set directory to script location
dir = os.path.dirname(sys.argv[0])
if dir == '':
    dir = os.curdir

# Get RSA Keys
with open('ServerKeys/Server.pubkey', 'r') as pubKeyFile:
    serverPubKey = pubKeyFile.read()
with open('ServerKeys/Server.pkey', 'r') as privKeyFile:
    serverPrivKey = privKeyFile.read()
# print(serverPubKey)
# print(serverPrivKey)

# Set up TCP/IP  echo server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('', int(sys.argv[1])))
server.listen(5)

# Set options
# SCU.setOptions([options])

# Run until stopped
while True:

    # Wait for a connection
    print('Waiting for a connection...')
    connection, client_address = server.accept()
    clients[connection] = client_address

    try:
        print('\nConnection from: ' + str(client_address))

        # Do TLS handshake to get sessionKey
        sessionKeys[connection] = SCU.serverSimpleTLSHandshake(serverPubKey, serverPrivKey, connection)

        # Listen for encrypted message
        data = [0, 0]
        data[0] = connection.recv(1024)
        data[1] = connection.recv(1024)

        # Process and send encrypted echo
        if data[0] and data[1]:
            # Returns: IV, Cipher
            IV, encryptedEcho = processData(data, sessionKeys[connection])
            connection.send(IV)
            connection.send(encryptedEcho)
        else:
            break

    finally:
        # Clean up the connection
        dropClient(connection)
