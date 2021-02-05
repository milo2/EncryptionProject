#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Demonstration program to run encryption service in Docker with REST API
"""


import sys
# For logging handling
import logging
# For file handling
import os.path
# For intercommunication
import signal
# For support JSON format
import json
import base64
# For access to environmental variables
from os import environ as env
# For REST API
from flask import Flask, request
#
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
# For key generation from password
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt


app = Flask(__name__)
app.config["DEBUG"] = True
IS_RUNNING = True

logging.basicConfig(format='%(asctime)s   %(message)s', datefmt='%I:%M:%S %p', \
    stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def terminate_by_signal(signal_number, frame):
    """
    Trigger a sequence for program termination.
    """
    logging.info("Terminate signal received")
    global IS_RUNNING  # pylint: disable=W0603
    IS_RUNNING = False


def get_env():
    """
    Return configuration items from the environmental variables or fail
    """
    try:
        return {'AES_KEY': env.get('AES_KEY', None)
                ,'verbosity':env.get('VERBOSITY', 'INFO')
                }
    except KeyError:
        logging.info("Mandatory environmental variables missing")
        raise


class Encryption_key:
    """
    Class to handle loading and generation of the encryption key
    """

    def __init__(self, password:str = None):
        """
        Class constructor
        """
        self.key = None

        if self.key is None:
            self.key = self.__load_key__()
            if self.__validate_key__(self.key) == 0:
                self.key = None

        if self.key is None:
            # Let's generate him
            self.key = self.__generate_key__(password)

    def __load_key__(self, key_file="./cert/secret_key.key"):
        """
        Load key from file if exists
        """
        if os.path.isfile(key_file):
            logging.info("Loading encryption key from file '%s'", key_file)
            self.key = open(key_file, "rb").read()
        else:
            logging.debug("File '%s' with key not found", key_file)
            self.key = None

        return self.key

    def __generate_salt__(self, salt_len:int=32):
        """
        Generate Salt
        """
        salt = None
        # Generate Salt to get different key from the same input password
        salt = get_random_bytes(salt_len)

        logging.debug("New Salt generated")
        self.salt = salt
        return salt

    def __generate_key__(self, password:str=None, key_len:int=32):
        """
        Generate key from given password
        """
        key = None

        if password is None:
            key = Fernet.generate_key()
        else:
            salt = self.__generate_salt__()
            # https://nitratine.net/blog/post/python-gcm-encryption-tutorial/
            # https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html#scrypt
            # https://crypto.stackexchange.com/questions/8159/what-is-the-difference-between-scrypt-and-pbkdf2
            key = scrypt(password, salt, key_len, N=2**17, r=8, p=1)
            #key = PBKDF2(password=password, salt=salt)

        logging.debug("New key '%s' for given password '%s' is generated", key, password)
        self.key = key
        return key

    def __validate_key__(self, key:bytes):
        """
        Validate given key
        """
        pass

        # Key could be validated here - minimum required bit length, etc.
        return 1

    def get_key(self):
        """
        Return an encryption key
        """
        return self.key

    def get_salt(self):
        """
        Return Salt
        """
        return self.salt



def encrypt_message(key, plain_text:bytearray=None, add:bytearray=None, nonce=None, mac_len=16):
    """
    Encrypt data
    returns: (encrypted_text, nonce)
    """
    logging.debug("plain_text is %s data type", type(plain_text))

    if type(plain_text) is str:
        logging.debug("Converting plain_text to bytearray data type")
        plain_text = bytearray(plain_text, 'utf8')

    logging.debug("Plain text to be encrypted: '%s'", plain_text)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=mac_len)
    # Add add - Associated authenticated data is any
    if add is not None:
        cipher.update(add)
    logging.debug(cipher.__dict__)

    if len(plain_text) > 0:
        encrypted_text = cipher.encrypt(plain_text)
        #logging.debug("Encrypted text: '%s', nonce: '%s', tag: '%s'", encrypted_text, cipher.nonce)

    return encrypted_text, cipher.nonce


def welcome_msg():
    """
    Generate welcome message of the service
    """
    print("Welcome to the microservice to encrypt data")

# Define respose to GET access to the service
@app.route("/", methods=["GET"])
def get_request():
    """
    Method to implement REST API call of GET
    """
    html_content = ""
    html_content += "<html><body>"
    html_content += "<h1>Encryption REST API service lives here</h1>"
    html_content += "Place your plain text message here<br>"
    html_content += '<label for="plain">Plain text: </label>'
    html_content += '<input type="text" id="plain" name="plain"><br><br>'
    html_content += '<form method="POST" action="/" enctype="multipart-form-data">'
    html_content += '<input type="submit" value="submit" \
        title="Submits plain text from input to encryption service">'
    html_content += "</form>"
    html_content += "<footer>"
    html_content += "<p>Author: Karel Jilcik</p>"
    html_content += "</footer>"
    html_content += "</body></html>"

    return html_content


# Define respose to POST access to the service
@app.route("/", methods=['POST'])
def receive_data():
    """
    Method to implement REST API call of POST
    """
    for item in request.form.items():
        print(item)

    return "Received data to be encrypted"


# Define respose to GET access to the service
@app.route("/file", methods=["GET"])
def get_request_file():
    """
    Method to implement REST API call of GET on address /file
    """
    html_content = ""
    html_content += "<html><body>"
    html_content += "<h1>Encryption REST API service lives here</h1>"
    html_content += "Upload your file here and let it encrypt<br>"
    html_content += '<label for="file">File to be encrypted: </label>'
    html_content += '<input type="file" id="file" name="file"><br><br>'
    html_content += '<form action="" method="POST">'
    html_content += '<input type="submit" value="Submit" title="Submits file">'
    html_content += "</body></html>"

    return html_content


# Define respose to POST access to the service - files
@app.route("/file", methods=['POST', 'PUT'])
def receive_file():
    """
    Method to implement REST API call of PUT & POST on address /file
    """
    file = request.get_data()
    logging.debug("File to be encrypted: '%s'", file)

    encrypted_message = None
    key_class = Encryption_key(password=env_vars['AES_KEY'])
    encrypted_message = encrypt_message(key_class.get_key(), file)
    logging.debug("Encrypted message: '%s'", encrypted_message)

    encrypted_text = encrypted_message[0]
    nonce = encrypted_message[1]

    result = {}
    result['encrypted'] = base64.b64encode(encrypted_text).decode('utf-8')
    result['nonce'] = base64.b64encode(nonce).decode('utf-8')

    print(result)

    return result



if __name__ == "__main__":
    welcome_msg()

    # Capture signal from the outside
    signal.signal(signal.SIGTERM, terminate_by_signal)

    # Load values from environmental variables
    env_vars = get_env()

    PLAIN_TEXT = "My test string to be encrypted"

    logging.debug("Envorinmental variable AES_KEY: '%s'", env_vars['AES_KEY'])
    logging.debug("Text to be encrypted: '%s'", PLAIN_TEXT)

    key_class = Encryption_key(password=env_vars['AES_KEY'])
    encrypted_text = encrypt_message(key_class.get_key(), PLAIN_TEXT)
    logging.debug("Encrypted text: '%s'", encrypted_text)

    # Use Flash without SSL
    app.run(host="0.0.0.0")

    # Use Flask with adhoc certificate
    #app.run(host="0.0.0.0", ssl_context='adhoc')

    # To run Flask with self-signed SSL cert
    #app.run(host="0.0.0.0", ssl_context=('cert/cert.pem', 'cert/key.pem'))

    sys.exit()
