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
import base64
# For access to environment variables
from os import environ as env
# For REST API
from flask import Flask, request
#
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
# For key generation from password
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt


app = Flask(__name__)
app.config["DEBUG"] = True
IS_RUNNING = True

# Configure logging service
logging.basicConfig(format='%(asctime)s   %(message)s', datefmt='%I:%M:%S %p', \
    stream=sys.stdout, level=logging.WARNING)
logger = logging.getLogger(__name__)


def terminate_by_signal(signal_number, frame):
    """
    Trigger a sequence for program termination.
    """
    logging.info("Signal %d received in process %s, terminating." \
        , signal_number, frame)
    global IS_RUNNING  # pylint: disable=W0603
    IS_RUNNING = False


def get_env():
    """
    Return configuration items from the environment variables or fail
    """
    try:
        return {'AES_KEY': env.get('AES_KEY', None)
                ,'VERBOSITY': env.get('VERBOSITY', 'INFO')
                ,'PORT': env.get('PORT', '8080')
                ,'SSL': env.get('SSL', 'NONE')
                }
    except KeyError:
        logging.info("Mandatory environment variable(s) missing")
        raise


class EncryptionKey:
    """
    Class to handle loading and generation of the encryption key
    """

    def __init__(self, password:str = None):
        """
        Class constructor
        """
        self.key = None
        self.salt = None

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
        valid = 0
        # Key could be validated here - minimum required bit length, etc.
        if key is not None and len(key) > 0:
            valid = 1
        else:
            valid = 0

        return valid

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

    #if type(plain_text) is str:
    if isinstance(plain_text, str):
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
    print("\nWelcome to the microservice to encrypt data\n")


# Define respose to GET access to the service
@app.route("/", methods=["GET"])
def get_request():
    """
    Method to implement REST API call of GET
    """
    try:
        content_file = open("html/root_get.html", "r")
        content = content_file.read()
    except:
        logging.info("Could not load source HTML file '%s'")
        raise

    return content


# Define respose to POST access to the service
@app.route("/", methods=['POST'])
def receive_data():
    """
    Method to implement REST API call of POST
    """
    for item in request.form.items():
        print(item)

    result = {}
    # Get object from the Flask
    data = request.get_data()

    # Validate file
    if data is not None and len(data) > 0:
        logging.debug("Data to be encrypted: '%s'", data)

        key_class = EncryptionKey(password=env_vars['AES_KEY'])
        encrypted_message = encrypt_message(key_class.get_key(), data)
        logging.debug("Encrypted message: '%s'", encrypted_message)

        encrypted_data = encrypted_message[0]
        nonce = encrypted_message[1]

        result = {}
        result['encrypted'] = base64.b64encode(encrypted_data).decode('utf-8')
        result['nonce'] = base64.b64encode(nonce).decode('utf-8')

    logging.debug("Encryption result: %s", result)
    return result


# Define respose to GET access to the service
@app.route("/file", methods=["GET"])
def get_request_file():
    """
    Method to implement REST API call of GET on address /file
    """
    try:
        content_file = open("html/file_get.html", "r")
        content = content_file.read()
    except:
        logging.info("Could not load source HTML file '%s'")
        raise

    return content


# Define respose to POST access to the service - files
@app.route("/file", methods=['POST', 'PUT'])
def receive_file():
    """
    Method to implement REST API call of PUT & POST on address /file
    """
    result = {}
    # Get file object from the Flask
    file = request.get_data()

    # Validate file
    if file is not None and len(file) > 0:
        logging.debug("File to be encrypted: '%s'", file)

        key_class = EncryptionKey(password=env_vars['AES_KEY'])
        encrypted_message = encrypt_message(key_class.get_key(), file)
        logging.debug("Encrypted message: '%s'", encrypted_message)

        encrypted_data = encrypted_message[0]
        nonce = encrypted_message[1]

        result = {}
        result['encrypted'] = base64.b64encode(encrypted_data).decode('utf-8')
        result['nonce'] = base64.b64encode(nonce).decode('utf-8')

    logging.debug("Encryption result: %s", result)
    return result



if __name__ == "__main__":
    # Capture signal from the outside
    signal.signal(signal.SIGTERM, terminate_by_signal)

    # Load values from environment variables
    env_vars = get_env()
    print("Logging level is set to:", env_vars.get('VERBOSITY'))

    port = int(env_vars.get('PORT'))
    print("REST API source port:", env_vars.get('PORT'))

    ssl = env_vars.get('SSL')
    print("SSL support is set to:", env_vars.get('SSL'))

    # Update logger configuration based on ENV variable value
    logger.setLevel(env_vars.get('VERBOSITY', 'DEBUG'))

    welcome_msg()

    PLAIN_TEXT = "My test string to be encrypted"
    logger.debug("Environment variable AES_KEY: '%s'", env_vars['AES_KEY'])
    logger.debug("Text to be encrypted: '%s'", PLAIN_TEXT)

    key_class = EncryptionKey(password=env_vars['AES_KEY'])
    encrypted_text = encrypt_message(key_class.get_key(), PLAIN_TEXT)
    logging.debug("Encrypted text: '%s'", encrypted_text)

    # Use Flash without SSL
    if env_vars.get('SSL') == "NONE":
        app.run(host="0.0.0.0", port=port)
    elif env_vars.get('SSL') == "ADHOC":
        # Use Flask with adhoc certificate
        app.run(host="0.0.0.0", ssl_context='adhoc', port=port)
    elif env_vars.get('SSL') == "CERTIFICATE":
        # To run Flask with self-signed SSL cert
        app.run(host="0.0.0.0", ssl_context=('cert/cert.pem', 'cert/key.pem'), port=port)

    sys.exit()
