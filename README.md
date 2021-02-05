# EncryptionProject
Python project to implement encryption functionality with REST API access

SYSTEM REQUIREMENTS:
- Create microservice for Backend servers running on Linux
- Written in Python 3+
- Encryption uses AES-GCM method
- Service should expose REST API to receive data to be encrypted
- Service should expose REST API to receive optional additional data to be part of the encryption
- Encrypted data shall be returned as REST response back to user
- AES Encryption key used for encryption shall be send over REST API
- Any additional returned information from service should be provided via REST API
- Run a docker container
- Integration tests are bonus
- Solution should be as secure as possible
- No decription is required

LOW LEVEL REQ:
- Microservice shall operate on Linux OS
- Microservice should minimize CPU and Memory demands
- Service shall accept following inputs:
  - secret key
  - initialization vector (IV)
  - plaintext
  - (optional) Additional authentication data (ADD)
- Service shall provide following outputs:
  - cipher text (encrypted text)
  - authentication tag (aka MAC or ICV)
- Microservice shall accept POST message to receive data to be encrypted (plaintext)
- Microservice should provide some information upon GET request (service name, service version, status)
- Context-type header "text/plain" for plaintext data should be supported
- Microservice should be able to take encryption key from the file on host system
- Microservice should be able to take IV from the file on host system
- Microservice REST API shall support HTTPS communication protocol
- HTTPS protocol should support only TLS1.2 and newer.


#RUN APPLICATION
- Application is delivered as Docker image, to run it execute command ```sudo docker run --rm -it encryptionService```


#USAGE
Use web browser or user command line tool to access the service and push text to be encrypted.
- Run locally by command ```pipenv run python service.py```
- Run in docker by command ```docker run --rm -it -p 5000:5000 encryption_service```


#PERFORMANCE TEST
- Microservice could be tested by send plain data to be encrypted over REST API. Test vectors are available [here](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip)


#BUILD AN APPLICATION
- Donwload application codes from GitLab repository by command ```git clone https://github.com/milo2/EncryptionProject.git .```
- Prepare Docker image by command ```docker build . -t encryption_service```


#TESTING
## Running tests
```bash
# There are not integration tests
pipenv install --dev
pipenv run pytest tests/unit -vv
```

## Running linter
```bash
pipenv install --dev
pipenv run pylint -f colorized **/*.py
```


#DEPENDENCIES
- virtualenv - Python virtual environment
- flask library - to perform REST API
- pycryptodome or cryptography. No PyCrypto as obsolete and (vulnerable)[https://www.cvedetails.com/vulnerability-list/vendor_id-11993/product_id-22441/Dlitz-Pycrypto.html]
- requests - to access data from REST API


#USED RESOURCES
- (Pipenv documentation)[https://pipenv.pypa.io/en/latest/]
- (Cryptography documentation)[https://cryptography.io/en/latest/]
