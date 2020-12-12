# -*- coding: utf-8 -*-
#!/usr/bin/python3
"""
@package:   emsg_encrypt
:module:    emsg_encrypt
:class:     EmsgEncrypt

Functions:

    - Generate an encryption key
    - Use encryption key to encrypt anything and return it in encrypted format
    - Use encryption key to decrypt using known encryption key
        - Return it in plain text format,
        - And store it in a defined location, using a pre-defined format
    - Retrieve the stored encryption key
    - Encrypt an ID and a password, storing the encrypted values in a pre-defined format
    - Retrieve encrypted ID and password
"""
import json
import secrets
import sys
from cryptography.fernet import Fernet
from os import getcwd, path, remove
from pprint import pprint as pp
from tornado.options import define, options
from emsg_functions import EmsgFunctions
EF = EmsgFunctions()

class EmsgEncrypt(object):
    """
    @class:  EmsgEncrypt

    Provide functions to support encryption, as well as storing/retrieving encrypted texts.
    """
    def __init__(self):
        """
        Initialize EmsgEncrypt object
        """
        self.cwd = getcwd()
        self.set_configs()

    def set_configs(self):
        """
        Name (define) the configuration items and load their values from configuration file
        """
        for config_item in ['tag_creds', 'encrypt_tag' ]:
            define(config_item)
        # Get configuration values from configuration filescript_name = path.basename(__file__)
        script_path = path.abspath(path.realpath(__file__))
        script_dir = path.split(script_path)[0]
        config_path = path.abspath(path.join(script_dir, 'model/EmsgEncrypt.conf'))
        options.parse_config_file(config_path)

    @classmethod
    def encrypt_me(cls, p_str_plaintext, p_key):
        """
        Return encrypted byte stream from the input string.

        :Args:
            {string} to be encrypted
            {bytes}  encryption key as byte-stream

        :Return:  {bytes} encrypted version of input
        """
        cipher_suite = Fernet(p_key)
        encoded_bytes = cipher_suite.encrypt(bytes(p_str_plaintext, 'utf-8'))
        return encoded_bytes

    @classmethod
    def decrypt_me(cls, p_bytes_encrypted, p_key):
        """
        Return decrypted version of the input bytes.

        :Args: {bytes} that were the result of calling the encrypt_me() function
               {bytes} encryption key as byte-stream

        :Return: {string} decrypted value
        """
        cipher_suite = Fernet(p_key)
        decoded_str = cipher_suite.decrypt(p_bytes_encrypted)
        decoded_str = decoded_str.decode("utf-8")
        return decoded_str

    def create_encrypt_key(self, p_key_tag=None):
        """
        Create a key for use with Fernet encryption.
        Store it in a formatted record a off-line storage location defined in config file,
          first removing any older records using the same tag.
        Return the encrypted byte-stream and the formatted record.

        @DEV: Let's stop using a secondary JSON file and just return the value to the caller,
              without formatting/managing storage for it. Let the caller manage that.

        :Args:  {string} (Optional) tag to verify/identify the encryption-key value.
                         If None, then use options.encrypt_tag

        :Return: {tuple} ( {string} encryption tag,
                           {bytes} encryption key )
        """
        encrypt_tag = p_key_tag if p_key_tag is not None else options.encrypt_tag
        encrypt_key = Fernet.generate_key()

        return (encrypt_tag, encrypt_key)

    def create_secret_key(self, key_length=None, context_key=None):
        """
        Return a cryptographically strong random value that is URL safe,
        A value shorter than 32 bytes is not good.

        Also return it in a JSON format that includes a timestamp and a context key

        :Args:
            - {integer} desired length of the key or None
            - {string} desired context key or None

        :Return: {tuple} ({bytes} encryption key, {string} JSON record)
        """
        key_length = 32 if key_length is None else key_length
        key_length = 32 if key_length < 32 else key_length
        secret_key = secrets.token_urlsafe(key_length)
        ts = EF.get_dttm()
        context_key = ts.curr_lcl if context_key is None else context_key
        secret_record = dict()
        secret_record[context_key] = {"date": str(ts.curr_lcl), "key": str(secret_key)}
        return (secret_key, json.dumps(secret_record))