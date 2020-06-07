#!/usr/bin/env python3

import base64
import binascii
import hashlib
import json
import logging
import re
import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from pprint import pprint

ROUTER_HOST = "192.168.0.1"
ROUTER_PASSWORD = "password"


class Client(object):
    def __init__(self, password, sig_priv=None, enc_priv=None):

        # get a requests session
        self.session = requests.Session()

        # setup crypto
        self.password = password
        self.init_aes()
        self.init_rsa()

        # build the username/password hash
        h = hashlib.md5()
        h.update(b"admin%s" % self.password.encode())

        # build the signature string
        self.sig_base = b"k=%s&i=%s&h=%s&s=" % (self.aes_key, self.aes_iv, h.hexdigest().encode())

        # login
        self.stok = ""
        self.login()



    def decrypt_aes(self, ciphertext):
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=self.aes_iv)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext



    def encrypt_aes(self, plaintext):
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=self.aes_iv)
        ciphertext = cipher.encrypt(plaintext)
        return ciphertext



    def get_signature(self, datalen):

        # plaintext signature string
        ss = b"%s%d" % (self.sig_base, (self.seq+datalen))

        # encrypt using the 512-bit public key
        sig = b""
        for x in range(0, len(ss), 53):
            chunk = ss[x:x+53]
            sig += self.sig_cipher.encrypt(ss[x:x+53])
        sig = binascii.hexlify(sig)

        return sig



    def send_encrypted_command(self, cmd, url):

        # encrypt the command (AES) and then base64-encode
        pc = chr(16 - (len(cmd) % 16))
        while len(cmd) % 16 != 0:
            cmd += pc.encode()
        cmd = self.encrypt_aes(cmd)
        cmd = base64.b64encode(cmd)

        # get the signature for the current sequence number
        sig = self.get_signature(len(cmd))

        # build the POST data
        post_data = { "sign": sig, "data": cmd }
        
        # send the request
        res = self.session.post("http://%s/cgi-bin/luci/;stok=%s%s" % (ROUTER_HOST, self.stok, url), data=post_data)

        # parse and decrypt the response
        data = json.loads(res.content)
        data_raw = base64.b64decode(data["data"])
        data = self.decrypt_aes(data_raw)
        if data[-1] < 16:
            data = data[:-data[-1]]
        data = json.loads(data)

        return data



    def login(self):
        
        # build the login command and encrypt with AES
        login_cmd = b"password=%s&operation=login" % binascii.hexlify(self.enc_cipher.encrypt(self.password.encode()))
        
        # send the command
        data = self.send_encrypted_command(login_cmd, "/login?form=login")

        # process the response
        if data["success"] != True:
            raise Exception("Login failure!")
        self.stok = data["data"]["stok"]
        logging.info("Logged in successfully!")



    def init_rsa(self, enc_priv=None, sig_priv=None):

        # request the signature public key and sequence number
        url = "http://%s/cgi-bin/luci/;stok=/login?form=auth" % ROUTER_HOST
        res = self.session.post(url, data={"operation":"read"})
        data = json.loads(res.content)
        self.sig_pub = int.from_bytes(binascii.unhexlify(data["data"]["key"][0]), "big")
        self.seq = data["data"]["seq"]

        # request the data public key
        url = "http://%s/cgi-bin/luci/;stok=/login?form=keys" % ROUTER_HOST
        res = self.session.post(url, data={"operation":"read"})
        data = json.loads(res.content)
        self.enc_pub = int.from_bytes(binascii.unhexlify(data["data"]["password"][0]), "big")

        # setup the data cipher
        self.enc_key = RSA.construct((self.enc_pub, 65537))
        if enc_priv is not None:
            self.enc_priv = enc_priv
            self.enc_key = RSA.construct((self.enc_pub, 65537, self.enc_priv))
        self.enc_cipher = PKCS1_v1_5.new(self.enc_key)        

        # setup the signature cipher
        self.sig_key = RSA.construct((self.sig_pub, 65537))
        if sig_priv is not None:
            self.sig_key = RSA.construct((self.sig_pub, 65537, sig_priv))
        self.sig_cipher = PKCS1_v1_5.new(self.sig_key)


    
    def init_aes(self):

        # request tpEncrypt.js and parse out the default AES key/IV
        url = "http://%s/webpages/js/libs/tpEncrypt.js" % ROUTER_HOST
        res = self.session.get(url)
        self.aes_key = re.search(r"t=\"(\d{16})\"", res.content.decode()).group(1).encode()
        self.aes_iv = re.search(r"e=\"(\d{16})\"", res.content.decode()).group(1).encode()

        # setup the cipher
        self.aes_cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=self.aes_iv)



if __name__ == "__main__":

    logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s.%(msecs)03d]  %(message)s', datefmt="%Y-%m-%d %H:%M:%S")

    # instantiate a Client instance and login
    client = Client(ROUTER_PASSWORD)

    # read out the aggregate status data
    ep = "/admin/status?form=all"
    ret = client.send_encrypted_command(b"operation=read", ep)
    pprint(ret)
    