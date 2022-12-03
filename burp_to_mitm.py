from mitmproxy import http
from urllib.parse import quote, unquote
from Crypto.Cipher import AES
from base64 import b64encode
from Crypto.Util.Padding import pad, unpad

#keys
iv = bytes("secretiv", 'utf-8')
key = bytes("secretkey", 'utf-8')

def request(flow: http.HTTPFlow) -> None:
    #if host matches
    if flow.request.host == "victim.com":
        print(flow.request.host)
        post_body = (flow.request.content).decode('utf8')
        #encrypting data coming from Burp
        edata = quote(encrypt(post_body))
        #appending IV to the request as it was originally done 
        prefix = quote(":") + quote(b64encode(iv))
        #final POST body
        to_send = "data=" + edata + prefix
        #send to server
        flow.request.content = bytes(to_send, 'utf-8')

#function to encrypt AES
def encrypt(message):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message.encode("UTF-8"), AES.block_size))
    return (b64encode(encrypted).decode('utf-8'))
