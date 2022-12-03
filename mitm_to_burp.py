from mitmproxy import http
from urllib.parse import quote, unquote
from Crypto.Cipher import AES
from base64 import b64decode
from Crypto.Util.Padding import pad, unpad

#keys
iv = bytes("secretiv", 'utf-8')
key = bytes("secretkey", 'utf-8')

def request(flow: http.HTTPFlow) -> None:
    #if host matches the victim
    if flow.request.host == "victim.com":
        post_body = (flow.request.content).decode('utf-8')
        #do voodoo magic to decode the data=AESEncodeddata:IV 
        to_decrypt = unquote(post_body.split("=")[1]).split(":")[0].replace("\n","")
        #send decrypted data
        flow.request.content = decrypt(to_decrypt)

#function to decrypt AES
def decrypt(message):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(b64decode(message)), AES.block_size)
    return decrypted