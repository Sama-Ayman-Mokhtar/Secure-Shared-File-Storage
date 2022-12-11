import threading
import config
import myftp
from secrets import token_bytes
import myCrypto

if __name__ == '__main__':
    thread = threading.Thread(target=myftp.runFTPserver)
    thread.start()

    key1 = token_bytes(config.AES_KEY_SIZE_BYTES)
    key2 = token_bytes(config.DES_KEY_SIZE_BYTES)
    key3 = token_bytes(config.RC2_KEY_SIZE_BYTES)


    file = myCrypto.roundRobinEncrypt("img.jpg", key1, key2, key3)
    myftp.upload(file)


    myftp.download(file)
    file = myCrypto.roundRobinDecrypt(file, key1, key2, key3)





