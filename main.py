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
    masterKey = token_bytes(config.CAST_128_KEY_SIZE_BYTES)


    dataFileEncrypted = myCrypto.roundRobinEncrypt("img.jpg", key1, key2, key3)
    keyFileEncrypted = myCrypto.getEncryptedKeysFile(masterKey, key1+key2+key3)
    myftp.upload(dataFileEncrypted)
    myftp.upload(keyFileEncrypted)


    myftp.download(dataFileEncrypted)
    myftp.download(keyFileEncrypted)
    key1Decrypted, key2Decrypted, key3Decrypted = myCrypto.decryptKeysFile(keyFileEncrypted, masterKey)
    file = myCrypto.roundRobinDecrypt(dataFileEncrypted, key1Decrypted, key2Decrypted, key3Decrypted)





