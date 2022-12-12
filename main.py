import rsa
import myftp
import config
import myCrypto
import threading
from secrets import token_bytes

#TODO: GUI

if __name__ == '__main__':
    thread = threading.Thread(target=myftp.runFTPserver)
    thread.start()

    filename = "img.jpg"
    #filename = "vid.mp4"

    blockSize = myCrypto.getBlockSize(filename)
    key1 = token_bytes(config.AES_KEY_SIZE_BYTES)
    key2 = token_bytes(config.DES_KEY_SIZE_BYTES)
    key3 = token_bytes(config.RC2_KEY_SIZE_BYTES)
    masterKey = token_bytes(config.CAST_128_KEY_SIZE_BYTES)


    dataFileEncrypted = myCrypto.roundRobinEncrypt(filename, key1, key2, key3, blockSize)
    keyFileEncrypted = myCrypto.getEncryptedKeysFile(filename, masterKey, key1+key2+key3+blockSize.to_bytes(32,'big'))
    myftp.upload(dataFileEncrypted)
    myftp.upload(keyFileEncrypted)
    localMasterKeyFile = myCrypto.storeLocally(filename, masterKey)


    (userPublicKey, userPrivateKey) = rsa.newkeys(1024)
    masterKeyFileEncrypted = myCrypto.getMasterKeyFileEncrypted(filename, userPublicKey)
    myftp.download(dataFileEncrypted)
    myftp.download(keyFileEncrypted)
    masterKey = myCrypto.decryptMasterKeyFile(masterKeyFileEncrypted, userPrivateKey)
    key1Decrypted, key2Decrypted, key3Decrypted, blockSizeDecrypted = myCrypto.decryptKeysFile(keyFileEncrypted, masterKey)
    file = myCrypto.roundRobinDecrypt(dataFileEncrypted, key1Decrypted, key2Decrypted, key3Decrypted, blockSizeDecrypted)

    print("sama")
    thread.join()
    print("amin")





