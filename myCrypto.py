from Cryptodome.Cipher import AES, DES, ARC2, CAST
import config
import rsa

def getBlockSize(filename):
    f = open(filename, "rb")
    dataBytes = f.read()
    sizeOfileInBytes = len((dataBytes))
    #can overflow (tested up to 1.5 GB file)
    return int(sizeOfileInBytes / 100)

def encryptAES(key, data_bytes):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    cipherText, tag = cipher.encrypt_and_digest(data_bytes)
    return cipherText, nonce


def decryptAES(key, cipherText, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce = nonce)
    plainText = cipher.decrypt(cipherText)
    return plainText


def encryptDES(key, data_bytes):
    cipher = DES.new(key, DES.MODE_EAX)
    nonce = cipher.nonce
    cipherText, tag = cipher.encrypt_and_digest(data_bytes)
    return cipherText, nonce


def decryptDES(key, cipherText, nonce):
    cipher = DES.new(key, AES.MODE_EAX, nonce = nonce)
    plainText = cipher.decrypt(cipherText)
    return plainText


def encryptRC2(key, data_bytes):
    cipher = ARC2.new(key, ARC2.MODE_EAX)
    nonce = cipher.nonce
    cipherText, tag = cipher.encrypt_and_digest(data_bytes)
    return cipherText, nonce


def decryptRC2(key, cipherText, nonce):
    cipher = ARC2.new(key, ARC2.MODE_EAX, nonce = nonce)
    plainText = cipher.decrypt(cipherText)
    return plainText


def roundRobinEncrypt(filename, keyAES, keyDES, keyRC2, blockSize):
    file = open(filename, 'rb')
    fileEncryptedName = "encrypted_"+filename
    fileEncrypted = open(fileEncryptedName, 'wb')
    count = 0
    while (True):
        nBytes = file.read(blockSize)
        if (nBytes):
            if(count == 3):
                count = 0
            if (count == config.AES):
                cipherText, nonce = encryptAES(keyAES, nBytes)
                [fileEncrypted.write(x) for x in (nonce, cipherText)]
            elif (count == config.DES):
                cipherText, nonce = encryptDES(keyDES, nBytes)
                [fileEncrypted.write(x) for x in (nonce, cipherText)]
            elif (count == config.RC2):
                cipherText, nonce = encryptRC2(keyRC2, nBytes)
                [fileEncrypted.write(x) for x in (nonce, cipherText)]
            else:
                exit(-200)
            count+=1
        else:
            break
    file.close()
    fileEncrypted.close()
    return fileEncryptedName


def roundRobinDecrypt(encryptedFilename, keyAES, keyDES, keyRC2, blockSize):
    encryptedFile= open(encryptedFilename, 'rb')
    decryptedFileName = "de"+encryptedFilename[2:]
    decryptedFile = open(decryptedFileName, 'wb')
    count = 0
    while (True):
        nonce, readCipherText = [encryptedFile.read(x) for x in (16, blockSize)]
        if (readCipherText):
            if (count == 3):
                count = 0
            if (count == config.AES):
                plainText = decryptAES(keyAES, readCipherText, nonce)
                decryptedFile.write(plainText)
            elif (count == config.DES):
                plainText = decryptDES(keyDES, readCipherText, nonce)
                decryptedFile.write(plainText)
            elif (count == config.RC2):
                plainText = decryptRC2(keyRC2, readCipherText, nonce)
                decryptedFile.write(plainText)
            else:
                exit(-200)
            count += 1
        else:
            break
    encryptedFile.close()
    decryptedFile.close()


def encryptCAST_128(key, data_bytes):
    cipher = CAST.new(key, CAST.MODE_EAX)
    nonce = cipher.nonce
    cipherText, tag = cipher.encrypt_and_digest(data_bytes)
    return cipherText, nonce


def decryptCAST_128(key, cipherText, nonce):
    cipher = CAST.new(key, CAST.MODE_EAX, nonce = nonce)
    plainText = cipher.decrypt(cipherText)
    return plainText


def getEncryptedKeysFile(filename,masterKey, dataBytes):
    fileEncryptedKeysName = "encrypted_keys_"+filename[:-4]+".txt"
    fileEncryptedKeys = open(fileEncryptedKeysName, 'wb')
    cipherText, nonce = encryptCAST_128(masterKey, dataBytes)
    [fileEncryptedKeys.write(x) for x in (nonce, cipherText)]
    fileEncryptedKeys.close()
    return fileEncryptedKeysName


def decryptKeysFile(filename, masterKey):
    fileEncryptedKeysDownloaded = open(filename, 'rb')
    nonce, readCipherText = [fileEncryptedKeysDownloaded.read(x) for x in (16, -1)]
    plainText = decryptCAST_128(masterKey, readCipherText, nonce)
    key1Decrypted = plainText[0:config.AES_KEY_SIZE_BYTES]
    key2Decrypted = plainText[config.AES_KEY_SIZE_BYTES : config.AES_KEY_SIZE_BYTES + config.DES_KEY_SIZE_BYTES]
    key3Decrypted = plainText[config.AES_KEY_SIZE_BYTES + config.DES_KEY_SIZE_BYTES : config.AES_KEY_SIZE_BYTES + config.DES_KEY_SIZE_BYTES + config.RC2_KEY_SIZE_BYTES]
    blockSizeDecrypted = plainText[config.AES_KEY_SIZE_BYTES + config.DES_KEY_SIZE_BYTES + config.RC2_KEY_SIZE_BYTES :]
    return key1Decrypted, key2Decrypted, key3Decrypted, int.from_bytes(blockSizeDecrypted, "big")


def storeLocally(filename, masterKey):
    fName= "master_key_"+filename[:-4]+".txt"
    f = open(fName, 'wb')
    f.write(masterKey)
    f.close()
    return fName


def encryptRSA(publicKey, dataBytes):
    return rsa.encrypt(dataBytes, publicKey)


def decryptRSA(privateKey, cipherText):
    return rsa.decrypt(cipherText, privateKey)


def getMasterKeyFileEncrypted(filename, userPublicKey):
    f = open("master_key_"+filename[:-4]+".txt", "rb")
    dataBytes = f.read()
    cipherText = encryptRSA(userPublicKey, dataBytes)
    f.close()
    fname = "encrypted_master_key_"+filename[:-4]+".txt"
    f = open(fname, "wb")
    f.write(cipherText)
    f.close()
    return fname


def decryptMasterKeyFile(filename, privateKey):
    f = open(filename, "rb")
    cipherText = f.read()
    f.close()
    plainText = decryptRSA(privateKey, cipherText)
    return plainText

