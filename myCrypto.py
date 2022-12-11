from Cryptodome.Cipher import AES, DES, ARC2
import config

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


def roundRobinEncrypt(filename, keyAES, keyDES, keyRC2):
    file = open(filename, 'rb')
    fileEncrypted = open("encrypted.jpg", 'wb')
    count = 0
    while (True):
        nBytes = file.read(config.BLOCK_SIZE)
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
    return "encrypted.jpg"


#TODO: handle file extentions
def roundRobinDecrypt(encryptedFilename, keyAES, keyDES, keyRC2):
    encryptedFile= open(encryptedFilename, 'rb')
    decryptedFile = open("decrypted.jpg", 'wb')
    count = 0
    while (True):
        nonce, readCipherText = [encryptedFile.read(x) for x in (16, config.BLOCK_SIZE)]
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