import threading
import myftp


if __name__ == '__main__':
    thread = threading.Thread(target=myftp.runFTPserver)
    thread.start()

    myftp.upload("textFile.txt")

    myftp.download("textFile2.txt")
