import gui
import myftp
import threading

#TODO: ftp dir
#TODO: upload
#TODO: select download

if __name__ == '__main__':
    thread = threading.Thread(target=myftp.runFTPserver)
    thread.start()

    app = gui.NewprojectApp()
    app.run()

