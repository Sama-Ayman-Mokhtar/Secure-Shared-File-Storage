import gui
import myftp
import threading

#TODO: scroll bar


if __name__ == '__main__':
    thread = threading.Thread(target=myftp.runFTPserver)
    thread.start()

    app = gui.NewprojectApp()
    app.run()

