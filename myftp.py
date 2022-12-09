import ftplib
import config
from subprocess import call

def runFTPserver():
    status = call("mkdir out", shell=True)
    command = "python -m python_ftp_server -u myUsername -p myPassword --ip 0.0.0.0 --port 6060 -d "+ r"./out"
    status = call(command, shell=True)


def upload(filename):
    ftp = ftplib.FTP()
    ftp.connect(config.FTP_HOST, config.FTP_PORT)
    ftp.login(config.FTP_USER, config.FTP_PASS)
    ftp.encoding = "utf-8"
    with open(filename, "rb") as file:
        ftp.storbinary(f"STOR {filename}", file)
    ftp.quit()


def download(filename):
    ftp = ftplib.FTP()
    ftp.connect(config.FTP_HOST, config.FTP_PORT)
    ftp.login(config.FTP_USER, config.FTP_PASS)
    ftp.encoding = "utf-8"
    with open(filename, "wb") as file:
        ftp.retrbinary(f"RETR {filename}", file.write)
    ftp.quit()




