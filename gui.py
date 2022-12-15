import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox as mb
import os
import rsa
import myftp
import config
import myCrypto
from secrets import token_bytes
from tkinter import filedialog

class NewprojectApp:
    def __init__(self, master=None):
        # build ui
        toplevel1 = tk.Tk() if master is None else tk.Toplevel(master)
        toplevel1.configure(height=400, width=500)
        self.leftFrame = ttk.Frame(toplevel1)
        self.leftFrame.configure(height=400, width=500)
        self.frame2 = ttk.Frame(self.leftFrame)
        self.frame2.configure(height=400, width=500)
        self.title_lbl = ttk.Label(self.frame2)
        self.title_lbl.configure(justify="center", text='FTP Directory')
        self.title_lbl.grid(column=0, columnspan=4, padx=20, pady=10, row=0)
        self.upload_btn = ttk.Button(self.frame2)
        self.upload_btn.configure(text='Upload', width=30)
        self.upload_btn.grid(column=0, columnspan=2, padx=20, pady=10, row=3)
        self.upload_btn.bind("<ButtonPress>", self.upload, add="+")
        self.dowload_btn = ttk.Button(self.frame2)
        self.dowload_btn.configure(text='Download', width=30)
        self.dowload_btn.grid(column=2, columnspan=2, row=3)
        self.dowload_btn.bind("<ButtonPress>", self.download, add="+")
        self.lst_box = tk.Listbox(self.frame2)
        self.lst_box.configure(height=15, width=70)
        self.lst_box.grid(column=0, columnspan=4, padx=20, pady=10, row=1)
        self.lst_box.bind("<<ListboxSelect>>", self.setSelectedFile)
        self.key_vw = ttk.Entry(self.frame2)
        self.key_vw.configure(width=50, state=tk.DISABLED)
        self.key_vw.grid(column=0, columnspan=3, padx=20, pady=10, row=2)
        self.gen_key_btn = ttk.Button(self.frame2)
        self.gen_key_btn.configure(text='Gen PubKey')
        self.gen_key_btn.grid(column=3, row=2)
        self.gen_key_btn.bind("<ButtonPress>", self.genPubKey, add="+")
        self.frame2.grid(column=0, pady=10, row=0)
        self.leftFrame.grid(column=0, row=0)
        self.rightFrame = ttk.Frame(toplevel1)
        self.rightFrame.configure(height=400, width=500)
        self.debug_txtArea = tk.Text(self.rightFrame)
        self.debug_txtArea.configure(height=20, width=80,state=tk.DISABLED)
        self.debug_txtArea.grid(column=0, padx=20, pady=5, row=1)
        self.debug = ttk.Label(self.rightFrame)
        self.debug.configure(text='Debug\n')
        self.debug.grid(column=0, pady=10, row=0)
        self.rightFrame.grid(column=1, ipady=10, row=0)
        self.userPublicKey=''
        self.selectedFile=''
        self.fill_ftp_dir()

        # Main widget
        self.mainwindow = toplevel1

    def run(self):
        self.mainwindow.mainloop()

    def upload(self, event=None):
        self.filepath = filedialog.askopenfilename(initialdir="/", title="Choose a file to upload to ftp Server")
        filename = self.filepath.split('/')[-1]

        self.debug_txtArea.configure(state=tk.NORMAL)

        blockSize = myCrypto.getBlockSize(self.filepath)
        self.debug_txtArea.insert(tk.INSERT, "[key] generated AES key: {} bytes long\n".format(config.AES_KEY_SIZE_BYTES))
        key1 = token_bytes(config.AES_KEY_SIZE_BYTES)
        self.debug_txtArea.insert(tk.INSERT, "[key] generated DES key: {} bytes long\n".format(config.DES_KEY_SIZE_BYTES))
        key2 = token_bytes(config.DES_KEY_SIZE_BYTES)
        self.debug_txtArea.insert(tk.INSERT, "[key] generated RC2 key: {} bytes long\n".format(config.RC2_KEY_SIZE_BYTES))
        key3 = token_bytes(config.RC2_KEY_SIZE_BYTES)
        self.debug_txtArea.insert(tk.INSERT, "[key] generated Master key: CAST_128 {} bytes long\n".format(config.CAST_128_KEY_SIZE_BYTES))
        masterKey = token_bytes(config.CAST_128_KEY_SIZE_BYTES)

        self.debug_txtArea.insert(tk.INSERT, "[Encryption] encrypted {} using round robin (AES, DES, RC2)\n".format(filename))
        dataFileEncrypted = myCrypto.roundRobinEncrypt(self.filepath, filename, key1, key2, key3, blockSize)
        self.debug_txtArea.insert(tk.INSERT, "[Encryption] encrypted the three keys and the master key\n")
        keyFileEncrypted = myCrypto.getEncryptedKeysFile(filename, masterKey,
                                                         key1 + key2 + key3 + blockSize.to_bytes(32, 'big'))

        myftp.upload(dataFileEncrypted)
        self.debug_txtArea.insert(tk.INSERT, "[Upload] uploaded {}\n".format(dataFileEncrypted))
        myftp.upload(keyFileEncrypted)
        self.debug_txtArea.insert(tk.INSERT, "[Upload] uploaded {}\n".format(keyFileEncrypted))
        localMasterKeyFile = myCrypto.storeLocally(filename, masterKey)
        self.debug_txtArea.insert(tk.INSERT, "[Local] stored {}\n\n".format(localMasterKeyFile))

        self.debug_txtArea.configure(state=tk.DISABLED)
        self.fill_ftp_dir()


    def download(self, event=None):

        if self.selectedFile == '':
            mb.showinfo("Error", "Select a File from the Ftp Dir to Download!")
            return

        if 'encrypted_keys_' in self.selectedFile:
            mb.showinfo("Error", "Don't select a 'KEY' file")
            return

        if self.userPublicKey == '':
            mb.showinfo("Error", "Generate Your Public Key First!")
            return

        if 'encrypted_' in self.selectedFile:
            filename = self.selectedFile[10:]

        print(filename)

        self.debug_txtArea.configure(state=tk.NORMAL)

        masterKeyFileEncrypted = myCrypto.getMasterKeyFileEncrypted(filename, self.userPublicKey)

        myftp.download("encrypted_"+filename)
        self.debug_txtArea.insert(tk.INSERT, "[Download] downloaded {}\n".format("encrypted_"+filename))
        myftp.download("encrypted_keys_"+filename[:-4]+".txt")
        self.debug_txtArea.insert(tk.INSERT, "[Download] downloaded {}\n".format("encrypted_keys_"+filename[:-4]+".txt"))

        masterKey = myCrypto.decryptMasterKeyFile(masterKeyFileEncrypted, self.userPrivateKey)
        self.debug_txtArea.insert(tk.INSERT, "[Decryption] decrypted the {} using user's private key\n".format(masterKeyFileEncrypted))
        key1Decrypted, key2Decrypted, key3Decrypted, blockSizeDecrypted = myCrypto.decryptKeysFile("encrypted_keys_"+filename[:-4]+".txt",
                                                                                                   masterKey)
        self.debug_txtArea.insert(tk.INSERT, "[Decryption] decrypted {} using the master key\n".format("encrypted_keys_"+filename[:-4]+".txt"))

        file = myCrypto.roundRobinDecrypt("encrypted_"+filename, key1Decrypted, key2Decrypted, key3Decrypted,
                                          blockSizeDecrypted)
        self.debug_txtArea.insert(tk.INSERT, "[Decryption] decrypted {} using the 3 keys (round robin)\n".format("encrypted_"+filename))

        self.debug_txtArea.insert(tk.INSERT, "[Result] the file is called: {} \n\n".format(file))

        self.debug_txtArea.configure(state=tk.DISABLED)


    def genPubKey(self, event=None):
        self.key_vw.configure(state=tk.NORMAL)
        self.debug_txtArea.configure(state=tk.NORMAL)

        (self.userPublicKey, self.userPrivateKey) = rsa.newkeys(1024)
        self.debug_txtArea.insert(tk.INSERT, "[Key] generated user's public and private keys\n\n")
        self.key_vw.delete(0,tk.END)
        self.key_vw.insert(tk.INSERT, self.userPublicKey)

        self.debug_txtArea.configure(state=tk.DISABLED)
        self.key_vw.configure(state=tk.DISABLED)


    def fill_ftp_dir(self):
        for file in os.listdir("./out"):
            self.lst_box.insert(self.lst_box.size(), file)


    def setSelectedFile(self, event=None):
        print(self.lst_box.get(self.lst_box.curselection()[0]))
        self.selectedFile = self.lst_box.get(self.lst_box.curselection()[0])


