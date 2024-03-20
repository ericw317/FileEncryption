from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import tkinter
from tkinter import filedialog
from tkinter import messagebox

root = tkinter.Tk()
root.wm_attributes("-topmost", 1)
root.withdraw()

# function to create and store an encryption key
def keyCreation():
    key = get_random_bytes(32)  # generate random key

    # save the key to a file for later use
    messagebox.showinfo("Key Creation", "Select a file to save your key to.")
    fi = open(filedialog.askopenfilename(), "wb")
    fi.write(key)
    fi.close()

# function to encrypt a file
def encrypt(file, key):
    messagebox.showinfo("Encrypted Name", "Select the directory you'd like to save the encrypted file.")
    encryptedFileName = str(filedialog.askdirectory()) + "/EncryptedFile"
    outputFile = encryptedFileName  # name of the file we are encrypting

    # store data from file into the data variable
    fi = open(file, "rb")
    data = fi.read()
    fi.close()

    # create AES object and encrypt data
    cipher = AES.new(key, AES.MODE_CFB)
    cipheredData = cipher.encrypt(data)

    # write the encrypted data to a file
    fo = open(encryptedFileName, "wb")
    fo.write(cipher.iv)
    fo.write(cipheredData)
    fo.close()

# function to decrypt a file
def decrypt(file, key):
    # read data from file we are decrypting
    fi = open(file, "rb")
    iv = fi.read(16)
    cipheredData = fi.read()
    fi.close()

    # decipher the data
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    decipheredData = cipher.decrypt(cipheredData)

    # output the deciphered data to a new file
    fi = open(file + "decrypted", "wb")
    fi.write(decipheredData)
    fi.close()

# function to return data in a file
def extractData(file):
    fi = open(file, "rb")
    data = fi.read()
    fi.close()

    return data


programLoop = True

while programLoop:
    # ask user what they'd like to do
    selection = input("What would you like to do?\n"
                      "1) Generate a key\n"
                      "2) Encrypt a file\n"
                      "3) Decrypt a file\n"
                      "0) Exit\n")

    # input validation
    while not selection.isnumeric() or int(selection) < 0 or int(selection) > 3:
        selection = input("Input must be a number between 0 and 3: ")

    if selection == "1":
        keyCreation()
    elif selection == "2":
        messagebox.showinfo("Encrypt", "Select the file you'd like to encrypt.")
        fileToEncrypt = filedialog.askopenfilename()
        messagebox.showinfo("Key", "Select the key file.")
        key = extractData(filedialog.askopenfilename())
        encrypt(fileToEncrypt, key)
    elif selection == "3":
        messagebox.showinfo("Decrypt", "Select the file you'd like to decrypt.")
        fileToDecrypt = filedialog.askopenfilename()
        messagebox.showinfo("Key", "Select the key file.")
        key = extractData(filedialog.askopenfilename())
        decrypt(fileToDecrypt, key)
    elif selection == "0":
        programLoop = False
