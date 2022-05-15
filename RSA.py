import math
import hashlib
import random
import base64
import os
import multiprocessing as mp
from multiprocessing import Queue
from threading import Thread
from multiprocessing.pool import ThreadPool
from tkinter import filedialog
import base64
import sympy
from sympy.codegen.ast import int64
from Crypto.Util.number import *
from pyfiglet import figlet_format

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y= '\033[33m' # yellow

global Digital_Signature


def randomNumberGenerator(N):
    return random.randrange(2 ** (N - 1) + 1, 2 ** N - 1)


def getPrimeNumber(n):
    while (True):
        x = randomNumberGenerator(n)
        first_primes_list=[2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67,
                     71, 73, 79, 83, 89, 97, 101, 103,
                     107, 109, 113, 127, 131, 137, 139,
                     149, 151, 157, 163, 167, 173, 179,
                     181, 191, 193, 197, 199, 211, 223,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]

        for divisor in first_primes_list:
            if x % divisor == 0 and divisor**2 <= x:
                break
            else:
                return x


def Keys_Generator(n):
    print(C+"Generating P & Q with ",n," bits  ....\n")
    while(True):
        p = getPrimeNumber(n)
        if not Miller_Rabin_Test(p):
            continue
        else:
            break
    while (True):
        q = getPrimeNumber(n)
        if not Miller_Rabin_Test(q):
            continue
        else:
            break
    print(C+"Generating e that must have GCD(e,(p-1)*(q-1)) = 1 .....")
    #n = p * q
    while(True):
        e = getPrimeNumber(16)
        if(Euclidean_Algorithm(e,(p-1)*(q-1)) == 1):
            break
        else:
            continue

    print(G+"P & Q & e generated successfully ,,, saving them into files .... ")
    try:
        with open('Private_Kyes_For_RSA.txt', 'w+') as f1:
            f1.write(str(p))
            f1.write('\n\n')
            f1.write(str(q))
            f1.write('\n\n')
            f1.write(str(e))
            f1.write('\n\n')
            f1.write(str((p - 1) * (q - 1)))
            f1.write('\n\n')
            f1.write(str(p * q))
            f1.write('\n\n')
            d = Private_key_Generator(p, q, e)
            f1.write(str(d))
    except Exception as e:
        print(e)
    print(G+"Private keys generated successfully ...")
    try:
        with open('Public_Kyes_For_RSA.txt', 'w+') as f2:
            f2.write(str(e))
            f2.write('\n\n')
            f2.write(str(p*q))

    except Exception as e:
        print(e)
    print(G+"Public keys generated successfully ...")


    return p,q,e,d

def Private_key_Generator(p,q,e):
    phi = (p-1) * (q-1)
    d = Modular_Inverse(e,int(phi))
    return d

def Modular_Inverse(a, m):
    m0 = m
    y = 0
    x = 1

    if (m == 1):
        return 0
    while (a > 1):
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    if (x < 0):
        x = x + m0
    return x



def Miller_Rabin_Test(n):
    DividorByTwo = 0
    evenElement = n - 1

    while evenElement % 2 == 0:
        evenElement >>= 1
        DividorByTwo += 1
    assert (2 ** DividorByTwo * evenElement == n - 1)

    def Composite_checker(local_test):
        if pow(local_test, evenElement, n) == 1:
            return False
        for i in range(DividorByTwo):
            if pow(local_test, 2 ** i * evenElement, n) == n - 1:
                return False
        return True

    # Set number of trials here
    numOfIterations = 50
    for i in range(numOfIterations):
        local_test = random.randrange(2,
                                        n)
        if Composite_checker(local_test):
            return False
    return True

def Euclidean_Algorithm(x, y):
    if (y == 0):
        return x
    else:
        return Euclidean_Algorithm(y, x % y)

def Extended_Euclidean_Algorithm(exp, x):
    if exp == 0:
        return x, 0, 1
    else:
        gcd, z, y = Extended_Euclidean_Algorithm(x % exp, exp)
        return gcd, y - (x // exp) * z, z


def Get_Digital_Signature(M,d,n):
    try:
        enc_m = M.encode('utf-8')
        SHA512 = hashlib.sha512()
        SHA512.update(enc_m)
        Hash = SHA512.digest()
        Hash = bytes_to_long(Hash)
        DS= pow(Hash,d,n)

        return DS
    except Exception as e:
        print(R+"Error While creating digital signature ... aborting \n",e)
        exit(1)

def Verify_Digital_Signature(sign,M,e,n):
    try:
        enc_m = M.encode('utf-8')
        SHA512 = hashlib.sha512()
        SHA512.update(enc_m)
        First_Hash = SHA512.hexdigest()
        Second_Hash = pow(sign,e,n)
        Second_Hash = long_to_bytes(Second_Hash).hex()

        if( First_Hash == Second_Hash):
            print(G+'Verified Digital Signature .... ')
            print(C+"Original hash value of the plaintext in hex format is:\n",str(First_Hash)+"\n")
            print(C+'\t\t\t\t\t\t=\n')
            print(C+"The hash value after decrypting the Original Signature in hex format: \n",str(Second_Hash)+"\n")
            return True
        else:
            print(R+"Digital Signature verification failed ......... NOT SECURE!!")
            return False

    except Exception as e:
        print(R+"Error While verifying digital signature ... aborting \n",e)
        exit(1)




def RSA_Encryption(m,n,e):
    try:
        print(C+"Encrypting your inquiry using public keys \n e={ ",e," } \n and \n N={ ",n," } \n ......")
        byte_m = m.encode('UTF-8')
        long_cipher = bytes_to_long(byte_m)
        print(R+"your plain text as a number is:\n",long_cipher)
        cipher = pow(long_cipher,e,n)
        print(C+'your cipher text as a number is:\n',cipher)

        return cipher
    except Exception as e:
        print(R+"Error While encrypting ... aborting\n",e)
        exit(1)

def RSA_Decryption(m,p,q,d):
   print(C+"Decrypting your inquiry  ......")
   try:
       n = p*q
       plaintext = pow(m,d,n)
       final_plain2 = long_to_bytes(plaintext)
       final_plain3 = final_plain2.decode('UTF-8')

       return final_plain3
   except Exception as e:
       print(R+"Error While decrypting .. aborting\n",e)
       exit(1)




if __name__ == '__main__':
    global Digital_Signature
    path = desktop = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop')
    Disk_Path= os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop')
    print(figlet_format("RSA \nCrypto System"), "This is Dakheel Almogbil Implementation for RSA Crypto System \n The Crypto System is using RSA Algorithm for different usages ")
    # print('**** This is Dakheel Implementation Cryptosystem ****')
    # print('**** The cryptosystem is using RSA Algorithm for different usages ****')
    while(True):
        print(Y+"""
            0.Upload Private & Public Keys from a file
            1.Generate Public Keys for RSA
            2.Encrypt a file using RSA
            3.Encrypt a message using RSA
            4.Decrypt a file using RSA
            5.Decrypt a message using RSA
            6.Print Public and Private Keys that will be used in RSA implementation
            7.Exit/Quit
            """)
        ans = int(input(W+"What would you like to do? -> "))
        if ans == 0:
            with open('Public_Kyes_For_RSA.txt', 'r') as file:
                Keys = file.read().split('\n\n')
                e=int(Keys[0])
                N = int(Keys[1])
            with open('Private_Kyes_For_RSA.txt', 'r') as file:
                Keys = file.read().split('\n\n')
                p = int(Keys[0])
                q = int(Keys[1])
                phi = int(Keys[3])
                d = int(Keys[5])

            print(C+"Public and private keys uploaded successfully click 6 to view them")
        elif ans == 1:
            while(True):
                print(C + "Please notice that the key size must be greater than or equal 512 bits")
                print(C + "Greater key size makes it harder to hackers to reveal the plaintext without the private keys ")
                key_size = int(input(W+"Enter the key size to generate P & Q: "))
                if(key_size >= 512):
                    break
                else:
                    print(R+"Please enter a key size that is greater than or equal 512 bits")
            cwd = os.getcwd()
            p,q,e,d = Keys_Generator(key_size)
        elif ans == 2:
            path = str(filedialog.askopenfilename(initialdir=Disk_Path, title='Select a file to Encrypt')).strip()
            with open(path, 'r') as file:
                data = file.read()
                CipherText = RSA_Encryption(data, (p*q), e)
                Digital_Signature = Get_Digital_Signature(data, d, (p*q))
                with open(path, 'w') as file2:
                    file2.write(str(CipherText))
                    file2.write("\n\n")
                    file2.write(str(Digital_Signature))
                print("Ecnryption Process Completed")
                Verify_Digital_Signature(Digital_Signature, data, e, (p*q))
        elif ans == 3:
            plain_text = input(R+"Enter the message you want to encrypt: ")
            cipher = RSA_Encryption(plain_text,(p*q),e)
            Digital_Signature = Get_Digital_Signature(plain_text,d,(p*q))
            # print(G+"The encrypted message is: ", cipher)
            print(G+"Digital Signature : \n" ,Digital_Signature)
            # print("Signature Verify : " + str(Verify_Signature(Cipher, CMAC, p, q, e)))
        elif ans == 4:
            path = str(filedialog.askopenfilename(initialdir=Disk_Path, title='Select a file to Decrypt')).strip()
            with open(path, 'r') as file:
                data = file.read()
                RealData = data.split("\n\n")
                PlainText = RSA_Decryption(int(RealData[0]), p, q, d)
                if(Verify_Digital_Signature(int(RealData[1]),PlainText,e,(p*q))):
                    with open(path, 'w') as file2:
                        file2.write(PlainText)
                    print(G+"Decryption Process Completed and Digital Signature is verified ...")
                else:
                    print(R+"Digital Signature is Manipulated, Aborting ....")
                    exit(1)
        elif ans == 5:
            CipherText = int(input(R+"Enter Cipher Text : "))
            Plaintext = RSA_Decryption(CipherText,p,q,d)
            print(G+"The decrypted message is: ", Plaintext)
            Verify_Digital_Signature(Digital_Signature,plain_text,e,(p*q))


        elif ans == 6:
            try:
                with open('Private_Kyes_For_RSA.txt','r') as f2:
                    Private_Keys = f2.read().split('\n\n')
                    print(G+"*** Private Keys ***")
                    print(G+"p :", Private_Keys[0])
                    print(G+"q :", Private_Keys[1])
                    print(G+"phi :", Private_Keys[3])
                    print(G+"d :", Private_Keys[5])
            except Exception as e:
                print(e)
            try:
                with open('Public_Kyes_For_RSA.txt', 'r') as f1:
                    Public_Keys = f1.read().split('\n\n')
                    print(C+"*** Public Keys ***")
                    print(C+"e :", Public_Keys[0])
                    print(C+"N :", Public_Keys[1])
            except Exception as e:
                print(e)
        elif ans == 7:
            print(C+"\n Good Bye")
            exit()
        elif ans != "":
         print(R+"\n Not Valid Choice Try again")

