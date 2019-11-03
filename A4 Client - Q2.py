import copy
import socket
import random
import time


#########################################################Encryption BEGIN


def mapChar (char,offset):
    charInt=ord(char)
    charInt=charInt+offset
    if(charInt>125):
        charInt=charInt%126 +32
    return(chr(charInt))
#######  mapChar takes a char and returns the cahr offset by value offset


def transListChar (charList,transList):
    while(len(charList)%16 !=0):
        charList.append("~")
    retList = []
    i=0
    while(i<len(charList)):
        swapb=int(i/16)*16+transList[i%16]
        retList.append(charList[swapb])
        i=i+1
    return retList
#######  transListChar takes a list of chars and a transposes it according to
#######  the transpose list that is taken as an input.


def completeEncryption(inputString, scheme):
    inputStringList=list(inputString)
    i=0
    while i<len(inputStringList):
        inputStringList[i]=mapChar(inputStringList[i],scheme[0])
        i=i+1
    return "".join(transListChar(inputStringList,scheme[1]))
#######  completeEncryption takes a string an an encryption scheme and returns
#######  the encrypted string. 


#########################################################Encryption END


#########################################################Decryption BEGIN


def revTransListChar (charList,transList):
    while(len(charList)%16 !=0):
        charList.append("~")
    retList = copy.deepcopy(charList)
    i=0
    while(i<len(charList)):
        posInTransList=i%16
        retList[int(i/16)*16+transList[posInTransList]]=charList[i]
        i=i+1
    return [x for x in retList if x != '~']
#######  transListChar takes a list of chars and a reverses the transposes that has been done
#######  to is according to the the transpose list that is taken as an input.


def revMapChar (char,offset):
    charInt=ord(char)
    charInt=charInt-offset
    if(charInt<32):
        charInt=charInt+94
    return(chr(charInt))
#######  mapChar takes a char and returns the char negative offset by value offset


def completeDecryption(inputString, scheme):
    inputStringList=list(inputString)
    inputStringList=revTransListChar(inputStringList,scheme[1])
    i=0
    while i<len(inputStringList):
        inputStringList[i]=revMapChar(inputStringList[i],scheme[0])
        i=i+1
    return "".join(inputStringList)
#######  completeDecryption takes an encrypted string an an encryption scheme and returns
#######  the decrypted string. 

#########################################################Decryption End


######################################################### List of security schemes


TransList1=[15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0]
TransList2=[1,3,5,7,9,11,13,15,14,12,10,8,6,4,2,0]
TransList3=[2,7,5,3,1,8,12,13,10,15,4,14,6,9,11,0]
TransList4=[0,2,4,6,8,10,12,14,1,3,5,7,9,11,13,15]
TransList5=[0,15,1,14,2,13,3,12,4,11,5,10,6,9,7,8]
OSList=[(32,TransList1),(0,TransList2),(100,TransList3),(42,TransList4),(1,TransList5)]


######################################################### List of security schemes END


######################################################### Client Socket connection
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 12336)) #connects to this address and port


######################################################### Secure secret key sharing BEGIN
######GET K
na=random.randint(1, 1000)
xa=random.randint(1, 1000)

message=str(na)
test=str.encode(str(message)) 
s.sendall(test)
#####STEP 1 send N

data = s.recv(1024)
qb=int(data)
####Recieve Q

ya=(na**xa) % qb
message=str(ya)
test=str.encode(str(message)) 
s.sendall(test)
####Send ya

data = s.recv(1024)
yb=int(data)
####Recieve yb

ka=(yb**xa) % qb
##generate ka

print("ka :"+str(ka))
i=ka % 5
print("i = ka mod 5 :"+str(i))
######################################################### Secure secret key sharing END


seedNum=random.randint(1, 99999)

####SEND SEED
encryptedString=completeEncryption(str(seedNum),OSList[i])
test=str.encode(str(encryptedString))
s.sendall(test)
####SEND SEED END


def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))


random.seed( seedNum )
while True:
    message=raw_input("Enter Message :")
    message=str(message)


    mList=list(chunkstring(message, 4))
    for chars in mList:
        key=(int(random.randint(0,4)))
        #print(key)
        encryptedString=completeEncryption(str(chars),OSList[key])
        test=(encryptedString)
        s.sendall(test)
        time.sleep(0.001)
    key=(int(random.randint(0,4)))
    encryptedString=completeEncryption(str("ENDEND"),OSList[key])
    test=unicode(encryptedString, "utf-8")
    s.sendall(test)


    print("please wait for message")
    endOfStream=True
    message=""
    while endOfStream:
        key=(int(random.randint(0,4)))
        data = s.recv(1024)
        time.sleep(0.001)
        dChar=completeDecryption(str(data),OSList[key])
        if(dChar=="ENDEND"):
            print(message)
            endOfStream=False
        message=message+dChar







