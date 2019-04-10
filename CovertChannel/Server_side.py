import sys
import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from _socket import AF_INET, SOCK_DGRAM
import random, string
import base64

class dnserver():
    def __init__(self):
        
        self._serversocket=socket.socket(AF_INET,SOCK_DGRAM)
        self._serversocket.bind(('',53))
        self._preshared='0x252'
        self._counter=0
        print('init has started and the counter is',self._counter)
        self._flags=['0','0','0','0','0','0']
        self._clients=[]
        self._connect=True
        self._ext='txt'
        self._finsent=False
        self.file_input() #to detect is there any data to send or not
        while self._connect==True:
            #try:
            print('***************************************************************************')
            print('started listening')
            self._connection,self._add=self._serversocket.recvfrom(4096)
            print('getting socket')
            self._req=DNS(self._connection)
            print('getting req as a dns')
            self.decapsulation()
            print('decap finished')
           # except Exception as e:
                #print('nothing')
                #print('garbage from {!r}? data {!r}'.format(self._add, self._connection))
    def file_input(self):
        
        print('file_input started')
        try:
            file=sys.argv[1]
            self._isdata=True
            if file.lower().endswith('.txt'):
                self._f=open(file,'r')
                self._ext='txt'
            else:
                self._f=open(file,'rb')
                self._ext='bin'
            self._total=int(os.stat(sys.argv[1]).st_size)
            self._sum=0
        except:
            self._isdata=False
            print('there is no input')
      
         
    def decapsulation(self):
        
        self._counter+=1
        print("decap started")
        self.parting()
        rawdata=self._qn
        print('the qname is', self._qn)
        rawdata=rawdata.rstrip('.')
        chunks=rawdata.split('.')
        leng=len(chunks)-1
        self._domain=chunks[leng-1]
        self._tld=chunks[leng]
        print('domain=',self._domain)
        print('tld=',self._tld)
        if 1==1: #check domain & tld
            data=""
            for i in range(0,leng-1):
                data+=chunks[i]
            #seprating things
            print('the data part without domain and tld=',data)
            decodedata=base64.b32decode(data)   #data in binary    
            decodestr=str(decodedata) #data in string
            print('the decodestr=',decodestr)
            self._rcvflags=decodestr[0:6]
            print('rcvflags=',self._rcvflags)
            self._rcvid=decodestr[6:9]
            print('rcv_id=',self._rcvid)
            self._rcvseq=decodestr[9:13]
            print('rcv_seq=',self._rcvseq)
            if(self._counter==1): #first time connection
                
                #generating seed and two files per each client
                print('counter is 1')
                self._isn=self._rcvseq
                self._seed=self.generate_seed(self._preshared, self._isn)
                print('seed='+self._seed)
                self._clients.append(self._rcvid)
                filenamet='rcvfile'+self._rcvid+'.txt'
                self._rcvft=open(filenamet,'w')
                filenameb='rcvfile'+self._rcvid
                self._rcvf=open(filenameb,'wb')
            #else: is not first connection, id check if id matched then check seq
            else:
                #check=(self._rcvid in self._clients)
                print('counter is not 1')
                if((self._rcvid in self._clients)==False):
                    print('the id does not exist in the list')
                    return
                    '''if(int(self.rcv_seq)!=int(self._seq)+1):
                        return'''
            if (self._rcvflags[0]=='0'): #there is data to obfuscate
            #if a test record         
                #self._flags[0]='0'
                #data
                obfdata=decodestr[13:len(decodestr)]
                print('the obfuscated data is',obfdata)
                self._rcvdata=self.obfuscation(obfdata,self._seed)
                print('the un obfuscated data is', self._rcvdata)
                #detecting data type
                if(self._rcvflags[3]=='1'):
                    print('the rcv data is txt')
                    self._rcvft.write(self._rcvdata)   #txt 
                    #with open(self._filenamet,'w') as f:
                        #f.write(self._rcvdata)
                    print('writing is finished')
                
                else: 
                    print('the rcv data is bin')  
                    #bytesrcv=bytes(self._rcvdata) #bin
                    #print('and type of it is',type(bytesrcv))
                    self._rcvf.write(self._rcvdata)
                    #f=open(self._filenameb,'wb') 
                    #f.write(self._rcvdata)
                    #f.close()
                    print('count of writing=',self._counter)
                    
            self.chunkfiles()   
    
    def chunkfiles(self):
        #A record rdata='127.0.0.1' #A
        print('chunkfile is started')
        if(self._qtype=='A'): 
            self._data='127.0.0.1'
            #if(self._isdata==False):
                #self._flags[0]='1'  #to show there is no data in packet
                #self._flags[5]='1'
            
        else:
            if(self._isdata):
                buffersize=random.randint(60,90)
                if(buffersize>=60 and buffersize<70):self._subsize=random.randint(10,50)
                elif(buffersize>=80 and buffersize<80):self._subsize=random.randint(30,50)
                else:self._subsize=random.randint(40,50)
                print('buffersize=',buffersize,'subsize=',self._subsize)
                self._sum+=buffersize
                self._buffer=self._f.read(buffersize)
                notfinished= len(self._buffer)
                if(notfinished):
                    self._data=self._buffer
                else: #there is no data to send
                    self._isdata=False
                    self._flags[5]='1'
                    self._finsent=True
                    '''if(self._sum<self._total): 
                        self._buffer=self._f.read(self._total-self._sum)
                        self._sum=self._total
                        self._data=self._buffer'''
                   
                    self._flags[0]='1'  #to show there is no data in packet
                    self._ext='txt'
                    self._data=''.join(random.choice(string.ascii_letters+string.digits) for i in range(20))
                        
            else:
                self._flags[0]='1'  #to show there is no data in packet
                self._flags[5]='1'
                self._finsent=True
                self._ext='txt'
                self._data=''.join(random.choice(string.ascii_letters+string.digits) for i in range(20))
        self.encapsulation()
                    
       
                           
            
        
    def encapsulation(self):
        print('encap started')
        if(self._ext=='txt'):
            self._flags[3]='1'
        else:
            self._flags[3]='0'
        flg=''.join(e for e in self._flags)
        xseq=int(self._rcvseq,16)
        self._seq =hex(xseq+1)
        self._counter +=1
        self._id=self._rcvid
        hd=flg+self._id+self._seq
        #randstr=''.join(random.choice(string.ascii_letters+string.digits) for i in range(20))
        #print('randstr='+randstr)
        if(self._ext=='txt'):#type of data
            finalstr=hd+self.obfuscation(self._data,self._seed)
        else:
            finalstr=hd+self.obfuscation(str(self._data),self._seed)
        if(self._qtype=='TXT'):
             data=base64.b64encode(finalstr)
        else:
             data=base64.b32encode(finalstr)
        print('finalstr= ',finalstr)
        
        print('endoded_fdata=',data)
        if(self._qtype !='A'):
             response=DNS(id=self._qrid,ancount=1,qr=1,an=DNSRR(rrname=str(self._qn),type=self._t,rdata=data+'.test.com'))
             print('rdata=',response[DNSRR].rdata)
        else:
             response=DNS(id=self._qrid,ancount=1,qr=1,an=DNSRR(rrname=str(self._qn),type=self._t,rdata=str(self._data)))
        self._serversocket.sendto(bytes(response),self._add)
        print('packet sent')
        print('rcvflag[5]=',self._rcvflags[5])
        print('flag[5]=',self._flags[5])

        if self._rcvflags[5]=='1'and self._finsent==True:
            print('connection is false')
            self._connect=False
            self._rcvf.close()
            self._rcvft.close()
            self.__init__()
        
        
    def parting(self):
        #self._dst=self._req[IP].src
        #self._dp=self._req[UDP].sport
        print('parting started')
        self._qrid=self._req[DNS].id
        print('dnsid=',self._qrid)
        self._q=self._req[DNS].qd
        print('dnsqd=',self._q)
        self._t=self._req[DNSQR].qtype
        print('dnsqr_type=',self._t)
        self._qn=self._req[DNSQR].qname
        print('qname=',self._qn)
        self._qtype =self._req[DNSQR].sprintf("%qtype%")
        print('qtype=',self._qtype)
        print('finish_parting')
        
    def formatting(self,st):
        chunk=[st[i:i+63] for i in range(0,len(st),63)]
        chunkdata='.'.join(str(e) for e in chunk)
        return (chunkdata+'.test.com')  
    
    def generate_seed(self,first,second):
        print('generating seed')
        sed = ""
        for character in first:
            for letter in second:
                character = chr(ord(character) ^ ord(letter))
            sed += character 
        print('seed is'+sed)
        return sed 
      
    def obfuscation(self,data,sed):
        randnum="" 
        print('obfuscation started')
        random.seed(sed) 
        for i in range(1,self._counter+1): 
            randnum=random.random()
        print('the random number generated for packet',self._counter,'is',randnum)
        output=""
        for character in data:
            for letter in str(randnum):
                character = chr(ord(character) ^ ord(letter))
            output += character
        return output
        
def main():
    print('first')
    serverside=dnserver()
    print('start')
if __name__=="__main__":main()
            
                
            
            
        
    
            
        
        
            
        
                
    
    
    
    
        
        
        
    
    
    
        
