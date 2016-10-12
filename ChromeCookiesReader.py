# coding:utf-8
#
# author: me@qzane.com
# https://github.com/qzane/ChromeCookiesReader

import os
import shutil 
import sys
import ctypes
import sqlite3

class ChromeCookiesReader(object):
    def __init__(self):
        self.chromeCookies = os.getenv("LOCALAPPDATA") + r"\Google\Chrome\User Data\Default\Cookies"
        
    def run(self,dataFile=r'.\Cookies.sqlite'):
        mDecryptor = Decryptor()
        shutil.copyfile(self.chromeCookies, dataFile)
        conn = sqlite3.connect(dataFile)
        cur = conn.cursor()
        cur.execute("CREATE TABLE decrypt (creation_utc INTEGER NOT NULL UNIQUE PRIMARY KEY,host_key TEXT NOT NULL,name TEXT NOT NULL,value TEXT NOT NULL)")
        
        cur.execute('select creation_utc, host_key, name, value, encrypted_value from cookies')
        for creation_utc, host, name, value, encrypted_value in cur.fetchall():
            if value == '': #todo: check cookies.secure
                value = mDecryptor.decrypt(encrypted_value)
                
            cur.execute('insert into decrypt values(?,?,?,?)',(creation_utc, host, name, value))
        conn.commit()
        conn.close()

class BLOB(ctypes.Structure):
    """ CRYPT_INTEGER_BLOB structure """

    _fields_ = [('cbData', ctypes.c_ulong),
                ('pbData', ctypes.POINTER(ctypes.c_byte))]
                
                
    def set(self, data):
        data_len = len(data)
        self.cbData = ctypes.c_ulong(data_len)
        self.pbData = (ctypes.c_byte * data_len)(*(i for i in data))
        
    def get(self):
        data_len = int(self.cbData)
        data = ctypes.cast(self.pbData, ctypes.POINTER(ctypes.c_char))
        result = b''
        for i in range(data_len):
            result += data[i]
        return result
        
class Decryptor(object):  
    
    def __init__(self):
        self.inData = BLOB()
        self.outData = BLOB()
        self.Pin = ctypes.pointer(self.inData)
        self.Pout = ctypes.pointer(self.outData)
        self.func = ctypes.windll.crypt32.CryptUnprotectData
        
    def decrypt(self, data):
        assert(type(data)==bytes)
        self.inData.set(data)
        if self.func(self.Pin, 0, 0, 0, 0, 0, self.Pout) != 1:
            raise(Exception('some thing wrong while using windll.crypt32.CryptUnprotectData'))
        return self.outData.get()
        
if __name__ == '__main__':
    worker = ChromeCookiesReader()
    cwd = os.getcwd()
    dataFile = os.path.join(cwd, 'Cookies.sqlite')
    worker.run(dataFile)
    print('All data are dumped into {} '.format(dataFile))
