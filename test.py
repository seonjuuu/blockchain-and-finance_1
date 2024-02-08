
def fun(finput):
    finput = finput&0xff
    finput1 = finput<<2
    finput1 = (finput1+finput)%(1<<8)
    finput2 = finput<<4
    finput2 = (finput1+finput2)%(1<<8)
    
    return finput2
    
def toy_cipher(pt,key):
    pt = pt&0xffff
    key= key&0xffff

    pt = pt^key
    
    L1 = (pt>>8)&0xff  #왼쪽으로 이동시킨후 8bit 떼어줘여함
    R1 = pt&0xff
    
    R2 = L1^fun(R1)
    L2 = R1
    
    L3 = L2^fun(R2)
    R3 = R2
    
    ct = (L3<<8)
    ct = ct^R3
    
    return ct

plaintext = 0x5A3C
key = 0x7B28
print("{:04x}".format(toy_cipher(plaintext, key))) #fd85
    