# Copyright Xenigma 2024 - (C) All Rights Reserved

from CERB256.CERB256e import CERBERUS
from CERB512.CERBEngine import CERBERUS2
from CRIS5.Enc import CRIS5

def Xen(Passw, XenBits="256"):
    XenBits = str(XenBits)
    
    if XenBits == "256":
        Hasher = CERBERUS()
        return Hasher.hash(Passw.encode('utf-8'))
    elif XenBits == "512":
        Hasher = CERBERUS2()
        return Hasher.hash(Passw.encode('utf-8'))
    elif XenBits == "CR5":
        return CRIS5(Passw.encode('utf-8'))
    else:
        raise ValueError("Unsupported XenBits. Use '256' or '512' or 'CR5'.")
