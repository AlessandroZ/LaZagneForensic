#!/usr/bin/env python
# -*- coding: utf-8 -*-

#############################################################################
##                                                                         ##
## This file is part of DPAPIck                                            ##
## Windows DPAPI decryption & forensic toolkit                             ##
##                                                                         ##
##                                                                         ##
## Copyright (C) 2010, 2011 Cassidian SAS. All rights reserved.            ##
## This document is the property of Cassidian SAS, it may not be copied or ##
## circulated without prior licence                                        ##
##                                                                         ##
##  Author: Jean-Michel Picod <jmichel.p@gmail.com>                        ##
##                                                                         ##
## This program is distributed under GPLv3 licence (see LICENCE.txt)       ##
##                                                                         ##
#############################################################################

from xml.etree import ElementTree
import hashlib
import struct
import array
from Crypto.Cipher import AES
from lazagne.config.modules.DPAPI import probe
from lazagne.config.modules.DPAPI.Core import blob


class SkypeAccount(probe.DPAPIProbe):

    def parse(self, data):
        self.login = None
        self.cleartext = None
        self.dpapiblob = blob.DPAPIBlob(data.remain())
        self.entropy = None

    def preprocess(self, **k):
        self.login = k.get('login')
        if k.get('xmlfile') is not None:
            tree = ElementTree.parse(k['xmlfile'])
        else:
            tree = ElementTree.fromstring(k['xml'])
        self.cred = tree.find(".//Account/Credentials2")
        if self.cred is None:
            self.cred = tree.find(".//Account/Credentials3")
        if self.cred is not None:
            self.cred = self.cred.text.decode('hex')

    def postprocess(self, **k):
        if self.cred is None:
            return
        # use SHA-1 counter mode to expand the key
        k = hashlib.sha1(struct.pack(">L", 0) + self.dpapiblob.cleartext).digest()
        k += hashlib.sha1(struct.pack(">L", 1) + self.dpapiblob.cleartext).digest()
        # use AES-256 CTR mode
        ciph = AES.new(k[:32], mode=AES.MODE_ECB)
        arr = array.array("B")
        arr.fromstring(self.cred)
        for i in range(0, len(self.cred), 16):
            buff = ciph.encrypt("\0"*12 + struct.pack(">L", i >> 4))
            for j in range(min(16, len(self.cred) - i)):
                arr[i + j] ^= ord(buff[j])
        self.cleartext = arr.tostring().encode('hex')

    def __getattr__(self, name):
        return getattr(self.dpapiblob, name)

    def jtr_shadow(self):
        if self.login is not None:
            return "%s:$dynamic_1401$%s" % (self.login, self.cleartext[:32])
        return ""

    def __repr__(self):
        s = ["Skype account"]
        if self.login is not None:
            s.append("        login = %s" % self.login)
        s.append("        hash  = %s" % self.cleartext[:32])
        return "\n".join(s)


# vim:ts=4:expandtab:sw=4
