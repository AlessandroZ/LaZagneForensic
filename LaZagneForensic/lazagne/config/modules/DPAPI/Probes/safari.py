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

import struct
import CFPropertyList
from DPAPI import probe
from DPAPI.Core import blob


class SafariPassword(probe.DPAPIProbe):

    _entropy = ("1DACA8F8D3B8483E487D3E0A6207DD26E6678103E7B213A5B079EE4F0F4115ED7B148CE54B460DC18EFED6E72775068B"
                "4900DC0F30A09EFD0985F1C8AA75C108057901E297D8AF8038600B710E6853772F0F61F61D8E8F5CB23D2174404BB506"
                "6EAB7ABD8BA97E328F6E0624D929A4A5BE2623FDEEF14C0F745E58FB9174EF91636F6D2E6170706C652E536166617269")

    def parse(self, data):
        self.dpapiblob = blob.DPAPIBlob(data.remain())
        self.cleartext = None

    def preprocess(self, **k):
        self.entropy = SafariPassword._entropy.decode("hex")

    def postprocess(self, **k):
        l = struct.unpack_from("<L", self.dpapiblob.cleartext)[0]
        self.cleartext = self.dpapiblob.cleartext[4:]
        self.cleartext = self.cleartext[:l]

    def __repr__(self):
        s = ["Safari Password"]
        if self.dpapiblob is not None and self.dpapiblob.decrypted:
            s.append("        password = %s" % self.cleartext)
        if self.entropy is not None:
            s.append("        entropy  = %s" % self.entropy.encode("hex"))
        s.append("    %r" % self.dpapiblob)
        return "\n".join(s)


class SafariFile(probe.DPAPIProbe):
    def parse(self, data):
        self.entries = None

    def preprocess(self, **k):
        plist = CFPropertyList.CFPropertyList(k['keychain'])
        plist.load()
        self.entries = CFPropertyList.native_types(plist.value).get('version1')

    def try_decrypt_with_hash(self, h, mkp, sid, **k):
        r = True
        if self.entries is not None:
            for e in self.entries:
                e['Password'] = None
                t = e.get('Data')
                if e.get('Data') is not None:
                    e['blob'] = SafariPassword(e['Data'])
                    e.pop('Data')
                    e['blob'].preprocess(**k)
                    if e['blob'].try_decrypt_with_hash(h, mkp, sid, **k):
                        e['blob'].postprocess(**k)
                    else:
                        r = False
        if r:
            self.postprocess(**k)
        return r

    def postprocess(self, **k):
        for e in self.entries:
            if e.get('blob') is not None:
                if e['blob'].cleartext is not None:
                    e['Password'] = e['blob'].cleartext
                e.pop('blob')

    def __repr__(self):
        s = ["Safari Password File"]
        for e in self.entries:
            s.append("-"*50)
            s.append("%s" % repr(e))
        return "\n".join(s)

# vim:ts=4:expandtab:sw=4
