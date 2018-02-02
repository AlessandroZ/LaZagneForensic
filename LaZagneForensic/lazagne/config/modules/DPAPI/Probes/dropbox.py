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
##                                                                         ##
## Dropbox DBX password                                                    ##
##                                                                         ##
## The following code ia based on the awesome research made by             ##
## Florian Ledoux and Nicolas Ruff                                         ##
## "A critical analysis of Dropbox software security"                      ##
## Open Source code here: https://github.com/newsoft                       ##
##                                                                         ##
##  Author: Francesco Picasso <francesco.picasso@gmail.com>                ##
##                                                                         ##
#############################################################################

from lazagne.config.modules.DPAPI import probe
from lazagne.config.modules.DPAPI.Core import blob
import hmac
from Crypto.Protocol import KDF


class Dropbox(probe.DPAPIProbe):
    """Dropbox DBX password decryptor, Version 0"""

    # TODO: make a better versioning.
    V0_HMAC_KEY = '\xd1\x14\xa5R\x12e_t\xbdw.7\xe6J\xee\x9b'
    V0_APP_KEY = '\rc\x8c\t.\x8b\x82\xfcE(\x83\xf9_5[\x8e'
    V0_APP_IV = '\xd8\x9bC\x1f\xb6\x1d\xde\x1a\xfd\xa4\xb7\xf9\xf4\xb8\r\x05'
    V0_APP_ITER = 1066
    V0_USER_KEYLEN = 16
    V0_DB_KEYLEN = 16
    V0_CRC_LEN = 16

    def parse(self, data):
        self.crc_ok = False
        self.user_key = None
        self.dbx_key = None
        data.pop('B')
        self.crc = data.pop_string(self.V0_CRC_LEN)
        self.raw = data.remain()
        self.version, dpapi_len = data.eat('LL')
        self.dpapiblob = blob.DPAPIBlob(data.eat_string(dpapi_len))

    def preprocess(self, **k):
        self.entropy = self.V0_HMAC_KEY
        hm = hmac.new(self.V0_HMAC_KEY, self.raw).digest()
        self.crc_ok = hm == self.crc

    def postprocess(self, **k):
        if self.dpapiblob.decrypted:
            self.user_key = self.dpapiblob.cleartext
            self.dbx_key = KDF.PBKDF2(self.user_key, self.V0_APP_KEY, self.V0_DB_KEYLEN, self.V0_APP_ITER)

    def __getattr__(self, name):
        return getattr(self.dpapiblob, name)

    def __repr__(self):
        s = ["\nDropbox DBX password"]
        if self.dpapiblob is not None and self.dpapiblob.decrypted:
            s.append("%s\n" % self.user_key.encode('hex'))
            if self.version != 0:
                s.append("*WARNING* version is not 0 but %s" % self.version)
                s.append("          The DBX password could be wrong!")
            if self.crc_ok is False:
                s.append("*WARNING* Drobox DPAPI blob CRC check failed!")
                s.append("          The DBX password could be wrong!")
        # s.append("    %r" % self.dpapiblob)
        return "\n".join(s)

# vim:ts=4:expandtab:sw=4
