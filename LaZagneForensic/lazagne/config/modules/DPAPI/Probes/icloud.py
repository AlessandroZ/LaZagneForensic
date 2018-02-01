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
## iCloud Apple token decryption                                           ##
##                                                                         ##
##  Author: Francesco Picasso <francesco.picasso@gmail.com>                ##
##                                                                         ##
#############################################################################

from DPAPI import probe
from DPAPI.Core import blob
from DPAPI.Core import eater
import CFPropertyList


class iCloud(probe.DPAPIProbe):
    """iCloud Apple token decryption"""

    APPLE_ENTROPY = (''
        '\x1D\xAC\xA8\xF8\xD3\xB8\x48\x3E\x48\x7D\x3E\x0A\x62\x07\xDD\x26'
        '\xE6\x67\x81\x03\xE7\xB2\x13\xA5\xB0\x79\xEE\x4F\x0F\x41\x15\xED'
        '\x7B\x14\x8C\xE5\x4B\x46\x0D\xC1\x8E\xFE\xD6\xE7\x27\x75\x06\x8B'
        '\x49\x00\xDC\x0F\x30\xA0\x9E\xFD\x09\x85\xF1\xC8\xAA\x75\xC1\x08'
        '\x05\x79\x01\xE2\x97\xD8\xAF\x80\x38\x60\x0B\x71\x0E\x68\x53\x77'
        '\x2F\x0F\x61\xF6\x1D\x8E\x8F\x5C\xB2\x3D\x21\x74\x40\x4B\xB5\x06'
        '\x6E\xAB\x7A\xBD\x8B\xA9\x7E\x32\x8F\x6E\x06\x24\xD9\x29\xA4\xA5'
        '\xBE\x26\x23\xFD\xEE\xF1\x4C\x0F\x74\x5E\x58\xFB\x91\x74\xEF\x91')

    def preprocess(self, **k):
        self.entropy = self.APPLE_ENTROPY
        with open(k["aoskit"], "rb") as f:
            plist = CFPropertyList.CFPropertyList(f)
            plist.load()
            plist_values = CFPropertyList.native_types(plist.value)
            self.account = plist_values.keys()[0]
            plist_data_dict = plist_values[self.account]
            self.dpapiblob = blob.DPAPIBlob(plist_data_dict['data'])

    def parse(self, data):
        self.dpapiblob = None
        self.account = None
        self.decrypted = None

    def postprocess(self, **k):
        if self.dpapiblob.decrypted:
            e = eater.Eater(self.dpapiblob.cleartext)
            self.decrypted = e.eat_length_and_string("L")

    def __repr__(self):
        s = ["\niCloud Apple token decryption"]
        if self.dpapiblob is not None and self.dpapiblob.decrypted:
            s.append("Binary PLIST file for account %s decrypted!" % self.account)
        else:
            s.append("Unable to decrypt Apple Token for account %s!" % self.account)
        return "\n".join(s)

# vim:ts=4:expandtab:sw=4
