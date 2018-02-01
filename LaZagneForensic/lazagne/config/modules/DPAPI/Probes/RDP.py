#!/usr/bin/env python

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

from DPAPI.probe import DPAPIProbe
from DPAPI.Core import blob
from collections import defaultdict


class RDPFile(DPAPIProbe):

    def parse(self, data):
        self.cleartext = None
        self.dpapiblob = None
        self.entropy = None
        self.values = defaultdict(lambda: None)

    def preprocess(self, **k):
        s = []
        if k.get('file'):
            f = open(k['file'], "r")
            s = f.read().split("\n")
            f.close()
        elif k.get('content'):
            s = k['content'].split("\n")
        for l in s:
            (n, t, v) = l.split(":", 3)
            v = v.rstrip()
            if t == 'i':
                v = int(v)
            elif t == 'b':
                if len(v) & 1 == 1:
                    # if odd length, strip the last quartet which should be a
                    # useless "0"
                    v = v[:-1]
                v = v.decode('hex')
            self.values[n] = v
            if self.values['password 51']:
                self.dpapiblob = blob.DPAPIBlob(self.values['password 51'])

    def __repr__(self):
        s = ["RDP Connection file"]
        for p in self.__dict__:
            if self.__dict__[p]:
                s.append("        %s = %r" % (p, self.__dict__[p]))
        return "\n".join(s)


# vim:ts=4:expandtab:sw=4
