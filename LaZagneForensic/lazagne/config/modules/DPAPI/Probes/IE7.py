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

import hashlib
from lazagne.config.modules.DPAPI import probe
from lazagne.config.modules.DPAPI.Core import blob
from lazagne.config.modules.DPAPI.Core import eater


class IE7Autocomplete(probe.DPAPIProbe):
    class IE7Secret(eater.DataStruct):
        def __init__(self, raw=None):
            self.secrets = []
            eater.DataStruct.__init__(self, raw)

        def parse(self, data):
            data.eat("L")  # header size
            data.eat("L")  # secret info size
            data.eat("L")  # secret size
            data.eat("L")  # magic
            data.eat("L")  # size (24)
            n = data.eat("L")  # total secrets
            data.eat("L")  # unknown
            data.eat("L")  # id
            data.eat("L")  # unknown
            l = []
            off = []
            for i in range(n):
                off.append(data.eat("L"))  # offset
                data.eat_string(8)  # unique id
                l.append(2 * data.eat("L"))  # length
            sec = data.remain()
            for i in range(n):
                self.secrets.append(sec[off[i]:off[i]+l[i]].decode('UTF-16LE'))

        def __repr__(self):
            s = ["IE7Secret",
                 "%s" % repr(self.secrets)]
            return "\n".join(s)

    class IE7Entry(probe.DPAPIProbe):
        def parse(self, data):
            self.dpapiblob = blob.DPAPIBlob(data.remain())
            self.cleartext = None
            self.login = None
            self.password = None
            self.other = []

        def preprocess(self, **k):
            self.entropy = k.get("entropy", None)

        def postprocess(self, **k):
            b = IE7Autocomplete.IE7Secret(self.dpapiblob.cleartext)
            self.login = b.secrets.pop(0)
            self.password = b.secrets.pop(0)
            if len(b.secrets) > 0:
                self.other = b.secrets

        def __repr__(self):
            s = ["Autocomplete Entry",
                 "url     : %s" % self.entropy,
                 "login   : %s" % self.login,
                 "password: %s" % self.password]
            for i in self.other:
                s.append("secret  : %s" % i)
            s.append("blob    : %r" % self.dpapiblob)
            return "\n".join(s)

    def parse(self, data):
        pass

    def preprocess(self, **k):
        self._dicurls = {}
        self.entries = k.get("values", {})
        self.urls = k.get("urls", [])
        ## Compute a dict of sha1 for faster lookup
        for i in self.urls:
            u = (i + "\0").encode("UTF-16LE")
            self._dicurls[hashlib.sha1(u).hexdigest().lower()] = u
        ## Strip the last 2 chars of hash & build the blob
        arr = self.entries.keys()
        for i in arr:
            self.entries[i[:40].lower()] = IE7Autocomplete.IE7Entry(self.entries[i])
            self.entries.pop(i)

    def try_decrypt_with_hash(self, h, mkeypool, sid, **k):
        self.preprocess(**k)
        rv = True
        for e in self.entries.keys():
            if self._dicurls.get(e) is not None:
                if not self.entries[e].try_decrypt_with_hash(h, mkeypool, sid, entropy=self._dicurls[e]):
                    rv = False
        return rv

    def postprocess(self, **k):
        pass

    def __repr__(self):
        s = ["Internet Explorer 7+ autocomplete"]
        for i in self.entries.keys():
            s.append("-" * 50)
            s.append("    %r" % self.entries[i])
        return "\n".join(s)


# vim:ts=4:expandtab:sw=4
