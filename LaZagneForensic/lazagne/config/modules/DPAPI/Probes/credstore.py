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
import datetime
from lazagne.config.modules.DPAPI import probe
from lazagne.config.modules.DPAPI.Core import blob


# http://www.securityxploded.com/networkpasswordsecrets.php
class CredentialStore(probe.DPAPIProbe):
    """This class represents a Credential Store file.
        It parses the file to extract the header, then builds a CredArray
        object that will contain Credential objects that are the actual blob

    """

    class Credential(probe.DPAPIProbe):
        """Represents an entry in the credential store."""

        _entropy = {
            1: "abe2869f-9b47-4cd9-a358-c22904dba7f7\0",
            4: "82BD0E67-9FEA-4748-8672-D5EFE5B779B0\0"
        }
        _type = {
            1: 'Generic',
            2: 'Domain password',
            3: 'Domain certificate',
            4: 'Domain Visible password',
            5: 'Generic certificate',
            6: 'Domain extended'
        }
        _persist = ["No", "Session", "Local machine", "Entreprise"]

        def parse(self, data):
            tmp = data.read("L")
            d = data
            if tmp == 0:
                # Windows 7
                data.read("L")
                self.credtype = data.eat("L")
                data.eat("L")
            else:
                # Windows XP
                d = data.eat_sub(tmp)
                d.eat("2L")
                self.credtype = d.eat("L")
            self.timestamp = d.eat("Q")  # timestamp 64bits
            if self.timestamp > 0:
                self.timestamp /= 10000000
                self.timestamp -= 11644473600

            d.eat("L")
            self.persist = d.eat("L")
            d.eat("3L")  # NULL
            self.name = d.eat_length_and_string("L").decode("UTF-16LE")
            self.comment = d.eat_length_and_string("L").decode("UTF-16LE")
            self.alias = d.eat_length_and_string("L").decode("UTF-16LE")
            if tmp == 0:
                # windows 7
                d.eat_length_and_string("L")
            self.username = d.eat_length_and_string("L").decode("UTF-16LE")
            self.password = None
            if self.credtype == 1 or self.credtype == 4:
                self.dpapiblob = blob.DPAPIBlob(d.eat_length_and_string("L"))
            elif self.credtype == 2:  # domain password
                self.password = d.eat_length_and_string("L")
                self.password = self.password.decode('UTF-16LE')
                self.dpapiblob = None
            elif self.credtype == 3:  # domain certificate
                self.password = d.eat_length_and_string("L")
                self.dpapiblob = None

            self.entropy = self._entropy.get(self.credtype)
            if self.entropy is not None:
                s = ""
                for c in self.entropy:
                    s += struct.pack("<h", ord(c) << 2)
                self.entropy = s

        def try_decrypt_with_hash(self, h, mkp, sid, **k):
            if self.dpapiblob is not None:
                return super(CredentialStore.Credential, self).try_decrypt_with_hash(h, mkp, sid, **k)
            return True

        def postprocess(self, **k):
            if self.credtype == 1:
                v = self.dpapiblob.cleartext.split(":", 2)
                self.username = v[0]
                self.password = v[1]
            if self.credtype == 4:
                self.password = self.dpapiblob.cleartext.decode('UTF-16LE')

        def __repr__(self):
            s = ["Credential",
                 "    Type    : %s" % self._type.get(self.credtype, "Unknown"),
                 "    Persist : %s" % self._persist[self.persist],
                 "    Name    : %s" % self.name,
                 "    Username: %s" % self.username,
                 "    Comment : %s" % self.comment,
                 "    Alias   : %s" % self.alias]
            if self.password is not None:
                s.append("    Password: %s" % self.password)
            tmp = datetime.datetime.utcfromtimestamp(self.timestamp).ctime()
            s.append("    When    : %s" % tmp)
            if self.entropy is not None:
                s.append("    Entropy : %s" % self.entropy.encode('hex'))
            s.append("    Blob    : %s" % repr(self.dpapiblob))
            return "\n".join(s)

    class CredArray(probe.DPAPIProbe):
        """Represents all the credential entries that are contained in the
            credential store file.

        """
        def parse(self, data):
            self.revision = data.eat("L")
            self.totallen = data.eat("L")
            self.creds = []
            while data:
                c = CredentialStore.Credential()
                c.parse(data)
                self.creds.append(c)

        def postprocess(self, **k):
            for c in self.creds:
                c.postprocess(**k)

        def try_decrypt_with_hash(self, h, mkp, sid, **k):
            """Returns True if all the entries has been successfully
                decrypted.

                This may change in future versions as in forensics usage
                we just want to retreive as many credentials as we can.

            """
            r = True
            for c in self.creds:
                r &= c.try_decrypt_with_hash(h, mkp, sid, **k)
            return r

        def __repr__(self):
            return ("\n" + "-" * 50 + "\n").join(map(lambda x: repr(x), self.creds))

    def parse(self, data):
        self.dpapiblob = blob.DPAPIBlob(data.remain())
        self.store = None

    def try_decrypt_with_hash(self, h, mkp, sid, **k):
        if super(CredentialStore, self).try_decrypt_with_hash(h, mkp, sid, **k):
            self.store = CredentialStore.CredArray(self.dpapiblob.cleartext)
            return self.store.try_decrypt_with_hash(h, mkp, sid, **k)
        return False

    def __repr__(self):
        s = ["Credential Store"]
        if self.store is not None:
            s.append("    %s" % repr(self.store))
        return "\n".join(s)


# vim:ts=4:expandtab:sw=4
