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

from Registry import Registry
from lazagne.config.modules.DPAPI.Core import crypto
from lazagne.config.modules.DPAPI.Core import eater


class Regedit(object):
    """This class provides several functions to handle registry extraction
    stuff.

    """

    def __init__(self):
        self.syskey = None
        self.lsakeys = None
        self.policy = {"major": 0, "minor": 0, "value": 0}
        self.lsa_secrets = {}

    def get_syskey(self, system):
        """Returns the syskey value after decryption from the registry values.

        system argument is the full path to the SYSTEM registry file (usually
        located under %WINDIR%\\system32\\config\\ directory.

        """
        with open(system, 'rb') as f:
            r = Registry.Registry(f)
            cs = r.open("Select").value("Current").value()
            r2 = r.open("ControlSet%03d\\Control\\Lsa" % cs)
            syskey = "".join([r2.subkey(x)._nkrecord.classname() for x in ('JD', 'Skew1', 'GBG', 'Data')])
        syskey = syskey.encode("ascii").decode("hex")
        transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
        self.syskey = ""
        for i in xrange(len(syskey)):
            self.syskey += syskey[transforms[i]]
        return self.syskey

    def get_lsa_key(self, security):
        """Returns and decrypts the LSA secret key for "CurrentControlSet".
        It is stored under Policy\\PolSecretEncryptionKey.

        security is the full path the the SECURITY registry file (usually
        located under %WINDIR%\\system32\\config\\ directory.

        To decrypt the LSA key, syskey is required. Thus you must first call
        self.get_syskey() if it has not been previously done.

        """
        lsakey = ""
        if self.syskey is None:
            raise ValueError("Must provide syskey or call get_syskey() method first")
        with open(security, 'rb') as f:
            r = Registry.Registry(f)
            rev = eater.Eater(r.open("Policy\\PolRevision").value("(default)").value())
            self.policy["minor"] = rev.eat("H")
            self.policy["major"] = rev.eat("H")
            self.policy["value"] = float("%d.%02d" % (self.policy["major"], self.policy["minor"]))
            if self.policy["value"] > 1.09:
                # NT6
                r2 = r.open("Policy\\PolEKList")
                lsakey = r2.value("(default)").value()
            else:
                # NT5
                r2 = r.open("Policy\\PolSecretEncryptionKey")
                lsakey = r2.value("(default)").value()
        rv = None
        if self.policy["value"] > 1.09:
            currentKey, self.lsakeys = crypto.decrypt_lsa_key_nt6(lsakey, self.syskey)
            rv = self.lsakeys[currentKey]["key"]
        else:
            self.lsakeys = crypto.decrypt_lsa_key_nt5(lsakey, self.syskey)
            rv = self.lsakeys[1]
        return rv

    def get_lsa_secrets(self, security, system):
        """Retrieves and decrypts LSA secrets from the registry.
        security and system arguments are the full path to the corresponding
        registry files.
        This function automatically calls self.get_syskey() and
        self.get_lsa_key() functions prior to the secrets retrieval.

        Returns a dictionary of secrets.

        """
        self.get_syskey(system)
        currentKey = self.get_lsa_key(security)
        self.lsa_secrets = {}
        with open(security, 'rb') as f:
            r = Registry.Registry(f)
            r2 = r.open("Policy\\Secrets")
            for i in r2.subkeys():
                self.lsa_secrets[i.name()] = {}
                for j in i.subkeys():
                    self.lsa_secrets[i.name()][j.name()] = j.value('(default)').value()
        for k, v in self.lsa_secrets.iteritems():
            for s in ["CurrVal", "OldVal"]:
                if v[s] != "":
                    if self.policy["value"] > 1.09:
                        # NT6
                        self.lsa_secrets[k][s] = crypto.decrypt_lsa_secret(v[s], self.lsakeys)
                    else:
                        self.lsa_secrets[k][s] = crypto.SystemFunction005(v[s][0xc:], currentKey)
            for s in ["OupdTime", "CupdTime"]:
                if self.lsa_secrets[k][s] > 0:
                    t = eater.Eater(self.lsa_secrets[k][s])
                    self.lsa_secrets[k][s] = (t.eat("Q") / 10000000) - 11644473600

        return self.lsa_secrets

# vim:ts=4:expandtab:sw=4

