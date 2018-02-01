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

from DPAPI import probe
from DPAPI.Core import blob


class ChromePassword(probe.DPAPIProbe):
    """This class represents a Google Chrome password entry that can
        be found in the SQLite databases of this browser.

    """
    def parse(self, data):
        self.dpapiblob = blob.DPAPIBlob(data.remain())

    def __getattr__(self, name):
        return getattr(self.dpapiblob, name)

    def __repr__(self):
        s = ["Google Chrome Password"]
        if self.dpapiblob is not None and self.dpapiblob.decrypted:
            s.append("        password = %s" % self.cleartext)
        s.append("    %r" % self.dpapiblob)
        return "\n".join(s)


# vim:ts=4:expandtab:sw=4
