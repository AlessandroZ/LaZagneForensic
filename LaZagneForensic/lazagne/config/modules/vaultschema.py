#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Credits goes to Benjamin Delphy aka @gentilkiwi and his Mimikatz project:
# vault structs are a mix of my research and his research.
"""Windows Vaults Schema structures and helpers."""

import construct
import struct

# Construct adapters.

class GuidAdapter(construct.Adapter):
    def _decode(self, obj, context):
        return '{:08x}-{:04x}-{:04x}-{:04x}-{:s}'.format(
            construct.ULInt32('foo').parse(obj[0:4]),
            construct.ULInt16('foo').parse(obj[4:6]),
            construct.ULInt16('foo').parse(obj[6:8]),
            construct.UBInt16('foo').parse(obj[8:10]),
            obj[10:16].encode('hex'))


def GUID(name):
    return GuidAdapter(construct.Bytes(name, 16))


class SidAdapter(construct.Adapter):
    def _decode(self, obj, context):
        el = [
            int(construct.Byte('foo').parse(obj[0:1])),
            (int(construct.ULInt32('foo').parse(obj[1:5])) +
                (int(construct.ULInt16('foo').parse(obj[5:7])) << 32))]
        
        auth_sub_count = construct.Byte('foo').parse(obj[7:8])
        for i in range(0, auth_sub_count):
            el.append(construct.ULInt32('foo').parse(obj[8+i*4:]))
            
        return 'S-' + '-'.join([str(x) for x in el])


def SID(name, length):
    return SidAdapter(construct.Bytes(name, length))


class BytesHexAdapter(construct.Adapter):
    '''Hex encoding output.'''
    def _decode(self, obj, context):
        return obj.encode('hex')


class NumericPinAdapter(construct.Adapter):
    '''Helper to pretty print the numeric PIN code.'''
    def _decode(self, obj, context):
        try:
            pin = int(''.join(reversed(
                [obj.data[i:i+2] for i in range(0, len(obj.data), 2)])), 16)
        except:
            return obj.data
        return pin


class UnicodeStringActiveSyncAdapter(construct.Adapter):
    '''Helper to pretty print string/hex and remove trailing zeroes.'''
    def _decode(self, obj, context):
        try:
            decoded = obj.decode('utf16')
            decoded = decoded.rstrip('\00').encode('utf8')
            if len(obj) <= 8:
                decoded = '{0:s} [hex: {1:s}]'.format(
                    decoded, obj.encode('hex'))
        except UnicodeDecodeError:
            decoded = obj.encode('hex')
        return decoded


class UnicodeOrHexAdapter(construct.Adapter):
    '''Helper to pretty print string/hex and remove trailing zeroes.'''
    def _decode(self, obj, context):
        try:
            decoded = obj.decode('utf16')
            decoded = decoded.rstrip('\00').encode('utf8')
        except UnicodeDecodeError:
            decoded = obj.encode('hex')
        return decoded


class UnicodeRstripZero(construct.Adapter):
    '''Helper to remove trailing zeroes.'''
    def _decode(self, obj, context):
        return obj.rstrip('\x00\x00')


class  VaultSchemaActiveSyncAdapter(construct.Adapter):
    def _decode(self, obj, context):
        return (
            'identity: {0:s}\nresource: {1:s}\nauthenticator: {2:s}'.format(
                obj.identity.data, obj.resource.data, obj.authenticator.data))


class VaultSchemaPinAdapter(construct.Adapter):
    def _decode(self, obj, context):
        return (
            'sid: {0:s}\nresource: {1:s}\npassword: {2:s}\npin: {3:d}'.format(
                obj.sid, obj.resource.data, obj.password.data, obj.pin))


class VaultSchemaSimpleAdapter(construct.Adapter):
    def _decode(self, obj, context):
        dataout = str(bytearray(obj.data))
        return 'hex: {0:s}'.format(dataout.encode('hex'))


class  VaultSchemaWebPasswordAdapter(construct.Adapter):
    def _decode(self, obj, context):
        return (
            'identity: {0:s}\nresource: {1:s}\nauthenticator: {2:s}'.format(
                obj.identity.data, obj.resource.data, obj.authenticator.data))


# Common structs.

UNICODE_STRING_ACTIVESYNC = construct.Struct(
    'UNICODE_STRING_ACTIVESYNC',
    construct.ULInt32('length'),
    UnicodeStringActiveSyncAdapter(
        construct.Bytes('data', lambda ctx: ctx.length)))

UNICODE_STRING_STRIP = construct.Struct(
    'UNICODE_STRING_STRIP',
    construct.ULInt32('length'),
    UnicodeRstripZero(
        construct.String('data', lambda ctx: ctx.length, encoding='utf16')))

UNICODE_STRING_HEX = construct.Struct(
    'UNICODE_STRING_HEX',
    construct.ULInt32('length'),
    UnicodeOrHexAdapter(construct.Bytes('data', lambda ctx: ctx.length)))

SIZED_DATA = construct.Struct(
    'SIZED_DATA',
    construct.ULInt32('size'),
    BytesHexAdapter(construct.Bytes('data', lambda ctx: ctx.size))
)

construct.Struct(
    'SIZED_DATA',
    construct.ULInt32('size'),
    BytesHexAdapter(construct.Bytes('data', lambda ctx: ctx.size))
)

# Vault file partial parsing

VAULT_VSCH = construct.Struct(
    'VAULT_VSCH',
    construct.ULInt32('version'),
    GUID('schema_guid'),
    construct.ULInt32('vault_vsch_unknown_1'),
    construct.ULInt32('count'),
    construct.Rename('schema_name', UNICODE_STRING_STRIP)
)

# Generic Vault Schema

VAULT_ATTRIBUTE_ITEM = construct.Struct(
    'VAULT_ATTRIBUTE_ITEM',
    construct.ULInt32('id'),
    construct.Switch(
        'item',
        lambda ctx: ctx.id,
        {
            1: construct.Rename('resource', UNICODE_STRING_HEX),
            2: construct.Rename('identity', UNICODE_STRING_HEX),
            3: construct.Rename('authenticator', UNICODE_STRING_HEX),
        },
        default = construct.Rename('generic', SIZED_DATA))
)

VAULT_SCHEMA_GENERIC = construct.Struct(
    'VAULT_SCHEMA_GENERIC',
    construct.ULInt32('version'),
    construct.ULInt32('count'),
    construct.ULInt32('vault_schema_generic_unknown1'),
    construct.Array(
        lambda ctx: ctx.count,
        VAULT_ATTRIBUTE_ITEM)   
)

# Vault Simple Schema

VAULT_SCHEMA_SIMPLE = VaultSchemaSimpleAdapter(
    construct.Struct(
        'VAULT_SCHEMA_SIMPLE',
        construct.OptionalGreedyRange(construct.Byte('data'))
    )
)

# PIN Logon Vault Resource Schema

VAULT_SCHEMA_PIN = VaultSchemaPinAdapter(
    construct.Struct(
        'VAULT_SCHEMA_PIN',
        construct.ULInt32('version'),
        construct.Const(construct.ULInt32('count'), 4),
        construct.ULInt32('vault_schema_pin_unknown1'),
        construct.Const(construct.ULInt32('id_sid'), 2),
        construct.ULInt32('sid_len'),
        SID('sid', lambda ctx: ctx.sid_len),
        construct.Const(construct.ULInt32('id_resource'), 1),
        construct.Rename('resource', UNICODE_STRING_STRIP),
        construct.Const(construct.ULInt32('id_password'), 3),
        construct.Rename('password', UNICODE_STRING_STRIP),
        construct.ULInt32('id_pin'),
        NumericPinAdapter(construct.Rename('pin', SIZED_DATA))  
    )
)

# Windows Web Password Credential Schema

VAULT_SCHEMA_WEB_PASSWORD = VaultSchemaWebPasswordAdapter(
    construct.Struct(
        'VAULT_SCHEMA_WEB_PASSWORD',
        construct.ULInt32('version'),
        construct.Const(construct.ULInt32('count'), 3),
        construct.ULInt32('vault_schema_web_password_unknown1'),
        construct.Const(construct.ULInt32('id_identity'), 2),
        construct.Rename('identity', UNICODE_STRING_STRIP),
        construct.Const(construct.ULInt32('id_resource'), 1),
        construct.Rename('resource', UNICODE_STRING_STRIP),
        construct.Const(construct.ULInt32('id_authenticator'), 3),
        construct.Rename('authenticator', UNICODE_STRING_STRIP)
    )
)

# Active Sync Credential Schema

VAULT_SCHEMA_ACTIVESYNC = VaultSchemaActiveSyncAdapter(
    construct.Struct(
        'VAULT_SCHEMA_ACTIVESYNC',
        construct.ULInt32('version'),
        construct.Const(construct.ULInt32('count'), 3),
        construct.ULInt32('vault_schema_activesync_unknown1'),
        construct.Const(construct.ULInt32('id_identity'), 2),
        construct.Rename('identity', UNICODE_STRING_STRIP),
        construct.Const(construct.ULInt32('id_resource'), 1),
        construct.Rename('resource', UNICODE_STRING_STRIP),
        construct.Const(construct.ULInt32('id_authenticator'), 3),
        construct.Rename('authenticator', UNICODE_STRING_ACTIVESYNC)
    )
)

# Vault Schema Dict

vault_schemas = {
    u'ActiveSyncCredentialSchema': VAULT_SCHEMA_ACTIVESYNC,
    u'PIN Logon Vault Resource Schema': VAULT_SCHEMA_PIN,
    u'Windows Web Password Credential': VAULT_SCHEMA_WEB_PASSWORD,
}
