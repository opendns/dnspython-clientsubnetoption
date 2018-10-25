#!/usr/bin/env python
#
# Copyright (c) 2012 OpenDNS, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of the OpenDNS nor the names of its contributors may be
#      used to endorse or promote products derived from this software without
#      specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL OPENDNS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

""" Class to implement RFC 7871 Client Subnet in DNS Queries

The contained class supports both IPv4 and IPv6 addresses.
Requirements:
  dnspython (http://www.dnspython.org/)
"""
from __future__ import print_function
from __future__ import division

import socket
import struct
import dns
import dns.edns

__author__ = "bhartvigsen@opendns.com (Brian Hartvigsen)"
__version__ = "3.0.0a1"

ASSIGNED_OPTION_CODE = 0x0008
DRAFT_OPTION_CODE = 0x50FA
_BITS_TO_SEGMENT = 8


class ClientSubnetOption(dns.edns.Option):
    """Implementation of RFC 7871 Client Subnet in DNS Queries

    Attributes:
        family: An integer inidicating which address family is being sent
        ip: IP address in integer notation
        mask: An integer representing the number of relevant bits being sent
        scope: An integer representing the number of significant bits used by
            the authoritative server.
    """

    factory = []
    _MIN_BITS = 0

    @staticmethod
    def FromIPString(ip, mask=-1, scope=0, option=ASSIGNED_OPTION_CODE):
        opt = None
        for make in ClientSubnetOption.factory:
            try:
                opt = make(ip, mask, scope, option)
            except socket.error as e:
                pass
            except AttributeError as e:
                raise e
        return opt

    @staticmethod
    def GetClassFromFamily(family):
        for make in ClientSubnetOption.factory:
            if make._IANA_FAMILY == family:
                return make
        raise NotImplementedError('Family type {0} is not implemented'.format(family))

    def __init__(self, scope, option):
        super(ClientSubnetOption, self).__init__(option)
        self.scope = scope
        self.option = option

    def __repr__(self):
        return "{0:s}({1:s}, {2:s}, {3:s})".format(
            self.__class__.__name__,
            self._ip_to_str(),
            self.mask,
            self.scope
        )

    def __eq__(self, other):
        """Rich comparison method for equality.

        Two ClientSubnetOptions are equal if their relevant ip bits, mask, and
        family are identical. We ignore scope since generally we want to
        compare questions to responses and that bit is only relevant when
        determining caching behavior.

        Returns:
            boolean
        """

        if not isinstance(other, ClientSubnetOption):
            return False
        if self.calculate_address() != other.calculate_address():
            return False
        if self.mask != other.mask:
            return False
        if self._IANA_FAMILY != other._IANA_FAMILY:
            return False
        return True

    def __ne__(self, other):
        """Rich comparison method for inequality.

        See notes for __eq__()

        Returns:
            boolean
        """
        return not self.__eq__(other)

    def calculate_address(self):
        raise NotImplementedError('Nothing to see here')

    def _to_packed(self, ip):
        raise NotImplementedError('Nothing to see here')

    def is_draft(self):
        """" Determines whether this instance is using the draft option code """
        return self.option == DRAFT_OPTION_CODE

    def to_wire(self, file):
        """Create EDNS packet as definied in draft-vandergaast-edns-client-subnet-01."""

        ip = self.calculate_address()
        ip = self._to_packed(ip)

        mask_bits = self.mask
        if mask_bits % _BITS_TO_SEGMENT != 0:
                mask_bits += _BITS_TO_SEGMENT - (self.mask % _BITS_TO_SEGMENT)
        ip = ip[-(mask_bits // _BITS_TO_SEGMENT):]

        format = "!HBB{0:d}s".format(mask_bits // _BITS_TO_SEGMENT)
        data = struct.pack(format, self._IANA_FAMILY, self.mask, 0, ip)
        file.write(data)

    @classmethod
    def from_wire(cls, option, wire, current, olen):
        """Read EDNS packet as defined in RFC 7871 Client Subnet in DNS Queries

        Returns:
            An instance of ClientSubnetOption based on the ENDS packet
        """

        data = wire[current:current + olen]
        (family, mask, scope) = struct.unpack("!HBB", data[:4])

        c_mask = mask
        if mask % _BITS_TO_SEGMENT != 0:
            c_mask += _BITS_TO_SEGMENT - (mask % _BITS_TO_SEGMENT)

        ip = struct.unpack_from("!{0:d}s".format(c_mask // _BITS_TO_SEGMENT), data, 4)[0]

        child = cls.GetClassFromFamily(family)
        ip = ip + b'\0' * ((child._MAX_BITS - c_mask) // _BITS_TO_SEGMENT)
        ip = child._packed_ip_to_str(ip)

        return child(ip, mask, scope, option)


class _IPClientSubnetOption(ClientSubnetOption):
    def __init__(self, ip, mask=-1, scope=0, option=ASSIGNED_OPTION_CODE):
        ip = socket.inet_pton(self._AF_FAMILY, ip)
        ip = struct.unpack(self._STRUCT, ip)
        self.ip = self._to_int(ip)

        if mask == -1:
            if self._AF_FAMILY == socket.AF_INET6:
                mask = 48
            else:
                mask = 24

        if mask > self._MAX_BITS or mask < self._MIN_BITS:
            raise AttributeError('bits must be between {0} and {1}'.format(
                self._MIN_BITS,
                self._MAX_BITS
            ))
        self.mask = mask

        if scope > self._MAX_BITS or scope < self._MIN_BITS:
            raise AttributeError('scope must be between {0} and {1}'.format(
                self._MIN_BITS,
                self._MAX_BITS
            ))
        self.scope = scope

        super(_IPClientSubnetOption, self).__init__(scope, option)

    def _to_int(self, ip):
        raise NotImplementedError('Nothing to see here')

    def calculate_address(self):
        ip = self.ip >> (self._MAX_BITS - self.mask)

        # 8 bits per segment
        if (self.mask % _BITS_TO_SEGMENT != 0):
            ip = ip << (_BITS_TO_SEGMENT - (self.mask % _BITS_TO_SEGMENT))

        return ip

    @classmethod
    def _packed_ip_to_str(cls, ip):
        return socket.inet_ntop(cls._AF_FAMILY, ip)

    def _ip_to_str(self):
        return self._packed_ip_to_str(self._to_packed(self.ip))


class _IPv6ClientSubnetOption(_IPClientSubnetOption):
    _AF_FAMILY = socket.AF_INET6
    _IANA_FAMILY = 2
    _MAX_BITS = 128
    _STRUCT = '!QQ'

    def _to_int(self, ip):
        return ip[0] << 64 | ip[1]

    def _to_packed(self, ip):
        return struct.pack(self._STRUCT, ip >> 64, ip & (2 ** 64 - 1))


class _IPv4ClientSubnetOption(_IPClientSubnetOption):
    _AF_FAMILY = socket.AF_INET
    _IANA_FAMILY = 1
    _MAX_BITS = 32
    _STRUCT = '!L'

    def _to_int(self, ip):
        return ip[0]

    def _to_packed(self, ip):
        return struct.pack(self._STRUCT, ip)

ClientSubnetOption.factory.append(_IPv4ClientSubnetOption)
ClientSubnetOption.factory.append(_IPv6ClientSubnetOption)

dns.edns._type_to_class[DRAFT_OPTION_CODE] = ClientSubnetOption
dns.edns._type_to_class[ASSIGNED_OPTION_CODE] = ClientSubnetOption

if __name__ == "__main__":
    import argparse
    import sys
    import dns.message
    import dns.query

    def CheckForClientSubnetOption(addr, args, option_code=ASSIGNED_OPTION_CODE):
        print("Testing for edns-clientsubnet using option code", hex(option_code), file=sys.stderr)
        cso = ClientSubnetOption.FromIPString(args.subnet, args.mask, option=option_code)
        message = dns.message.make_query(args.rr, args.type)
        # Tested authoritative servers seem to use the last code in cases
        # where they support both. We make the official code last to allow
        # us to check for support of both draft and official
        message.use_edns(options=[cso])

        if args.recursive:
            message.flags = message.flags | dns.flags.RD

        try:
            r = dns.query.udp(message, addr, timeout=args.timeout)
            if r.flags & dns.flags.TC:
                r = dns.query.tcp(message, addr, timeout=args.timeout)
        except dns.exception.Timeout:
            print("Timeout: No answer received from {0:s}".format(args.nameserver), file=sys.stderr)
            return

        error = False
        found = False
        for options in r.options:
            # Have not run into anyone who passes back both codes yet
            # but just in case, we want to check all possible options
            if isinstance(options, ClientSubnetOption):
                found = True
                print("Found ClientSubnetOption...", end="", file=sys.stderr)
                if not cso._IANA_FAMILY == options._IANA_FAMILY:
                    error = True
                    print("\nFailed: returned family ({0:d}) is different from the passed family ({1:d})".format(options._IANA_FAMILY, cso._IANA_FAMILY), file=sys.stderr)
                if not cso.calculate_address() == options.calculate_address():
                    error = True
                    print("\nFailed: returned ip ({0:s}) is different from the passed ip ({1:s}).".format(options.calculate_address(), cso.calculate_address()), file=sys.stderr)
                if not options.mask == cso.mask:
                    error = True
                    print("\nFailed: returned mask bits ({0:d}) is different from the passed mask bits ({1:d})".format(options.mask, cso.mask), file=sys.stderr)
                if not options.scope != 0:
                    print("\nWarning: scope indicates edns-clientsubnet data is not used", file=sys.stderr)
                if options.is_draft():
                    print("\nWarning: detected support for edns-clientsubnet draft code", file=sys.stderr)

        if found and not error:
            print("Success", file=sys.stderr)
        elif found:
            print("Failed: See error messages above", file=sys.stderr)
        else:
            print("Failed: No ClientSubnetOption returned", file=sys.stderr)

    parser = argparse.ArgumentParser(description='RFC 7871 Client Subnet in DNS Queries tester')
    parser.add_argument('nameserver', help='The nameserver to test')
    parser.add_argument('rr', help='DNS record that should return an EDNS enabled response')
    parser.add_argument('-s', '--subnet', help='Specifies an IP to pass as the client subnet.', default='192.0.2.0')
    parser.add_argument('-m', '--mask', type=int, help='CIDR mask to use for subnet')
    parser.add_argument('--timeout', type=int, help='Set the timeout for query to TIMEOUT seconds, default=10', default=10)
    parser.add_argument('-t', '--type', help='DNS query type, default=A', default='A')
    parser.add_argument('-r', '--recursive', action="store_true", help='Send a query with RD bits set', default=False)
    args = parser.parse_args()

    if not args.mask:
        if ':' in args.subnet:
            args.mask = 48
        else:
            args.mask = 24

    try:
        addr = socket.gethostbyname(args.nameserver)
    except socket.gaierror:
        print("Unable to resolve {0:s}".format(args.nameserver), file=sys.stderr)
        sys.exit(3)

    CheckForClientSubnetOption(addr, args, DRAFT_OPTION_CODE)
    print("", file=sys.stderr)
    CheckForClientSubnetOption(addr, args, ASSIGNED_OPTION_CODE)
