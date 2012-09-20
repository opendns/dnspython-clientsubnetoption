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
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL OPENDNS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

""" Class to implement draft-vandergaast-edns-client-subnet-01.

The contained class supports both IPv4 and IPv6 family and addresses.
Requirements:
  dnspython (http://www.dnspython.org/)
"""

import socket
import struct
import sys
import dns
import dns.edns
import dns.flags
import dns.message
import dns.query

__author__ = "bhartvigsen@opendns.com (Brian Hartvigsen)"
__version__ = "1.0.0"


class ClientSubnetOption(dns.edns.Option):
    """Implementation of draft-vandergaast-edns-client-subnet-01.

    Attributes:
        family: An integer inidicating which address family is being sent
        ip: IP address in integer notation
        mask: An integer representing the number of relevant bits being sent
        scope: An integer representing the number of significant bits used by
            the authoritative server.
    """

    def __init__(self, family, ip, bits=24, scope=0):
        super(ClientSubnetOption, self).__init__(0x50fa)

        if not (family == 1 or family == 2):
            raise Exception("Family must be either 1 (IPv4) or 2 (IPv6)")

        self.family = family
        self.ip = ip
        self.mask = bits
        self.scope = scope

        if self.family == 1 and self.mask > 32:
            raise Exception("32 bits is the max for IPv4 (%d)" % bits)
        if self.family == 2 and self.mask > 128:
            raise Exception("128 bits is the max for IPv6 (%d)" % bits)

    def calculate_ip(self):
        if self.family == 1:
            bits = 32
        elif self.family == 2:
            bits = 128

        ip = self.ip >> bits - self.mask

        if (self.mask % 8 != 0):
            ip = ip << 8 - (self.mask % 8)

        return ip

    def to_wire(self, file):
        ip = self.calculate_ip()

        mask_bits = self.mask
        if mask_bits % 8 != 0:
                mask_bits += 8 - (self.mask % 8)

        if self.family == 1:
            test = struct.pack("!L", ip)
        elif self.family == 2:
            test = struct.pack("!QQ", ip >> 64, ip & (2 ** 64 - 1))
        test = test[-(mask_bits / 8):]

        format = "!HBB%ds" % (mask_bits / 8)
        data = struct.pack(format, self.family, self.mask, 0, test)
        file.write(data)

    def from_wire(cls, otype, wire, current, olen):
        data = wire[current:current + olen]
        (family, mask, scope) = struct.unpack("!HBB", data[:4])

        c_mask = mask
        if mask % 8 != 0:
            c_mask += 8 - (mask % 8)

        ip = struct.unpack_from("!%ds" % (c_mask / 8), data, 4)[0]

        if (family == 1):
            ip = struct.unpack("!L", ip + '\0' * ((32 - c_mask) / 8))[0]
        elif (family == 2):
            hi, lo = struct.unpack("!QQ", ip + '\0' * ((128 - c_mask) / 8))
            ip = hi << 64 | lo
        else:
            raise Exception("Returned a family other then 1 (IPv4) or 2 (IPv6)")

        return cls(family, ip, mask, scope)

    from_wire = classmethod(from_wire)

dns.edns._type_to_class[0x50fa] = ClientSubnetOption

if __name__ == "__main__":
    if len(sys.argv) <= 2:
        print("Format is %s [nameserver] [record] ([ip_to_fake [mask]])" % sys.argv[0])
        sys.exit(1)

    if len(sys.argv) >= 4:
        if ":" in sys.argv[3]:
            family = 2
            hi, lo = struct.unpack('!QQ', socket.inet_pton(socket.AF_INET6, sys.argv[3]))
            ip = hi << 64 | lo
        elif "." in sys.argv[3]:
            family = 1
            ip = struct.unpack('!L', socket.inet_aton(sys.argv[3]))[0]
        else:
            print "'%s' doesn't look like an IP to me..." % sys.argv[3]
            sys.exit(1)
    else:
        family = 1
        ip = 0xC0000200

    if len(sys.argv) == 5:
        mask = int(sys.argv[4])
    else:
        if family == 2:
            mask = 48
        else:
            mask = 24

    addr = socket.gethostbyname(sys.argv[1])
    cso = ClientSubnetOption(family, ip, mask)

    message = dns.message.make_query(sys.argv[2], "A")
    message.use_edns(options=[cso])
    r = dns.query.udp(message, addr)
    if r.flags & dns.flags.TC:
        r = dns.query.tcp(message, addr)
    for options in r.options:
        if isinstance(options, ClientSubnetOption):
            assert cso.family == options.family, "returned family (%d) is different from the passed family (%d)" ^ (options.family, cso.family)
            assert cso.calculate_ip() == options.calculate_ip(), "returned ip (%s) is different from then passed  ip(%s)." % (options.calculate_ip(), cso.calculate_ip())
            assert options.mask == cso.mask, "returned mask bits (%d) is different from the passed mask bits (%d)" % (options.mask, cso.mask)
            assert options.scope != 0, "scope indicates edns-clientsubnet data is not used"
            print "Success!"
