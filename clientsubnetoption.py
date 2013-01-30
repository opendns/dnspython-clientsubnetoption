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

""" Class to implement draft-vandergaast-edns-client-subnet-01.

The contained class supports both IPv4 and IPv6 family and addresses.
Requirements:
  dnspython (http://www.dnspython.org/)
"""

import struct
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
        """Calculates the relevant ip address based on the network mask.

        Calculates the relevant bits of the IP address based on network mask.
        Sizes up to the nearest octet for use with wire format.

        Returns:
            An integer of only the significant bits sized up to the nearest
            octect.
        """

        if self.family == 1:
            bits = 32
        elif self.family == 2:
            bits = 128

        ip = self.ip >> bits - self.mask

        if (self.mask % 8 != 0):
            ip = ip << 8 - (self.mask % 8)

        return ip

    def to_wire(self, file):
        """Create EDNS packet as definied in draft-vandergaast-edns-client-subnet-01."""

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
        """Read EDNS packet as defined in draft-vandergaast-edns-client-subnet-01.

        Returns:
            An instance of ClientSubnetOption based on the ENDS packet
        """

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
        if self.calculate_ip() != other.calculate_ip():
            return False
        if self.mask != other.mask:
            return False
        if self.family != other.family:
            return False
        return True

    def __ne__(self, other):
        """Rich comparison method for inequality.

        See notes for __eq__()

        Returns:
            boolean
        """
        return not self.__eq__(other)


dns.edns._type_to_class[0x50fa] = ClientSubnetOption

if __name__ == "__main__":
    import argparse
    import socket

    def valid_ip(string):
        if ":" in string:
            try:
                hi, lo = struct.unpack('!QQ', socket.inet_pton(socket.AF_INET6, string))
                return {'family': 2, 'ip': hi << 64 | lo}
            except:
                pass
        elif "." in string:
            try:
                ip = struct.unpack('!L', socket.inet_aton(string))[0]
                return {'family': 1, 'ip': ip}
            except:
                pass
        raise argparse.ArgumentTypeError("'%s' doesn't look like an IP to me..." % string)

    parser = argparse.ArgumentParser(description='draft-vandergaast-edns-client-subnet-01 tester')
    parser.add_argument('nameserver', help='The nameserver to test')
    parser.add_argument('rr', help='DNS record that should return an EDNS enabled response')
    parser.add_argument('-s', '--subnet', type=valid_ip, help='Specifies an IP to pass as the client subnet.', default={'family': 1, 'ip': 0xC0000200})
    parser.add_argument('-m', '--mask', type=int, help='CIDR mask to use for subnet')
    parser.add_argument('--timeout', type=int, help='Set the timeout for query to TIMEOUT seconds, default=10', default=10)
    parser.add_argument('-t', '--type', help='DNS query type, default=A', default='A')
    args = parser.parse_args()

    if not args.mask:
        if args.subnet['family'] == 2:
            args.mask = 48
        else:
            args.mask = 24

    try:
        addr = socket.gethostbyname(args.nameserver)
    except socket.gaierror:
        parser.exit(1, "Unable to resolve %s\n" % args.nameserver)
    cso = ClientSubnetOption(args.subnet['family'], args.subnet['ip'], args.mask)

    message = dns.message.make_query(args.rr, args.type)
    message.use_edns(options=[cso])
    try:
        r = dns.query.udp(message, addr, timeout=args.timeout)
        if r.flags & dns.flags.TC:
            r = dns.query.tcp(message, addr, timeout=args.timeout)
    except dns.exception.Timeout:
        parser.exit(3, "Timeout: No answer received from %s\n" % args.nameserver)

    for options in r.options:
        if isinstance(options, ClientSubnetOption):
            if not cso.family == options.family:
                parser.exit(3, "Failed: returned family (%d) is different from the passed family (%d)\n" % (options.family, cso.family))
            if not cso.calculate_ip() == options.calculate_ip():
                parser.exit(3, "Failed: returned ip (%s) is different from then passed  ip(%s).\n" % (options.calculate_ip(), cso.calculate_ip()))
            if not options.mask == cso.mask:
                parser.exit(3, "Failed: returned mask bits (%d) is different from the passed mask bits (%d)\n" % (options.mask, cso.mask))
            if not options.scope != 0:
                parser.exit(4, "Warning: scope indicates edns-clientsubnet data is not used\n")
            parser.exit(message="Success!\n")

    parser.exit(3, "Failed: No ClientSubnetOption returned\n")
