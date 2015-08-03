# ClientSubnetOption

Class to add [draft-vandergaast-edns-client-subnet-01](http://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-01) support to [dnspython](http://www.dnspython.org).

## Installation

`pip install clientsubnetoption`

## Requirements

* [python](http://www.python.org) 2.7 or later
* [dnspython](http://www.dnspython.org) 1.10.0 or later

**Note**: If you are installing dnspython on Python3, use `pip install dnspython3`

## Example

This example is designed to work with Python2 or Python3.

```python
from __future__ import print_function
import socket
import dns
import dns.message
import dns.query
from clientsubnetoption import ClientSubnetOption

cso = ClientSubnetOption.FromIPString('192.168.1.1', mask=27)
message = dns.message.make_query('www.google.com', 'A')
message.use_edns(options=[cso])
result = dns.query.udp(message, socket.gethostbyname('ns1.google.com'), timeout=5)
for option in result.options:
    if isinstance(option, ClientSubnetOption):
        print(option)
```

## Changelog

### 3.0.0 [unreleased]
 * Rewritten in an object-oriented fashioned

### 2.1.0
 * Correctly set scope in `to_wire` (@rgacogne)
 * CLI Improvements:
   * Option to set Recursion Desired flag on the message
   * Won't fail completely on nameserver timeout

### 2.0.0
 * Python 3 compatible (tested with 3.4.3 & 2.7.10)
 * Can be installed via pip: `pip install clientsubnetoption`
 * Family is now auto-detected
 * IPs must be given as strings (versus their unpacked form)
  * `ClientSubnetOption('192.168.1.1')` vs `ClientSubnetOption(struct.unpack('!L', socket.inet_aton('192.168.1.1'))[0])`
