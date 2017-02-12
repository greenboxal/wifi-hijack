# wifi-hijack

Wifi DNS hijacker

Actually works on any network if you can MITM it.

# How it works

wifi-hijack sniffs a network device for DNS requests using libpcap. When a desired DNS query is sent by someone (except yourself), a fake response is written, hopefully before the actual DNS server responds. This causes the device that made the query believe that your response is the right one, hijacking the traffic to whatever IP you want.

# Usage

```
Usage: wifi-hijack CONFIG

Hijacks DNS requests on the given device.

Arguments:
  CONFIG        configuration file
Options:
  -h --help
```

# Config

```
# Device where to sniff DNS traffic
source_device: en0

# Device where to inject fake DNS responses
target_device: en7

# Target DNS queries
targets:
  - address: 10.0.0.8   # Address is the fake response
    matches:            # Matches are a list of regexes to match agains't the query
      - "google.com"
      - "*.google.com"
  - address: 10.0.0.7
    matches:
      - "*"
```

Targets are evaluated in order, consider this if building a complex configuration. (wait... wat u doin m8?)

# Disclaimer

I'm not responsible by anything that you do with this tool. It was created solely by the curiosity about the security flaws of open wifi networks.

*Don't be evil.*

# LICENSE

Copyright (c) 2017 Jonathan Lima <greenboxal@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

