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

# LICENSE

MIT.

