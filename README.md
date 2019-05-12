# QUICk

a go library based on [gopacket](https://github.com/google/gopacket) for analyzing QUIC ClientHello (CHLO) messages.

### What is QUIC?

- [QUIC: A UDP-Based Multiplexed and Secure Transport](https://tools.ietf.org/html/draft-ietf-quic-transport-20)
- [HTTP/3 explained](https://http3-explained.haxx.se/en/)

## Usage

There is a simple QUIC sniffer in [example](example/) directory. An improved version will be added to the repo soon.

```$xslt
cd example/
go build quick_sniffer.go
./quick_sniffer -i en0
```

### Example Output

```$xslt
2019/05/11 05:42:10 192.168.1.9:58556 -> 172.217.25.174:443(https) [QUIC]  SNI: www.youtube.com
Public Flags: d
CID: e4fca1c8ad38dc14
Version: Q043
Packet Number: 3
Message Authentication Hash: 0db44cd94bb3ad0afd57126e
Frame Type: a0
Stream ID: 1
Data Length: 1024
Tag: CHLO
Tag Number: 25
SNI: "www.youtube.com"
UAID: "Chrome/74.0.3729.131 Intel Mac OS X 10_14_4"
Tags in Order: ["PAD" "SNI" "STK" "VER" "CCS" "NONC" "AEAD" "UAID" "SCID" "TCID" "PDMD" "SMHL" "ICSL" "NONP" "PUBS" "MIDS" "SCLS" "KEXS" "XLCT" "CSCT" "COPT" "CCRT" "IRTT" "CFCW" "SFCW"]
Tag Values: map[AEAD:AESG CCRT:2237aaad1bebaa6c67f8adc58015e3ff CCS:01e8816092921ae87eed8086a2158291 CFCW:0000f000 COPT:NSTP CSCT: ICSL:1e000000 IRTT:40440000 KEXS:C255 MIDS:64000000 NONC:5cd5d4123030303030303030e9c59effcecd21da531a5084a5333242335e8494 NONP:7d6f3ecd3b19182dc50916bbf73520fb7b8e679003806739f3aaba383fcac3bd PDMD:X509 PUBS:e8b53d02466ad7ee37c92c5c55144a7b399d5689e50683a4e7542da36ed36912 SCID:8fffefdd83ec8a46169e93b0e332dd4b SCLS:01000000 SFCW:00006000 SMHL:01000000 SNI:www.youtube.com STK:a31c12b6480c17f4b87695dacd6ce7c359509e6b40a1d2b353fe72ebb06e19f6725c557e6e1dc66e714f97b4e5a596dda9994578393c TCID:00000000 UAID:Chrome/74.0.3729.131 Intel Mac OS X 10_14_4 VER:Q043 XLCT:2237aaad1bebaa6c]


2019/05/11 05:42:12 192.168.1.9:58053 -> 216.58.200.99:443(https) [QUIC]  SNI: fonts.gstatic.com
Public Flags: d
CID: 17f255ae6f55b260
Version: Q043
Packet Number: 1
Message Authentication Hash: 4247258b9146098152ff3d82
Frame Type: a0
Stream ID: 1
Data Length: 1024
Tag: CHLO
Tag Number: 25
SNI: "fonts.gstatic.com"
UAID: "Chrome/74.0.3729.131 Intel Mac OS X 10_14_4"
Tags in Order: ["PAD" "SNI" "STK" "VER" "CCS" "NONC" "AEAD" "UAID" "SCID" "TCID" "PDMD" "SMHL" "ICSL" "NONP" "PUBS" "MIDS" "SCLS" "KEXS" "XLCT" "CSCT" "COPT" "CCRT" "IRTT" "CFCW" "SFCW"]
Tag Values: map[AEAD:AESG CCRT:2237aaad1bebaa6c67f8adc58015e3ff CCS:01e8816092921ae87eed8086a2158291 CFCW:0000f000 COPT:NSTP CSCT: ICSL:1e000000 IRTT:c2840000 KEXS:C255 MIDS:64000000 NONC:5cd5d41430303030303030307921451c2d12865a234c05726f7dc38069a9741c NONP:5eceff43869fbe6b291c0e5852927dcb5d3df75e21d32d21b4a2dc61e09ae46d PDMD:X509 PUBS:c4c035f104b45a5f7cc585220e41633f44afe4cf2c47ad4835381dee5933b040 SCID:8fffefdd83ec8a46169e93b0e332dd4b SCLS:01000000 SFCW:00006000 SMHL:01000000 SNI:fonts.gstatic.com STK:1ab50b5e10de678cd5f48357c84cfb6510178fd0a62744dda0532e9dcb5f0b199024316d44d7443b704b191e3339561b90ea4d1a471a TCID:00000000 UAID:Chrome/74.0.3729.131 Intel Mac OS X 10_14_4 VER:Q043 XLCT:2237aaad1bebaa6c]
```

## TODO

- [ ] QUICk sniffer v1.0
- [ ] QUIC Layer for gopacket
- [ ] Add the analysis and collected data to the repo
- [ ] Release QUICpot

