"""
NotSoSmartConfig.py - Decode SmartConfig credentials from a PCAP file

in depth analysis of the protocol:
https://arxiv.org/pdf/1811.03241.pdf

The configurator broadcast the GuideCode as a preamble so the IoT device
can recognize the pattern.

preamble GuideCode:
   guides[0] = 515; 559; 44 bytes extra when encrypted
   guides[1] = 514; 558; 44
   guides[2] = 513; 557; 44
   guides[3] = 512; 556; 44 


Then the configurator starts broadcasting the DatumCode.
The DatumCode is made in groups of 3 bytes:
- The first byte contains the top 4 bits of the Information byte.
- The second byte contains a counter to detect the Datum order since 
   they are transmitted via UDP over 802.11
- The third byte contains the bottom 4 bits of the Information byte.

example of DatumCode:
  173|  321|  189|   46|  322|  225|  110|  323|  254|  254|  324|  145|

00 85 01 19 00 95|00 06 01 1a 00 b9|00 46 01 1b 00 d6|00 d6 01 1c 00 69|
   ^^          ^^    ^^          ^^    ^^          ^^                ^^|
                U                 i                 f                 i|

effective data sent
 = totalLen (1 byte) 
 + apPwdLen (1 byte)
 + SsidCRC  (1 byte)
 + BssidCRC (1 byte)
 + totalXOR (1 byte)
 + ipAddr   (4 bytes)
 + apPwd    (variable)
 + apSSID   (variable)
 + apBSSID  (6 bytes)

"""

import sys
from binascii import unhexlify as unhex, hexlify as hhex
from os.path import isfile
from scapy.all import *

class WifiCredentials(object):
    def __init__(self, ssid, pwd, bssid=None, ip=None, token_group=None):
        self.ssid = ssid
        self.pwd = pwd
        self.bssid = bssid
        self.ip = ip
        self.token_group = token_group
        if token_group is not None:
            self.region = token_group[:2]
            self.secret = token_group[2:]
    
    @staticmethod
    def pprint(credz):
        if type(credz) is not WifiCredentials:
            raise NotSmartException('[E] Failed pretty-printing an object with type not equals to "WifiCredentials"')
        print("SSID: {}".format(credz.ssid))
        print("Pwd: {}".format(credz.pwd))
        if credz.bssid is not None:
            print("BSSID: {}".format(credz.bssid))
        if credz.ip is not None:
            print("IP: {}".format(credz.ip))
        if credz.region is not None:
            print("Region: {}".format(credz.region))
        if credz.secret is not None:
            print("Secret: {}".format(credz.secret))

    def __str__(self):
        s = []
        s.append("ssid={}".format(self.ssid))
        s.append("pwd={}".format(self.pwd))
        if self.bssid is not None:
            s.append("bssid={}".format(self.bssid))
        if self.ip is not None:
            s.append("ip={}".format(self.ip))
        if self.token_group is not None:
            s.append("token_group={}".format(self.token_group))
        return "WifiCredentials({})".format(', '.join(s))
    
    def __repr__(self):
        return {'ssid':self.ssid, 'pwd':self.pwd, 'bssid':self.bssid, 'ip':self.ip, 'token_group':self.token_group}

class NotSmartException(Exception):
    pass

class GenericWLAN(object):
    preamble = [559, 558, 557, 556]
    clearlen = 44
    technique = "802.11 Multicast"
    mac_filter = '01:00:5e'  

    def __init__(self, pcap_file, debug=False):
        if not isfile(pcap_file):
            raise NotSmartException("[E] File not found: {}. Specify at least one file as argument.".format(pcap_file))
        try:
            self.pcap = rdpcap(pcap_file)
        except scapy.error.Scapy_Exception as e:
            raise NotSmartException("[E] {}".format(e))
        self.debug = debug

    def decode(self):
        # Parse PCAP file
        packets = self.parse_pcap()
        if len(packets) == 0:
            return None
        # Detect the GuideCode and extract the following DatumCode sequence
        datum = self.get_datum_sequence(packets)
        if len(datum) == 0:
            return None
        # Convert lenghts in DatumCodes to a DatumCode hexstring
        datumstr = self.parse_datum(datum)
        if len(datumstr) == 0:
            return None
        # Convert the DatumCode hexstring to cleartext UTF-8
        result = self.datum_to_cleartext(datumstr)
        if len(result) == 0:
            return None
        # Get all the juicy stuff
        return self.get_credentials(result)

    def packet_filter(self, packet):
        if Dot11 in packet and self.mac_filter in packet.addr1:
            # Encrypted 802.11 traffic to multicast MAC
            data = packet.data
            if data is None:
                return None
            # packet.addr1 is the destination address
            # packet.addr2 is the AP's BSSID address
            # packet.addr3 is the source address
            json = {}
            json['dest'] = packet.addr1
            json['len'] = len(data)
            return json

    def parse_pcap(self):
        filtered = []
        for packet in self.pcap:
            if self.debug: packet.show()
            pkt = self.packet_filter(packet)
            if pkt is not None:
                filtered.append(pkt)
        if len(filtered) == 0:
            raise NotSmartException(f"[E] No {self.technique} packet with destination MAC \"{self.mac_filter}\" found inside PCAP")
        return filtered
    
    def get_datum_sequence(self, packets):
        """
        NotSoSmart-StateMachine

        s -> 0; searching for preamble/GuideCode
        s -> 1; starting GuideCode found 515
        s -> 2; found 514
        s -> 3; found 513
        s -> 4; GuideCode ending found 512
        s -> 5; read DatumCode
        """
        s = 0
        datum = []
        for pack in packets:
            packetlen = pack['len']
            if s == 5 and (packetlen == self.preamble[0] or 
                           packetlen == self.preamble[1] or 
                           packetlen == self.preamble[2] or 
                           packetlen == self.preamble[3]):
                # finished reading some datum
                s = 1
            elif packetlen == self.preamble[0]:
                # found starting guide
                s = 1
            elif s == 1 and packetlen == self.preamble[1]:
                s = 2
            elif s == 2 and packetlen == self.preamble[2]:
                s = 3
            elif s == 3 and packetlen == self.preamble[3]:
                s = 4
            elif s == 4 and packetlen != self.preamble[0]:
                # found starting datum
                s = 5
                datum.append({'dest': pack['dest'], 'len': packetlen - self.clearlen})
            elif s == 5:
                datum.append({'dest': pack['dest'], 'len': packetlen - self.clearlen})
        return datum

    def reorder(self, datum):
        # Fix the packet order
        ordered_lengths = {}
        current = datum[0]['dest'][-2:]
        triplet = []
        for element in datum:
            if current == element['dest'][-2:]:
                triplet.append(element['len'])
            else:
                current = element['dest'][-2:]
                triplet = [element['len']]
            if len(triplet) == 3:
                if ordered_lengths.get(triplet[1]) is None:
                    ordered_lengths[triplet[1]] = []
                if len(ordered_lengths[triplet[1]]) != 3:
                    ordered_lengths[triplet[1]] = triplet
        return ordered_lengths
    
    def parse_datum(self, datum):
        datum = self.reorder(datum)
        k = sorted(datum.keys())
        hexstr = []
        for index in k:
            if self.debug: print(datum[index])
            hexstr.extend(self.lenght_to_datum(datum[index][0]))
            hexstr.extend(self.lenght_to_datum(datum[index][-1]))
        return hexstr

    def lenght_to_datum(self, dat):
        dat = dat - 40
        high = dat >> 8
        low = dat & 0x00ff
        return ['{:02x}'.format(high), '{:02x}'.format(low)]

    def bytes_to_ips(data, sequence):
        r = []
        if len(data) & 1:
            data.append(0)
        for i in range(0, len(data), 2):
            r.append( "226." + str(sequence) + "." + str(data[i+1]) + "." + str(data[i]) )
            sequence += 1
        return r

    def datum_to_cleartext(self, datum):
        clear = []
        for i in range(0, len(datum), 4):
            a = datum[i:i + 4]
            low = ord(unhex(a[-1]))
            high = ord(unhex(a[1]))
            clear.append(bytes([((high & 0xf) << 4) + (low & 0xf)]))
        return clear

    def get_credentials(self, result):
        pwd_len = int.from_bytes(result[1], 'big')
        ip = '.'.join([str(int.from_bytes(x, 'big')) for x in result[5:5+4]])
        pwd = b''.join(result[5+4:5+4+pwd_len])
        ssid = b''.join(result[5+4+pwd_len:-6])
        bssid = ':'.join([hhex(x).decode() for x in result[-6:]])
        return WifiCredentials(ssid, pwd, bssid, ip)

class GenericBroadcast(GenericWLAN):
    preamble = [515, 514, 513, 512]
    clearlen = 0
    technique = "UDP Broadcast"
    mac_filter = 'ff:ff:ff:ff:ff:ff'

    def packet_filter(self, packet):
        # TODO: Add check on DPORT
        if Ether in packet and UDP in packet and self.mac_filter in packet.dst:
            # Cleartext UDP traffic to multicast MAC
            data = packet.getlayer(Raw)
            if data is None:
                return None
            json = {}
            json['dest'] = packet.dst
            json['len'] = len(data)
            return json

class GenericMulticast(GenericBroadcast):
    preamble = [515, 514, 513, 512]
    clearlen = 0
    technique = "UDP Multicast"
    mac_filter = '01:00:5e'
    
class TuyaBroadcast(GenericBroadcast):
    preamble = [1, 3, 6, 10]
    clearlen = 0
    technique = "UDP Broadcast"
    mac_filter = 'ff:ff:ff:ff:ff:ff'

    def parse_datum(self, datum):
        hexstr = []
        for pkg in datum:
            if self.debug: print(pkg['len'])
            hexstr.append(pkg['len'])
        return hexstr

    def datum_to_cleartext(self, datum):
        clear = []
        # first 2 bytes are the length
        length = ((datum[0] & 0xf) << 4) + (datum[1] & 0xf)
        # second 2 bytes are the crc of the length
        length_crc = ((datum[2] & 0xf) << 4) + (datum[3] & 0xf)
        datum = datum[4:]

        # calculate the real length since the data is packed like this: [crc, sequence, byte1, byte2, byte3, byte3] + padding
        ll = int(length*3/2)
        for i in range(0, ll, 6):
            group_crc = datum[i]
            # TODO: Check CRC
            sequence = datum[i+1]
            a = datum[i+2:i+6]
            clear.extend(bytes([c & 0xFF for c in a]))
        return clear

    def get_credentials(self, result):
        result = bytes(result).rstrip(b'\x00')
        # data is packed as following:
        # pwd_len + pwd + token_group_len + token_group + ssid
        pwd_len = result[0]
        pwd = result[1:pwd_len+1].decode()
        token_group_len = result[pwd_len+1]
        token_group = result[pwd_len+2:pwd_len+2+token_group_len].decode()
        ssid = result[pwd_len+2+token_group_len:].decode()
        return WifiCredentials(ssid, pwd, token_group=token_group)

class TuyaMulticast(GenericMulticast):
    preamble = GenericMulticast.bytes_to_ips([ ord(c) for c in "TYST01" ], 120)
    clearlen = 0
    technique = "UDP Multicast"
    mac_filter = '01:00:5e'

    def packet_filter(self, packet):
        # TODO: Add check on DPORT
        if Ether in packet and UDP in packet and self.mac_filter in packet.dst:
            # Cleartext UDP traffic to multicast MAC
            data = packet.getlayer(Raw)
            if data is None:
                return None
            json = {}
            json['dest'] = packet.getlayer(IP).dst
            return json

    def get_datum_sequence(self, packets):
        """
        TuyaMulticast-StateMachine

        s -> 0; searching for preamble/GuideCode
        s -> 1; starting GuideCode found
        s -> 3; GuideCode ending found
        s -> 4; read DatumCode
        """
        s = 0
        datum = []
        for pack in packets:
            packetlen = pack['dest']
            if s == len(self.preamble)+1 and packetlen in self.preamble:
                # finished reading some datum
                s = 1
            elif packetlen == self.preamble[0]:
                # found starting guide
                s = 1
            elif packetlen == self.preamble[s%len(self.preamble)]:
                s = s+1
            elif s == len(self.preamble) and packetlen != self.preamble[0]:
                # found starting datum
                s = s+1
                datum.append({'dest': pack['dest']})
            elif s == len(self.preamble)+1:
                datum.append({'dest': pack['dest']})
        return datum

    def parse_datum(self, datum):
        hexstr = []
        d = {}
        for pkg in datum:
            if self.debug: print(pkg)
            data = pkg['dest'].split('.')
            d[int(data[1])] = chr(int(data[3])) + chr(int(data[2]))
        
        hexstr.append(filter(lambda x: x is not None, [d.get(i) for i in range(0,32)]))
        hexstr.append(filter(lambda x: x is not None, [d.get(i) for i in range(32,64)]))
        hexstr.append(filter(lambda x: x is not None, [d.get(i) for i in range(64,256)]))
        return hexstr

    def datum_to_cleartext(self, datum):
        cleardatum = []
        cleardatum.append(''.join(datum[0]))
        cleardatum.append(''.join(datum[1]))
        cleardatum.append(''.join(datum[2]))
        return cleardatum

    def get_credentials(self, result):
        # data is packed as following:
        # len + len + crc_32 + data
        if result[0][0] != result[0][1] or result[1][0] != result[1][1] or result[2][0] != result[2][1]:
            return None
        pwd_len = ord(result[0][0])
        pwd = result[0][6:pwd_len+6]
        token_group_len = ord(result[1][0])
        token_group = result[1][6:token_group_len+6]
        ssid_len = ord(result[2][0])
        ssid = result[2][6:ssid_len+6]
        return WifiCredentials(ssid, pwd, token_group=token_group)

class NotSmart(object):
    def __init__(self, pcap_file, debug=False):
        if not isfile(pcap_file):
            raise NotSmartException("[E] File not found: {}. Specify at least one file as argument.".format(pcap_file))
        self.pcap_file = pcap_file
        self.debug = debug
        
    def decode(self):
        for cls in [TuyaMulticast, TuyaBroadcast, GenericMulticast, GenericBroadcast, GenericWLAN]:
            try:
                strategy = cls(self.pcap_file, self.debug)
                if self.debug: print(f"[+] Trying strategy: {type(strategy).__name__}")
                credentials = strategy.decode()
                if credentials is not None:
                    return credentials
            except NotSmartException as e:
                if self.debug: print(f"[{type(strategy).__name__}] - {e}")
                pass
        return None

if __name__ == "__main__":
    print("NotSoSmartConfig! - SmartConfig credentials decoder")
    if len(sys.argv) < 2:
        print("No file supplied")
        exit(1)
    pcap_file = sys.argv[1]
    ns = NotSmart(pcap_file)
    credz = ns.decode()
    if credz is not None:
        print("[!] Found WiFi credentials in Pcap!")
        WifiCredentials.pprint(credz)
    else:
        print("[!] No WiFi credentials found in Pcap :(")

