# NotSoSmartConfig

This tool allows to extract WiFi credentials sent Over-The-Air during the configuration of an IoT device using the SmartConfig / ESPTouch protocol.

More info about the security analysis of the SmartConfig protocol can be found in the ["NotSoSmartConfig: broadcasting WiFi credentials Over-The-Air"](https://www.shielder.it/blog/notsosmartconfig:-broadcasting-wifi-credentials-over-the-air/) article on Shielder's blog.

## Usage

`python3 NotSoSmartConfig.py ./<wifi_traffic_file>.pcap`

<img src="https://www.shielder.it/blog/wp-content/uploads/2020/04/SmartConfig.gif" width="600" />
