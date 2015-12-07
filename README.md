mx490cfg
========

A Wifi configuration tool for Canon PIXMA MX490 series printers

Requirements
------------

libusb, Python, PyUSB

Usage
-----

Connect your printer via USB, then run the tool to set Wifi options:

```
$ python mx490cfg.py  --help
usage: mx490cfg.py [-h] [--wpa1] [--encryption {CCMP,TKIP}] [--debug]
                   SSID password

Canon PIXMA MX490 series configuration tool

positional arguments:
  SSID                  SSID to connect to
  password              Password

optional arguments:
  -h, --help            show this help message and exit
  --wpa1                Use WPA1 instead of WPA2 (default: False)
  --encryption {CCMP,TKIP}
                        WPA cipher (default: CCMP)
  --debug               Print packets (default: False)


$ python mx490cfg.py "My SSID" "Secret Passw0rd"
```

The printer reports the complete list of settings available via USB in reponse to `CMD_GET_CONFIG`. If you run the tool with `--debug`, you'll see the raw packet.
