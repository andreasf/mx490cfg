#!/usr/bin/env python
"""
Wifi configuration tool for Canon MX490 series printers.

Canon only provides configuration software for Windows and Mac OS, this should
work on any system with libusb support. Use at your own risk. I mostly don't
know what I'm sending to the printer -- more or less I'm replaying messages
recorded with Wireshark.

Copyright (c) 2015 Andreas Fleig
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import argparse
import usb.core
import usb.util
import struct
import sys

bh = bytearray.fromhex
# control transfer messages
C1 = bh("7a00000000000000")
C2 = bh("7800000000000000")
C3 = bh("7900000000000000")
C4 = bh("7b00000000000000")

# printer commands sent via bulk transfers
CMD_GET_CONFIG = bh("1003")
CMD_SET_CONFIG = bh("1004")
CMD_INIT_1 = bh("1ffe")
CMD_INIT_2 = bh("1b10")
CMD_LEAVE_1 = bh("1BFF")
CMD_LEAVE_2 = bh("1fff")

# config template. this is just a subset of settings. the whole configuration
# is returned in response to CMD_GET_CONFIG.
PACKET = ("<param_set><ID><![CDATA[wireless0]]></ID><802.11>"
          "<ssid><![CDATA[%(ssid)s]]></ssid>"
          "<wpa2on>%(wpa2)s</wpa2on>"
          "<wpa_encrypt>%(encryption)s</wpa_encrypt>"
          "<wpa2_encrypt>%(encryption)s</wpa2_encrypt>"
          "<wpa_psk>%(psk)s</wpa_psk>"
          "<mixon>1</mixon>"
          "<bssid>FFFFFFFFFFFF</bssid></802.11></param_set>")

# list of (vendor id, product id)
VALID_DEVICES = ((0x04a9, 0x1787),)

TIMEOUT = 10000
MAX_RESPONSE = 4096


def main():
    parser = argparse.ArgumentParser(description="Canon PIXMA MX490 series configuration tool",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("SSID", help="SSID to connect to")
    parser.add_argument("password", help="Password")
    parser.add_argument("--wpa1", action="store_const", const=True,
                        default=False, help="Use WPA1 instead of WPA2")
    parser.add_argument("--encryption", default="CCMP", choices=("CCMP", "TKIP"),
                        help="WPA cipher")
    parser.add_argument("--debug", action="store_const", const=True, default=False,
                        help="Print packages")
    args = parser.parse_args()
    set_config(args)


def set_config(args):
    """
    Finds the USB device and tries to submit the configuration.
    """
    dev = find_device()
    if dev is None:
        panic("Error: no known printer found. If your printer is connected, "
              "try adding it to VALID_DEVICES.")

    detach_kernel(dev)
    try:
        dev.set_configuration()
        cfg = dev.get_active_configuration()
        eps = find_endpoints(cfg)
        if not eps:
            panic("Error: unable to find printer endpoint")
        # the second printer endpoint is the fax
        out_ep, in_ep = eps[0]

        # enter configuration mode
        dev.ctrl_transfer(bmRequestType=0x41, bRequest=0x7a,
                          data_or_wLength=C1, wIndex=256)
        send_request(out_ep, in_ep,
                     make_packet(CMD_INIT_1, struct.pack(">I", 1)),
                     debug=args.debug)
        dev.ctrl_transfer(bmRequestType=0x41, bRequest=0x78,
                          data_or_wLength=C2, wIndex=256)
        send_request(out_ep, in_ep,
                     make_packet(CMD_INIT_2, struct.pack(">2I", 0x800000, 0x1000000)),
                     debug=args.debug)

        # this request is optional, it just retrieves the current
        # configuration. a fancier version of this tool would parse and
        # display the config.
        send_request(out_ep, in_ep,
                     make_packet(CMD_GET_CONFIG, struct.pack(">I", 0)),
                     debug=args.debug)

        # set configuration
        wifi_config = format_wifi_config(args)
        send_request(out_ep, in_ep,
                     make_packet(CMD_SET_CONFIG, wifi_config),
                     debug=args.debug)

        # leave configuration mode
        send_request(out_ep, in_ep,
                     make_packet(CMD_LEAVE_1, ""),
                     debug=args.debug)
        dev.ctrl_transfer(bmRequestType=0x41, bRequest=0x79,
                          data_or_wLength=C3, wIndex=256)
        send_request(out_ep, in_ep,
                     make_packet(CMD_LEAVE_2, struct.pack(">I", 1)),
                     debug=args.debug)
        dev.ctrl_transfer(bmRequestType=0x41, bRequest=0x7b,
                          data_or_wLength=C4, wIndex=256)
    finally:
        dev.reset()


def find_device():
    for vendor_id, product_id in VALID_DEVICES:
        dev = usb.core.find(idVendor=vendor_id, idProduct=product_id)
        if dev is not None:
            return dev
    return None


def detach_kernel(device):
    for cfg in device:
        for intf in cfg:
            if device.is_kernel_driver_active(intf.bInterfaceNumber):
                try:
                    device.detach_kernel_driver(intf.bInterfaceNumber)
                except usb.core.USBError:
                    panic("Error: could not detach device from kernel")


def find_endpoints(cfg):
    """
    Returns the first OUT endpoint in the first printer interface
    """
    eps = []
    for interface in cfg:
        if interface.bInterfaceClass == 7:  # printer
            out_ep = None
            in_ep = None
            for ep in interface:
                d = usb.util.endpoint_direction(ep.bEndpointAddress)
                if d == usb.util.ENDPOINT_OUT:
                    out_ep = ep
                    break
            for ep in interface:
                d = usb.util.endpoint_direction(ep.bEndpointAddress)
                if d == usb.util.ENDPOINT_IN:
                    in_ep = ep
                    break
            if out_ep and in_ep:
                eps.append((out_ep, in_ep))
    return eps


def send_request(out_ep, in_ep, req, debug=False):
    """
    Sends req to the OUT endpoint, then reads a response from the IN endpoint.
    """
    if debug:
        print_packet("> ", req)
    out_ep.write(req)
    resp = in_ep.read(MAX_RESPONSE, timeout=TIMEOUT)
    if debug:
        print_packet("< ", resp.tostring())
    return resp


def print_packet(prefix, packet):
    per_line = 79 - len(prefix)
    for i in range(0, len(packet), per_line):
        print prefix + packet[i:i + per_line]
    print ""


def make_packet(cmd, payload):
    """
    Adds command header, length field and padding
    """
    pad_len = (4 - (len(payload) % 4)) % 4
    padded = payload + pad_len * "\x00"
    divlen = len(padded) / 4
    header = cmd + struct.pack(">H", divlen)
    return header + padded


def format_wifi_config(args):
    return PACKET % {
        "ssid": encode_str(args.SSID),
        "psk": encode_str(args.password),
        "encryption": args.encryption,
        "wpa2": int(not args.wpa1),
    }


def encode_str(text):
    char_codes = []
    for char in text:
        char_codes.append("%x" % ord(char))
    return "".join(char_codes)


def panic(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()
    sys.exit(1)


if __name__ == "__main__":
    main()
