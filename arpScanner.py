import scapy.all as scapy
import argparse
from colorama import Fore


class ArpScanner:
    def __init__(self, iface="eth0", ips="192.168.1.0/24", ethDst="ff:ff:ff:ff:ff:ff"):
        self.__ether = scapy.Ether(dst=ethDst)
        self.__arp = scapy.ARP(pdst=ips)
        self.__packet = self.__ether/self.__arp
        self.__devicesNum = 0
        self.__iface = iface
        self.__gateway = scapy.conf.route.route("0.0.0.0")[2]

    def __str__(self):
        msg = Fore.GREEN + \
            f"At least {Fore.MAGENTA}{self.__devicesNum}{Fore.GREEN} devices are connected to this interface\n"
        msg += "_" * (len(msg)) + '\n' + Fore.BLUE

        for answer in self.__answers:
            msg += f"\n{answer.src} -> {answer.psrc}" \
                + f"{Fore.RED+'  (Your device)'+Fore.BLUE if self.__ether.src==answer.hwsrc else ''}"

        return msg

    def scan(self, **kwargs):
        self.__answers = self.__noGateway(self.__arpReq(**kwargs))
        self.__devicesNum = len(self.__answers)
        return self

    def __noGateway(self, req):   # return except gateway
        return list(filter(lambda pck: self.__gateway != pck.psrc, req))

    def __arpReq(self, **kwargs):
        packets = scapy.srp(self.__packet, iface=self.__iface, **kwargs)[0]
        return list(response[1] for response in packets)

    @property
    def numberOfDevices(self):
        return self.__devicesNum


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="ArpScanner",
                                     description="Scan your network with arp packets,\
                                         the results may be vary depending on timeouts.")
    parser.add_argument('--ipdst', default="192.168.1.0/24",
                        help="Target IP addresses (usage: ipv4/subnet)")
    parser.add_argument('--ethDst', default="ff:ff:ff:ff:ff:ff",
                        help="Target MAC address (default: broadcast)")
    parser.add_argument('--iface', '-i', default="Wi-Fi",
                        help="interface to be scanned, default=Wi-Fi")
    parser.add_argument('--timeout', '-t', type=int, default=5,
                        help="timeout for scanning, default=5")
    parser.add_argument('--verbose', '-v', action="store_true", default=False)
    args = parser.parse_args()

    clients = ArpScanner(iface=args.iface, ips=args.ipdst)
    clients.scan(verbose=args.verbose, timeout=args.timeout)
    print(clients)
