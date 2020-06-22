# arpspoof
This repo extracts the [arpspoof](https://manpages.debian.org/stretch/dsniff/arpspoof.8.en.html) from the [dsniff](https://tracker.debian.org/pkg/dsniff) toolkit and lets it run on *macOS*

## Installing

```shell
curl -LJO https://github.com/YeautyYE/arpspoof/releases/download/2.4b1%2Bdebian-29/arpspoof && chmod a+x arpspoof && mv arpspoof /usr/local/bin/
```

## Compiling

```shell
brew install cmake
brew install pkg-config
brew install libnet
brew install libpcap
ln -s /usr/local/opt/libpcap/lib/pkgconfig/libpcap.pc /usr/local/lib/pkgconfig/libpcap.pc
git clone https://github.com/YeautyYE/arpspoof.git
cd arpspoof
cmake . && make && make install
arpspoof
```

## synopsis

`arpspoof [-i interface] [-c own|host|both] [-t target] [-r] host`

```
-i interface
	Specify the interface to use.
	
-c own|host|both
	Specify which hardware address t use when restoring the arp configuration; while cleaning up, packets can be send with the own address as well as with the address of the host. Sending packets with a fake hw address can disrupt connectivity with certain switch/ap/bridge configurations, however it works more reliably than using the own address, which is the default way arpspoof cleans up afterwards.
	
-t target
	Specify a particular host to ARP poison (if not specified, all hosts on the LAN). Repeat to specify multiple hosts.
	
-r
	Poison both hosts (host and target) to capture traffic in both directions. (only valid in conjuntion with -t)
	
host
	Specify the host you wish to intercept packets for (usually the local gateway).
```



