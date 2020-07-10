# dhcp-spoofing
DHCP Spoofing

## System requirements

- [VirtualBox](https://www.virtualbox.org/)
- [Vagrant](https://www.vagrantup.com/)

## Setup

Build the `corevm` virtual machine by:

```bash
$ vagrant up
...
```

It's gonna take few minutes if you're running it for the first time. When it's done, just check the virtual machine status by:

```bash
$ vagrant status
...
corevm                    running (virtualbox)
...
```

## Launching

If `corevm` virtual machine isn't running, just follow the steps on the [Setup section](#setup). Otherwise, just ssh to it.

```bash
$ vagrant ssh
vagrant@corevm:~$
```

### Installing DHCP and DNS related dependencies

```bash
vagrant@corevm:~$ sudo su -
vagrant@corevm:~# apt install -y isc-dhcp-server bind9
vagrant@corevm:~# unlink /etc/resolv.conf
vagrant@corevm:~# systemctl disable systemd-resolved
vagrant@corevm:~# service systemd-resolved stop
vagrant@corevm:~# apt-get -y install resolvconf
vagrant@corevm:~# chmod +x /etc/dhcp/dhclient-enter-hooks.d/resolvconf
vagrant@corevm:~# mkdir /etc/dhcp/dhclient-enter-hooks.d/old
vagrant@corevm:~# mv /etc/dhcp/dhclient-enter-hooks.d/resolved /etc/dhcp/dhclient-enter-hooks.d/old/
vagrant@corevm:~# exit
```

### Opening the core application.

```bash
vagrant@corevm:~$ sudo /etc/init.d/core-daemon start
starting core-daemon
vagrant@corevm:~$ core-gui
Connecting to "core-daemon" (127.0.0.1:4038)...connected.
```

## Exiting

If you're running `core-gui`, then your terminal window should be looking like this:

```bash
vagrant@corevm:~$ core-gui
Connecting to "core-daemon" (127.0.0.1:4038)...connected.
```

On `core-gui` window click on File and then click on Quit. On the terminal window, it should display the connection to the core-daemon is closed. Now you should be able to run `exit` inside `corevm` and then halt the virtual machine.

```bash
Connection to "core-daemon" (127.0.0.1:4038) closed.
vagrant@corevm:~$ exit
$ vagrant halt
```

To be sure if `corevm` virtual machine is down just check its status by:

```bash
$ vagrant status
...
corevm                    poweroff (virtualbox)
...
```

## Loading topology

On `core-gui` window click on File, then click on Open and then navigate to `/vagrant` directory and select `topology.imn`/`topology.xml` file.

## Topology

There is only one network on this topology. There are two DHCP client machines (`n1` and `n5`). The `n2` machine (10.0.0.10/24) is an authentic DHCP/DNS server with a 64 Kbps link and 800 ms latency. The `n4` machine (10.0.0.20/24) is a fake DHCP/DNS server which can be used to direct traffic from other DHCP client machines through it instead of the authentic DHCP/DNS server.

## Simulation

Start the simulation on Core and open a bash window on `n4` machine (10.0.0.20/24) and let's the run the `dhcp.py` script as follows:

```bash
$ cd /vagrant
$ python3 dhcp.py
```

Probably at this point, since `n2` was the only active DHCP/DNS server before running the `dhcp.py` script, all DHCP client machines (`n1` and `n5`) already have an IP address. Open a bash window for both hosts, and let's refresh the DHCP configuration on the DHCP client machines (`n1` and `n5`) by running the following:

```bash
$ dhclient -r -v && dhclient -v eth0
```

Despite the slow link connected to the authentic DHCP server, there's a chance of it replying before the fake DHCP server. You can check the IP address assigned to the DHCP client by running:

```bash
$ ip addr
```

If it displays an IP address greater than 10.0.0.126, the authentic DHCP server replied first. Just refresh the DHCP configuration again and probably the assigned IP address will be within the fake DHCP server's IP addresses pool range (10.0.0.100 - 10.0.0.126). Another way for checking if the DHCP client machine is connected to the fake DHCP server is by running the ping command to `www.google.com` or `www.teste.com`.

```bash
$ ping www.google.com
```

If the latency is 800 ms or greater, the DHCP client machine is using the authentic DHCP server instead of the fake one.

## Implementation

The `dhcp.py` Python scrip sniffs all packets coming through `eth0` network interface of the host it's running and filters for further processing only IP packets matching the following requirements:

- Its protocol must be only UDP.
- Its UDP source and target ports must be 68 and 67 respectively.
- On the data area of the UDP header it must contain a valid DHCP protocol type code
  - DHCP Release: 7
  - DHCP Discover: 1
  - DHCP Offer: 2
  - DHCP Request: 3
  - DHCP Ack: 5

After this filtering, the script sends back a DHCP Discover packet, if it sniffs a DHCP Discover, offering an IP address available in the IP addresses pool. If it sniffs a DHCP Request packet, it sends back a DHCP Ack packet acknowledging the requested IP address.

## Limitations

The current implementation is scalable as long there are free IP addresses in the fake DHCP server IP addresses pool. There are some hardcoded IP and MAC addresses on `dhcp.py` script which would need to be changed if you intend to use it on another host.

### UDP

You may happen to notice an ICMP destination unreachable packet due an unhandled behavior where there's no UDP open port. It occurs only when the DHCP client IP address needs to be renewed and sends a DHCP Request to the fake DHCP server. However, it won't cause any issues between the DHCP client and fake DHCP server UDP communication though. A DHCP Ack will be sent back to the DHCP client as expected.
