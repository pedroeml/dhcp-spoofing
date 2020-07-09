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
