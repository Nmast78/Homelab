# Nick's Homelab
What is a homelab?

A homelab is a laboratory at home where you can self-host, experiment with new technologies, develop your skills, and lots else. 

## Overview
This is the repository I developed during summer 2025. The homelab consists of the following hardware:
1. Raspberry Pi 4B
2. Raspberry Pi 3B
3. Levono ThinkPad T560
4. TPLink TL-SF1005P Unmanaged Switch

As you can see, it does not consist of much hardware😂. However, you might be suprised how much you can do and learn on such limited hardware.

![Homelab Image](./Nicks_Physical_Homelab_Picture.png)

## Diagram

Below is the diagram of my homelab, as well as some of the programs and containers that are running on each device.

![Homelab Diagram](./Nicks_Homelab.png)

## Tech Stack
| Logo | Name  | Description |
| :-----: | :---: | :---: |
| <img src="https://github.com/devicons/devicon/blob/master/icons/ansible/ansible-original.svg" title="Ansible" alt="Ansible" width="40" height="40"/>&nbsp; | Ansible  | Automate OS Updates |
| <img src="./Images/NetworkManager.png" title="NetworkManager" alt="NetworkManager" width="40" height="40"/>&nbsp; | NetworkManager | Network Configuration of Head Node and Compute Nodes |
| <img src="./Images/iptables.jpg" title="IPTables" alt="IPTables" width="40" height="40"/>&nbsp; | IPTables | Firewall Rules for Head Node Traffic |
| <img src="./Images/wireguard.png" title="WireGuard" alt="WireGuard" width="40" height="40"/>&nbsp; | WireGuard | Remote Access to Homelab |
| <img src="./Images/snortlogo.png" title="Snort" alt="Snort" width="40" height="40"/>&nbsp; | Snort | Intrusion Detection for Head Node |
| <img src="https://github.com/devicons/devicon/blob/master/icons/docker/docker-original.svg" title="Docker" alt="Docker" width="40" height="40"/>&nbsp; | Docker | Containerization for all Devices |
| <img src="./Images/netalertx.png" title="NetAlertX" alt="NetAlertX" width="40" height="40"/>&nbsp; | NetAlertX | Homelab Overview and Management Running on Head Node |
| <img src="https://github.com/devicons/devicon/blob/master/icons/vagrant/vagrant-original.svg" title="Vagrant" alt="Vagrant" width="40" height="40"/>&nbsp; | Vagrant | Virtual Machine Management for ThinkPad |
| <img src="./Images/Virtualbox_logo.png" title="VirtualBox" alt="VirtualBox" width="40" height="40"/>&nbsp; | VirtualBox | Virtualization for Hardware |
| <img src="./Images/nemesis.png" title="Nemesis" alt="Nemesis" width="40" height="40"/>&nbsp; | Nemesis | Network IP Suite |
