# Wazuh Offline All-in-One Installation Using Ansible

This guide explains how to deploy Wazuh on an offline Ubuntu/Debian server using Ansible.

The Ansible control server already has the Wazuh offline installation files, and the target Wazuh server does not have internet access.

<img width="1631" height="1695" alt="image" src="https://github.com/user-attachments/assets/1ca05b2c-2b28-4e25-ac94-21bd669598d9" />


## Architecture

```text
Internet-connected system
        |
        | Download Wazuh offline files
        v
Ansible control server
        |
        | Copy files and run installer using Ansible
        v
Offline Wazuh server
```

## Example Lab Details

```text
Ansible server: ansible
Offline Wazuh server: wazuh-server
Wazuh target IP: 192.168.56.11
Package type: DEB
Architecture: amd64 / x86_64
Wazuh version: 4.14.5
Deployment type: All-in-one
```

The all-in-one deployment installs the following components on the same offline server:

```text
Wazuh indexer
Wazuh manager
Filebeat
Wazuh dashboard
```

## Prerequisites

### On the Ansible Server

Install Ansible:

```bash
apt update
apt install -y ansible
```

Confirm Ansible is installed:

```bash
ansible --version
```

### On the Offline Wazuh Server

The target server must have:

```text
Ubuntu/Debian OS
SSH access from the Ansible server
Python 3 installed
Sufficient CPU, RAM, and disk space
No internet required
```

Check SSH access from the Ansible server:

```bash
ssh root@192.168.56.11
```

If SSH passwordless login is not configured, copy the SSH key:

```bash
ssh-keygen -t rsa -b 4096
ssh-copy-id root@192.168.56.11
```

Test again:

```bash
ssh root@192.168.56.11
```

## Step 1: Download Wazuh Offline Files on an Internet-Connected Linux System

Run these commands on a Linux system that has internet access.

Download the Wazuh installer script:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
chmod 744 wazuh-install.sh
```

Download the offline DEB packages for AMD64/x86_64:

```bash
./wazuh-install.sh -dw deb -da amd64
```

Download the certificates configuration file:

```bash
curl -sO https://packages.wazuh.com/4.14/config.yml
```

For an all-in-one deployment, edit `config.yml` and use `127.0.0.1` for the indexer, manager, and dashboard IP values.

Example:

```yaml
nodes:
  indexer:
    - name: node-1
      ip: 127.0.0.1

  server:
    - name: wazuh-1
      ip: 127.0.0.1

  dashboard:
    - name: dashboard
      ip: 127.0.0.1
```

Generate certificates:

```bash
./wazuh-install.sh -g
```

After this, you should have these files:

```text
wazuh-install.sh
wazuh-offline.tar.gz
wazuh-install-files.tar
```

## Step 2: Copy the Offline Files to the Ansible Server

Copy the three files to the Ansible server.

Example:

```bash
scp wazuh-install.sh root@<ANSIBLE_SERVER_IP>:/home/vagrant/
scp wazuh-offline.tar.gz root@<ANSIBLE_SERVER_IP>:/home/vagrant/
scp wazuh-install-files.tar root@<ANSIBLE_SERVER_IP>:/home/vagrant/
```

On the Ansible server, verify the files:

```bash
cd /home/vagrant
ls -lh wazuh-install.sh wazuh-offline.tar.gz wazuh-install-files.tar
```

Expected output should look similar to this:

```text
-rw-rw-r-- 1 vagrant vagrant  11K May  8 07:45 wazuh-install-files.tar
-rw-rw-r-- 1 vagrant vagrant 195K May  8 07:15 wazuh-install.sh
-rw-rw-r-- 1 vagrant vagrant 1.5G May  8 07:40 wazuh-offline.tar.gz
```

## Step 3: Create the Ansible Working Directory

On the Ansible server:

```bash
mkdir -p /etc/ansible/wazuh-offline
cd /etc/ansible/wazuh-offline
```

## Step 4: Create the Ansible Inventory

Create the inventory file:

```bash
vi inventory.ini
```

Add the following content:

```ini
[wazuh_offline]
wazuh-server ansible_host=192.168.56.11 ansible_user=root

[all:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_ssh_extra_args='-o StrictHostKeyChecking=no'
```

Update `192.168.56.11` with the IP address of your offline Wazuh server.

Test Ansible connectivity:

```bash
ansible -i inventory.ini wazuh_offline -m ping
```

Expected output:

```text
wazuh-server | SUCCESS => {
    "changed": false,
    "ping": "pong"
}
```

If this fails, fix SSH access before continuing.

## Step 5: Create the Ansible Playbook

Create the playbook:

```bash
vi install-wazuh-offline.yml
```

Add the following content:

```yaml
---
- name: Install Wazuh all-in-one using offline package bundle
  hosts: wazuh_offline
  become: yes

  vars:
    local_offline_files_dir: "/home/vagrant"
    remote_offline_dir: "/root/wazuh-offline-install"
    overwrite_existing_installation: true

  tasks:
    - name: Create offline installation directory on target server
      file:
        path: "{{ remote_offline_dir }}"
        state: directory
        owner: root
        group: root
        mode: "0755"

    - name: Copy Wazuh offline installer script
      copy:
        src: "{{ local_offline_files_dir }}/wazuh-install.sh"
        dest: "{{ remote_offline_dir }}/wazuh-install.sh"
        owner: root
        group: root
        mode: "0744"

    - name: Copy Wazuh offline package archive
      copy:
        src: "{{ local_offline_files_dir }}/wazuh-offline.tar.gz"
        dest: "{{ remote_offline_dir }}/wazuh-offline.tar.gz"
        owner: root
        group: root
        mode: "0644"

    - name: Copy Wazuh install files archive
      copy:
        src: "{{ local_offline_files_dir }}/wazuh-install-files.tar"
        dest: "{{ remote_offline_dir }}/wazuh-install-files.tar"
        owner: root
        group: root
        mode: "0644"

    - name: Check target architecture
      command: uname -m
      register: target_arch
      changed_when: false

    - name: Show target architecture
      debug:
        msg: "Target architecture is {{ target_arch.stdout }}. For DEB amd64 package, this should be x86_64."

    - name: Clean broken Wazuh packages and leftovers
      shell: |
        mkdir -p /root/dpkg-broken-scripts-backup

        mv /var/lib/dpkg/info/wazuh-dashboard.prerm /root/dpkg-broken-scripts-backup/ 2>/dev/null || true
        mv /var/lib/dpkg/info/wazuh-dashboard.postrm /root/dpkg-broken-scripts-backup/ 2>/dev/null || true
        mv /var/lib/dpkg/info/wazuh-dashboard.postinst /root/dpkg-broken-scripts-backup/ 2>/dev/null || true

        dpkg --remove --force-remove-reinstreq wazuh-manager 2>/dev/null || true
        dpkg --purge --force-all wazuh-manager wazuh-indexer wazuh-dashboard filebeat 2>/dev/null || true
        dpkg --configure -a || true

        rm -rf /var/ossec
        rm -rf /etc/wazuh-indexer /var/lib/wazuh-indexer /usr/share/wazuh-indexer
        rm -rf /etc/wazuh-dashboard /usr/share/wazuh-dashboard
        rm -rf /etc/filebeat /var/lib/filebeat

        systemctl daemon-reload
      changed_when: true
      when: overwrite_existing_installation | bool

    - name: Create dummy apt-transport-https package if missing
      shell: |
        if ! dpkg -l | grep -q '^ii  apt-transport-https'; then
          rm -rf /root/apt-transport-https-dummy /root/apt-transport-https_2.4.14_all.deb
          mkdir -p /root/apt-transport-https-dummy/DEBIAN

          cat > /root/apt-transport-https-dummy/DEBIAN/control << 'PKGEOF'
Package: apt-transport-https
Version: 2.4.14
Section: admin
Priority: optional
Architecture: all
Depends: apt
Maintainer: local
Description: Dummy apt-transport-https package for offline Wazuh installation
PKGEOF

          dpkg-deb --build /root/apt-transport-https-dummy /root/apt-transport-https_2.4.14_all.deb
          dpkg -i /root/apt-transport-https_2.4.14_all.deb
        fi
      changed_when: true

    - name: Create dummy debhelper package if missing
      shell: |
        if ! dpkg -l | grep -q '^ii  debhelper'; then
          rm -rf /root/debhelper-dummy /root/debhelper_13.6ubuntu1_all.deb
          mkdir -p /root/debhelper-dummy/DEBIAN

          cat > /root/debhelper-dummy/DEBIAN/control << 'PKGEOF'
Package: debhelper
Version: 13.6ubuntu1
Section: devel
Priority: optional
Architecture: all
Depends: perl
Maintainer: local
Description: Dummy debhelper package for offline Wazuh installation
PKGEOF

          dpkg-deb --build /root/debhelper-dummy /root/debhelper_13.6ubuntu1_all.deb
          dpkg -i /root/debhelper_13.6ubuntu1_all.deb
        fi
      changed_when: true

    - name: Show prerequisite package status
      shell: dpkg -l | grep -E 'apt-transport-https|debhelper' || true
      register: prereq_packages
      changed_when: false

    - name: Display prerequisite package status
      debug:
        var: prereq_packages.stdout_lines

    - name: Run Wazuh offline all-in-one installation with overwrite
      command: bash ./wazuh-install.sh --offline-installation -a -o
      args:
        chdir: "{{ remote_offline_dir }}"
      register: wazuh_install_output
      when: overwrite_existing_installation | bool

    - name: Run Wazuh offline all-in-one installation without overwrite
      command: bash ./wazuh-install.sh --offline-installation -a
      args:
        chdir: "{{ remote_offline_dir }}"
      register: wazuh_install_output
      when: not overwrite_existing_installation | bool

    - name: Show Wazuh installation output
      debug:
        var: wazuh_install_output.stdout_lines
      when: wazuh_install_output is defined

    - name: Check Wazuh services
      shell: |
        systemctl is-active wazuh-indexer || true
        systemctl is-active wazuh-manager || true
        systemctl is-active filebeat || true
        systemctl is-active wazuh-dashboard || true
      register: wazuh_services
      changed_when: false

    - name: Show Wazuh service status
      debug:
        var: wazuh_services.stdout_lines

    - name: Extract Wazuh admin password
      shell: |
        tar -axf {{ remote_offline_dir }}/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -P "'admin'" -A 1 || true
      register: wazuh_admin_password
      changed_when: false

    - name: Show Wazuh admin password
      debug:
        var: wazuh_admin_password.stdout_lines
```

## Step 6: Run the Playbook

Run the playbook from the Ansible server:

```bash
cd /etc/ansible/wazuh-offline
ansible-playbook -i inventory.ini install-wazuh-offline.yml
```

If SSH password authentication is required, use:

```bash
ansible-playbook -i inventory.ini install-wazuh-offline.yml --ask-pass
```

If sudo password is required, use:

```bash
ansible-playbook -i inventory.ini install-wazuh-offline.yml -K
```

If both SSH and sudo password are required, use:

```bash
ansible-playbook -i inventory.ini install-wazuh-offline.yml --ask-pass -K
```

## Step 7: Verify the Installation

Check service status:

```bash
ansible -i inventory.ini wazuh_offline -b -m shell -a "systemctl is-active wazuh-indexer wazuh-manager filebeat wazuh-dashboard"
```

Expected output:

```text
active
active
active
active
```

Check detailed service status:

```bash
ansible -i inventory.ini wazuh_offline -b -m shell -a "systemctl status wazuh-indexer --no-pager"
ansible -i inventory.ini wazuh_offline -b -m shell -a "systemctl status wazuh-manager --no-pager"
ansible -i inventory.ini wazuh_offline -b -m shell -a "systemctl status filebeat --no-pager"
ansible -i inventory.ini wazuh_offline -b -m shell -a "systemctl status wazuh-dashboard --no-pager"
```

Check installed packages:

```bash
ansible -i inventory.ini wazuh_offline -b -m shell -a "dpkg -l | grep -E 'wazuh|filebeat|apt-transport-https|debhelper'"
```

Expected package state should be `ii`:

```text
ii  apt-transport-https
ii  debhelper
ii  filebeat
ii  wazuh-dashboard
ii  wazuh-indexer
ii  wazuh-manager
```

## Step 8: Get the Wazuh Dashboard Password

The playbook prints the admin password at the end.

You can also manually extract it with:

```bash
ansible -i inventory.ini wazuh_offline -b -m shell -a "tar -axf /root/wazuh-offline-install/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -P \"'admin'\" -A 1"
```

## Step 9: Access the Wazuh Dashboard

Open the browser:

```text
https://<OFFLINE_WAZUH_SERVER_IP>
```

Example:

```text
https://192.168.56.11
```

Login with:

```text
Username: admin
Password: <password shown by the playbook>
```

## Important Notes

### Dummy packages are a lab workaround

The dummy `apt-transport-https` and `debhelper` packages only satisfy the Wazuh installer prerequisite checks.

For production, the cleaner method is to download the real packages and all their dependencies from an internet-connected Ubuntu system with the same OS version and architecture, then copy and install them offline.

### The three Wazuh files must stay together

Keep these files in the same directory on the target server:

```text
wazuh-install.sh
wazuh-offline.tar.gz
wazuh-install-files.tar
```

In this guide, they are copied to:

```text
/root/wazuh-offline-install
```

### Do not extract wazuh-offline.tar.gz manually

For the assisted offline installation method, let `wazuh-install.sh` handle the archive.

### Use the correct architecture

For DEB amd64 packages, the target server should show:

```bash
uname -m
```

Expected:

```text
x86_64
```

If the server is ARM64, you must download the ARM64 package bundle instead:

```bash
./wazuh-install.sh -dw deb -da arm64
```

## Useful Commands

Check architecture:

```bash
ansible -i inventory.ini wazuh_offline -b -m shell -a "uname -m"
```

Check package state:

```bash
ansible -i inventory.ini wazuh_offline -b -m shell -a "dpkg -l | grep -E 'wazuh|filebeat|apt-transport-https|debhelper' || true"
```

Check Wazuh installer log:

```bash
ansible -i inventory.ini wazuh_offline -b -m shell -a "tail -n 100 /var/log/wazuh-install.log"
```

Check service status:

```bash
ansible -i inventory.ini wazuh_offline -b -m shell -a "systemctl is-active wazuh-indexer wazuh-manager filebeat wazuh-dashboard"
```

Restart services:

```bash
ansible -i inventory.ini wazuh_offline -b -m shell -a "systemctl restart wazuh-indexer wazuh-manager filebeat wazuh-dashboard"
```

Check Wazuh indexer locally:

```bash
ansible -i inventory.ini wazuh_offline -b -m shell -a "curl -k -u admin:<PASSWORD> https://127.0.0.1:9200"
```

Check Wazuh indexer nodes:

```bash
ansible -i inventory.ini wazuh_offline -b -m shell -a "curl -k -u admin:<PASSWORD> https://127.0.0.1:9200/_cat/nodes?v"
```
