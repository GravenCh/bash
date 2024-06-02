#!/bin/bash

apt update && apt upgrade -y && apt autoremove -y
apt install net-tools htop vim curl python3-pip sysstat linux-modules-extra-$(uname -r) -y
wget -P /home https://raw.githubusercontent.com/MateorChan/bash/main/report.py
nohup python3 /home/report.py -p=a63f5045-8a43-4f2f-bbca-cde1d561a5eb -a=https://monitor.imateor.com/api.php  > /dev/null &
cat > /etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local Compatibility
Documentation=man:systemd-rc-local-generator(8)
ConditionFileIsExecutable=/etc/rc.local
After=network.target

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
RemainAfterExit=yes
GuessMainPID=no

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/rc.local <<EOF
#!/bin/bash

nohup python3 /home/report.py -p=a63f5045-8a43-4f2f-bbca-cde1d561a5eb -a=https://monitor.imateor.com/api.php  > /dev/null &
EOF
chmod +x /etc/rc.local
systemctl enable rc-local
sudo modprobe tcp_bbr
echo "tcp_bbr" | sudo tee --append /etc/modules-load.d/modules.conf
echo "net.core.default_qdisc=fq" | sudo tee --append /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" | sudo tee --append /etc/sysctl.conf
sysctl -p
cat > /etc/security/limits.conf <<EOF
* soft nofile 1024000
* soft nproc 1024000
* hard nofile 1024000
* hard nproc 1024000
root soft nofile 1024000
root soft nproc 1024000
root hard nofile 1024000
root hard nproc 1024000
nobody soft nofile 1024000
nobody soft nproc 1024000
nobody hard nofile 1024000
nobody hard nproc 1024000
EOF
