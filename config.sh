systemctl disable --now ssh.service
systemctl enable --now ssh.socket
mkdir -p /etc/systemd/system/ssh.socket.d
cat >/etc/systemd/system/ssh.socket.d/listen.conf <<EOF
[Socket]
ListenStream=
ListenStream=853
EOF
sudo systemctl daemon-reload
sudo systemctl restart ssh
ssh-keygen -t rsa -b 4096 -C "lihs@punkt.de" -f foo
apt update
apt install python3-pip -y
pip3 install twisted
pip3 install pyOpenSSL
pip3 install service_identity
pip3 install zope
