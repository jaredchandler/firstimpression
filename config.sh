mkdir -p /etc/systemd/system/ssh.socket.d
cat >/etc/systemd/system/ssh.socket.d/listen.conf <<EOF
[Socket]
ListenStream=
ListenStream=2200
EOF
sudo systemctl daemon-reload
sudo systemctl restart ssh
ssh-keygen -t rsa -b 4096 -C "lihs@punkt.de" -f foo