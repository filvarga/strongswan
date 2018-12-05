#!/bin/bash

AGENT_CFG_DIR="/tmp/vpp-agent"
INITIATOR_CFG_DIR="/tmp/initiator"

grpc_conf() {
  cat << EOF > $AGENT_CFG_DIR/grpc.conf
# GRPC endpoint defines IP address and port (if tcp type) or unix domain socket file (if unix type).
endpoint: 0.0.0.0:9111

# If unix domain socket file is used for GRPC communication, permissions to the file can be set here.
# Permission value uses standard three-or-four number linux binary reference.
permission: 000

# If socket file exists in defined path, it is not removed by default, GRPC plugin tries to use it.
# Set the force removal flag to 'true' ensures that the socket file will be always re-created
force-socket-removal: false

# Available socket types: tcp, tcp4, tcp6, unix, unixpacket. If not set, defaults to tcp.
network: tcp

# Maximum message size in bytes for inbound mesages. If not set, GRPC uses the default 4MB.
max-msg-size: 4096

# Limit of server streams to each server transport.
max-concurrent-streams: 0
EOF
}

# TODO: as sudo
responder_conf() {
  sudo bash -c 'cat << EOF > /etc/ipsec.conf
conn responder
# defaults?
  auto=add
  compress=no
  fragmentation=yes
  forceencaps=yes

  type=tunnel
  keyexchange=ikev2
  ike=aes256-sha1-modp2048
  esp=aes192-sha1-esn!
  
# local:
  left=172.16.0.2
  leftauth=psk

  leftsubnet=10.10.10.0/24

# remote: (roadwarrior)
  rightauth=psk 
  
EOF'
  sudo bash -c 'cat << EOF > /etc/ipsec.secrets
: PSK "Vpp123"
EOF'
}

initiator_conf() {
  mkdir -p $INITIATOR_CFG_DIR
  cat << EOF > $INITIATOR_CFG_DIR/ipsec.conf
conn initiator
# defaults?
  auto=add
  compress=no
  fragmentation=yes
  forceencaps=yes

  type=tunnel
  keyexchange=ikev2
  ike=aes256-sha1-modp2048
  esp=aes192-sha1-esn!

# local:
  leftauth=psk  

# remote: (gateway)
  right=172.16.0.2
  rightauth=psk

  rightsubnet=10.10.10.0/24
  
EOF
  cat << EOF > $INITIATOR_CFG_DIR/ipsec.secrets
: PSK "Vpp123"
EOF
}

responder_conf
initiator_conf
grpc_conf

# vpp-agent prerequisites (kafka + etcd)
docker run --name kafka -p 9092:9092 -d --rm spotify/kafka
docker run --name etcd -p 2379:2379 -d --rm quay.io/coreos/etcd:v3.1.0 /usr/local/bin/etcd
sleep 1

# responder aka vpn server (gateway)
docker run --name responder -d --rm --net=host --privileged -it -v $AGENT_CFG_DIR:/opt/vpp-agent/dev ligato/vpp-agent

# initiator aka vpn client
docker run --name initiator -d --rm --privileged -v $INITIATOR_CFG_DIR:/etc/ipsec.d philplckthun/strongswan

# dummy network behind vpn
sleep 1
docker exec responder vppctl -s localhost:5002 tap connect tap0
docker exec responder vppctl -s localhost:5002 set int state tapcli-0 up
docker exec responder vppctl -s localhost:5002 set int ip address tapcli-0 10.10.10.1/24

# if we register veth interface in docker namespace docker will automatically
# delete the interface after container is destroied
# alternatively try to remove the interface: sudo ip link del wan0

# 1) create veth pair
sudo ip link add wan0 type veth peer name wan1
# 2) add one side of the veth pair to responder
docker exec responder vppctl -s localhost:5002 create host-interface name wan0
docker exec responder vppctl -s localhost:5002 set int state host-wan0 up
docker exec responder vppctl -s localhost:5002 set int ip address host-wan0 172.16.0.2/24
# 3) add other side of the veth pair to the initiator container
sudo ip link set netns $(docker inspect --format '{{.State.Pid}}' initiator) dev wan1
docker exec initiator ip addr add 172.16.0.1/24 dev wan1
docker exec initiator ip link set wan1 up

# 1) try to connect to responder over ikev2 vpn
# docker exec initiator ipsec up initiator 

# to debug (responder):
# docker exec -it responder vppctl -s localhost:5002
# to debug (initiator):
# docker exec -it initiator /bin/bash
