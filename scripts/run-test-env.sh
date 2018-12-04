#!/bin/bash

AGENT_CFG_DIR="/tmp"

KAFKA_ADDRESS="172.16.0.4"
KAFKA_PORT="9092"

ETCD_ADDRESS="172.16.0.3"
ETCD_PORT="2379"

GRPC_ADDRESS="172.16.0.2"
GRPC_PORT="9111"

HOST_ADDRESS="172.16.0.2"

kafka_conf() {
  cat << EOF > $AGENT_CFG_DIR/kafka.conf
addrs:
 - "$KAFKA_ADDRESS:$KAFKA_PORT"
EOF
}

etcd_conf() {
  cat << EOF > $AGENT_CFG_DIR/etcd.conf
insecure-transport: true
dial-timeout: 1000000000
endpoints:
 - "$ETCD_ADDRESS:$ETCD_PORT"
EOF
}

grpc_conf() {
  cat << EOF > $AGENT_CFG_DIR/grpc.conf
# GRPC endpoint defines IP address and port (if tcp type) or unix domain socket file (if unix type).
endpoint: $GRPC_ADDRESS:$GRPC_PORT

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
  mkdir -p /tmp/responder
  cat << EOF > /tmp/responder/ipsec.conf
conn gateway
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
  
EOF
  cat << EOF > /tmp/responder/ipsec.secrets
: PSK "Vpp123"
EOF
}

initiator_conf() {
  mkdir -p /tmp/initiator
  cat << EOF > /tmp/initiator/ipsec.conf
conn roadwarrior
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
  cat << EOF > /tmp/initiator/ipsec.secrets
: PSK "Vpp123"
EOF
}

#responder_conf
#initiator_conf

#docker network create --driver=bridge --gateway=172.16.0.10 --subnet=172.16.0.0/24 dev-net

#docker run --name responder -p 501:500 -p 171:170 -p 4501:4500 --net=dev-net --ip=172.16.0.2 -d --rm --privileged -v /tmp/responder:/etc/ipsec.d philplckthun/strongswan

#docker exec responder ip tuntap add dev tap0 mode tap
#docker exec responder ip addr add 10.10.10.1/24 dev tap0

#docker run --name initiator -p 502:500 -p 172:170 -p 4502:4500 --net=dev-net --ip=172.16.0.1 -d --rm --privileged -v /tmp/initiator:/etc/ipsec.d philplckthun/strongswan

#docker exec initiator ipsec up roadwarrior

# docker exec -i -t initiator /bin/bash

# docker run --net=dev-net --ip=172.16.0.1 --name roadwarrior --name strongswan -d --privileged --net=host -v /etc/ipsec.d:/etc/ipsec.d mberner/strongswan:v2

docker run --net=dev-net --ip=$KAFKA_ADDRESS -d --name kafka --rm --env ADVERTISED_HOST=$KAFKA_ADDRESS --env ADVERTISED_PORT=$KAFKA_PORT spotify/kafka

docker run --net=dev-net --ip=$ETCD_ADDRESS -d --name etcd --rm quay.io/coreos/etcd:v3.1.0 /usr/local/bin/etcd -advertise-client-urls http://$ETCD_ADDRESS:$ETCD_PORT -listen-client-urls http://$ETCD_ADDRESS:$ETCD_PORT

kafka_conf
etcd_conf
grpc_conf

sleep 2
docker run --net=dev-net --ip=$GRPC_ADDRESS -p 9111:9111  --privileged -it --name vpp --rm -v $AGENT_CFG_DIR:/opt/vpp-agent/dev ligato/vpp-agent

