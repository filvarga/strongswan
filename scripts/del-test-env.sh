#!/bin/bash

sudo docker stop initiator &> /dev/null
sudo docker stop responder &> /dev/null

#sudo docker stop kafka &> /dev/null
#sudo docker stop etcd &> /dev/null
#sudo docker stop vpp &> /dev/null
#sudo docker network rm dev-net &> /dev/null
