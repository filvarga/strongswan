#!/usr/bin/env bash

# Copyright (c) 2018 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#AGENT_ROOT=../vpp-agent/plugins
AGENT_ROOT=~/go/src/github.com/ligato/vpp-agent/plugins

PROTO_PLUGIN=`which grpc_cpp_plugin`

linux_plugins=(
    interfaces
    l3
)

vpp_plugins=(
    interfaces
    ipsec
    punt
    acl
    bfd
    nat
    stn
    l2
    l3
    l4
)

for file in ${linux_plugins[@]}
do
    mkdir -p ./model/linux/model/${file}
    cp ${AGENT_ROOT}/linux/model/${file}/${file}.proto \
      ./model/linux/model/${file}/${file}.proto

    #protoc -I ./model --plugin=protoc-gen-grpc=${PROTO_PLUGIN} \
    #--grpc_out=. ./model/linux/model/${file}/${file}.proto
    protoc -I ./model --cpp_out=. ./model/linux/model/${file}/${file}.proto

    python -m grpc_tools.protoc -I ./model --python_out=. \
      ./model/linux/model/${file}/${file}.proto
    touch ./linux/model/${file}/__init__.py
done 
touch ./linux/model/__init__.py
touch ./linux/__init__.py

for file in ${vpp_plugins[@]}
do
    mkdir -p ./model/vpp/model/${file}
    cp ${AGENT_ROOT}/vpp/model/${file}/${file}.proto \
      ./model/vpp/model/${file}/${file}.proto

    #protoc -I ./model --plugin=protoc-gen-grpc=${PROTO_PLUGIN} \
    #--grpc_out=. ./model/vpp/model/${file}/${file}.proto
    protoc -I ./model --cpp_out=. ./model/vpp/model/${file}/${file}.proto

    python -m grpc_tools.protoc -I ./model --python_out=. \
      ./model/vpp/model/${file}/${file}.proto
    touch ./vpp/model/${file}/__init__.py
done

touch ./vpp/model/__init__.py
touch ./vpp/__init__.py

touch ./model/__init__.py

cp ${AGENT_ROOT}/vpp/model/rpc/rpc.proto ./model/rpc.proto

# Workaround #1: fix messed up import paths in rpc.proto
sed -i 's/github.com\/ligato\/vpp-agent\/plugins\///' \
    ./model/rpc.proto

protoc -I ./model --plugin=protoc-gen-grpc=${PROTO_PLUGIN} \
  --grpc_out=. ./model/rpc.proto
protoc -I ./model --cpp_out=. ./model/rpc.proto

python -m grpc_tools.protoc -Imodel --python_out=. --grpc_python_out=. model/rpc.proto
#rm -rf ./model

