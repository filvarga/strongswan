/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdio>
#include <unistd.h>

#include <grpcpp/grpcpp.h>
#include <grpc/support/log.h>

#include "rpc.grpc.pb.h"

#include "libvpc.h"

using grpc::Channel;
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::CompletionQueue;
using grpc::Status;

// these are used for streams !!
using grpc::ClientReader;
using grpc::ClientWriter;

// we only need to enwrap streams
// in readers or writers

using interfaces::Interfaces_Interface;
using rpc::DataDumpService;
using rpc::DumpRequest;
using rpc::InterfaceResponse;


int main(int argc, char **argv)
{
  ClientContext context;
  Status status;

  DumpRequest req;
  InterfaceResponse rsp;

  std::shared_ptr<Channel> channel;
  std::unique_ptr<DataDumpService::Stub> stub;

  channel = grpc::CreateChannel(
    "localhost:9111", grpc::InsecureChannelCredentials());

  stub = DataDumpService::NewStub(channel);

  // we may use reader or something to list over
  // those features hmm
  //
  status = stub->DumpInterfaces(&context, req, &rsp);
  if (!status.ok())
  {
      fprintf(stderr, "!!!error!!!\n");
      exit(1);
  }

  // we need to somehow close the connectio ?
  // after we exit the thread the other side
  // returns error: transport is closing
  // not sure if this is an error or not
  //sleep(2);

  printf("all ok!\n");

  for (int i = 0; i < rsp.interfaces_size(); i++)
  {
      const Interfaces_Interface& interface = rsp.interfaces(i);

      printf("if_name: %s\n", interface.name().c_str());
      printf("if_mac: %s\n", interface.phys_address().c_str());
  }

  exit(0);
}

