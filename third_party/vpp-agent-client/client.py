#!/usr/bin/env python2

from grpc import insecure_channel
from rpc_pb2 import DumpRequest
from rpc_pb2_grpc import DataDumpServiceStub


def run():
    channel = insecure_channel('127.0.0.1:9111')
    stub = DataDumpServiceStub(channel)

    response = stub.DumpInterfaces(DumpRequest())

    print(dir(response))
    return response

if __name__ == '__main__':
    run()

