# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: vpp/model/punt/punt.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='vpp/model/punt/punt.proto',
  package='punt',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=_b('\n\x19vpp/model/punt/punt.proto\x12\x04punt\"\x85\x01\n\x04Punt\x12\x0c\n\x04name\x18\x01 \x01(\t\x12%\n\x0bl3_protocol\x18\x02 \x01(\x0e\x32\x10.punt.L3Protocol\x12%\n\x0bl4_protocol\x18\x03 \x01(\x0e\x32\x10.punt.L4Protocol\x12\x0c\n\x04port\x18\x04 \x01(\r\x12\x13\n\x0bsocket_path\x18\x05 \x01(\t*;\n\nL3Protocol\x12\x10\n\x0cUNDEFINED_L3\x10\x00\x12\x08\n\x04IPv4\x10\x04\x12\x08\n\x04IPv6\x10\x06\x12\x07\n\x03\x41LL\x10\n*0\n\nL4Protocol\x12\x10\n\x0cUNDEFINED_L4\x10\x00\x12\x07\n\x03TCP\x10\x06\x12\x07\n\x03UDP\x10\x11\x62\x06proto3')
)

_L3PROTOCOL = _descriptor.EnumDescriptor(
  name='L3Protocol',
  full_name='punt.L3Protocol',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='UNDEFINED_L3', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='IPv4', index=1, number=4,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='IPv6', index=2, number=6,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ALL', index=3, number=10,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=171,
  serialized_end=230,
)
_sym_db.RegisterEnumDescriptor(_L3PROTOCOL)

L3Protocol = enum_type_wrapper.EnumTypeWrapper(_L3PROTOCOL)
_L4PROTOCOL = _descriptor.EnumDescriptor(
  name='L4Protocol',
  full_name='punt.L4Protocol',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='UNDEFINED_L4', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='TCP', index=1, number=6,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='UDP', index=2, number=17,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=232,
  serialized_end=280,
)
_sym_db.RegisterEnumDescriptor(_L4PROTOCOL)

L4Protocol = enum_type_wrapper.EnumTypeWrapper(_L4PROTOCOL)
UNDEFINED_L3 = 0
IPv4 = 4
IPv6 = 6
ALL = 10
UNDEFINED_L4 = 0
TCP = 6
UDP = 17



_PUNT = _descriptor.Descriptor(
  name='Punt',
  full_name='punt.Punt',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='name', full_name='punt.Punt.name', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='l3_protocol', full_name='punt.Punt.l3_protocol', index=1,
      number=2, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='l4_protocol', full_name='punt.Punt.l4_protocol', index=2,
      number=3, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='port', full_name='punt.Punt.port', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='socket_path', full_name='punt.Punt.socket_path', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=36,
  serialized_end=169,
)

_PUNT.fields_by_name['l3_protocol'].enum_type = _L3PROTOCOL
_PUNT.fields_by_name['l4_protocol'].enum_type = _L4PROTOCOL
DESCRIPTOR.message_types_by_name['Punt'] = _PUNT
DESCRIPTOR.enum_types_by_name['L3Protocol'] = _L3PROTOCOL
DESCRIPTOR.enum_types_by_name['L4Protocol'] = _L4PROTOCOL
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Punt = _reflection.GeneratedProtocolMessageType('Punt', (_message.Message,), dict(
  DESCRIPTOR = _PUNT,
  __module__ = 'vpp.model.punt.punt_pb2'
  # @@protoc_insertion_point(class_scope:punt.Punt)
  ))
_sym_db.RegisterMessage(Punt)


# @@protoc_insertion_point(module_scope)
