#!/usr/bin/env python3
import argparse
import grpc
import os
import sys
import threading
from time import sleep
import numpy as np
import joblib
import warnings

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 './utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

def attackDefence(p4info_helper, sw):
    digest_id = p4info_helper.get_id("digests", "digest_t")
    digest_entry = p4info_helper.buildDigestEntry(digest_id)
    table_entry = p4info_helper.buildTableEntry(table_name="MyIngress.update_is_attack_table",
                                                default_action = True,
                                                action_name="MyIngress.update_is_attack",
                                                action_params={
                                                "new_is_attack": 0,
                                                })
    sw.DigestConfig(digest_entry)
    sw.WriteTableEntry(table_entry)
    list_id = None
    no_attack_count = 0
    is_attack = False
    while True:
        print('\n----- Reading digest(%d) for %s -----'%(digest_id, sw.name))
        for digest in sw.ReadDigest(digest_id, list_id):
            list_id = digest.list_id
            for data in digest.data:
                packet_count = int.from_bytes(data.struct.members[0].bitstring, 'big')
                packet_size = int.from_bytes(data.struct.members[1].bitstring, 'big')
                icmp_count = int.from_bytes(data.struct.members[2].bitstring, 'big')
                tcp_count = int.from_bytes(data.struct.members[3].bitstring, 'big')
                udp_count = int.from_bytes(data.struct.members[4].bitstring, 'big')
                other_count = int.from_bytes(data.struct.members[5].bitstring, 'big')
                syn_count = int.from_bytes(data.struct.members[6].bitstring, 'big')
                faultflags_count = int.from_bytes(data.struct.members[7].bitstring, 'big')
                interval = int.from_bytes(data.struct.members[8].bitstring, 'big')
                print('---------------------------')
                #print(f'packet_count: {packet_count}')
                #print(f'packet_length: {packet_size}')
                #print(f'tcp_count: {tcp_count}')
                #print(f'udp_count: {udp_count}')
                #print(f'syn_count: {syn_count}')
                #print(f'interval: {interval}')
                a = packet_size/ packet_count
                b = interval/(1000000000*packet_count)
                c = tcp_count/packet_count
                d = udp_count/packet_count
                e = icmp_count/packet_count
                f = other_count/packet_count
                if tcp_count == 0 :
                    g = 0.0
                    h = 0.0
                else :
                    g = syn_count/tcp_count
                    h = faultflags_count/tcp_count
                print(f'packet size: {a}')
                print(f'interval: {b}')
                print(f'tcp ratio: {c}')
                print(f'udp ratio: {d}')
                print(f'icmp ratio: {e}')
                print(f'other ratio: {f}')
                print(f'syn/tcp: {g}')
                print(f'faultflags/tcp: {h}')
                target = RF.predict(np.array([[a,b,c,d,e,f,g,h]]))
                if target != 0:
                    #print("\033[91m%s\033[0m"%"Under attacking!!!")
                    if target[0] == 1:
                        print("\033[91m%s\033[0m"%"Under SYN flood attacking!!!")
                    elif target[0] == 2:
                        print("\033[91m%s\033[0m"%"Under UDP flood attacking!!!")
                    elif target[0] == 3:
                        print("\033[91m%s\033[0m"%"Under ICMP flood attacking!!!")
                    elif target[0] == 4:
                        print("\033[91m%s\033[0m"%"Under TCP flags attacking!!!")
                    no_attack_count = 0
                    if not is_attack:
                        table_entry.action.action.params[0].value = bytes([target[0]])
                        sw.WriteTableEntry(table_entry)
                    is_attack = True
                else:
                    print("\033[93m%s\033[0m"%'BENGIN')
                    if is_attack:
                        no_attack_count += 1
                    if is_attack and no_attack_count == 10:
                        table_entry.action.action.params[0].value = bytes([target[0]])
                        sw.WriteTableEntry(table_entry)
                        no_attack_count = 0
                        is_attack = False


def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()

        attackDefence(p4info_helper, s1)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    RF = joblib.load('RF2')
    warnings.filterwarnings("ignore")
    main(args.p4info, args.bmv2_json)
