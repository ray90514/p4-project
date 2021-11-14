/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#define LIST_BIT_WIDTH  256
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_Alarm = 0x800;
const int WINDOW_SIZE = 8192;
const int TABLE_NUM = 8192;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header alarm_t {
    bit<8> isSuspectList;
}

header suspect_list_t {
    bit<LIST_BIT_WIDTH> list;
}

header removed_ip_t {
    bit<32> removed_ip;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    alarm_t      alarm;
    suspect_list_t suspect_list_h;
    removed_ip_t   removed_ip_h;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_Alarm: parse_alarm;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
    state parse_alarm {
        packet.extract(hdr.alarm);
        transition select(hdr.alarm.isSuspectList){
            1: parse_suspect;
            0: parse_removed;
        }
    }
    state parse_suspect {
        packet.extract(hdr.suspect_list_h);
        transition parse_ipv4;
    }
    state parse_removed {
        packet.extract(hdr.removed_ip_h);
        transition parse_ipv4;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<LIST_BIT_WIDTH>>(1) suspect_list;
    register<bit<LIST_BIT_WIDTH>>(1) remove_suspect_list;
    action addSuspect() {
        bit<LIST_BIT_WIDTH> res_suspect_list;
        suspect_list.read(res_suspect_list, 0);
        res_suspect_list = res_suspect_list | hdr.suspect_list_h.list;
        suspect_list.write(0, res_suspect_list);
    }
    action removeSuspect(bit<32> ip_addr) {
        bit<8> pos1;
        bit<LIST_BIT_WIDTH> res_remove_suspect;
        hash(pos1, HashAlgorithm.crc16, (bit<8>)0, {ip_addr}, (bit<9>)LIST_BIT_WIDTH);
        remove_suspect_list.read(res_remove_suspect, 0);
        remove_suspect_list.write(0, res_remove_suspect | (bit<LIST_BIT_WIDTH>)1 << pos1);
    }
    /*action checkSuspect(out bool isSuspect, bit<32> ip_addr) {

    }*/
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        /* TODO: fill out code in action body */
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        /* TODO: fix ingress control logic
         *  - ipv4_lpm should be applied only when IPv4 header is valid
         */
        if(hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        //remove ip in suspect_list
        if(hdr.removed_ip_h.isValid()) {
            removeSuspect(hdr.removed_ip_h.removed_ip);
            bit<LIST_BIT_WIDTH> res_suspect; bit<LIST_BIT_WIDTH> res_remove_suspect;
            suspect_list.read(res_suspect, 0);
            remove_suspect_list.read(res_remove_suspect, 0);
            if(res_suspect == res_remove_suspect) {
                suspect_list.write(0, (bit<LIST_BIT_WIDTH>)0);
                remove_suspect_list.write(0, (bit<LIST_BIT_WIDTH>)0);
            }
        }
        //add suspect_list
        if(hdr.suspect_list_h.isValid()) {
            addSuspect();
        }
        //check suspect
        bool isSuspect;
        bit<8> pos1;
        bit<LIST_BIT_WIDTH> res_suspect; bit<LIST_BIT_WIDTH> res_remove_suspect;
        hash(pos1, HashAlgorithm.crc16, (bit<8>)0, {hdr.ipv4.srcAddr}, (bit<9>)LIST_BIT_WIDTH);
        remove_suspect_list.read(res_remove_suspect, 0);
        //ip addr isn't removed
        if((res_remove_suspect & (bit<LIST_BIT_WIDTH>)1 << pos1) == 0 ) {
            suspect_list.read(res_suspect, 0);
            if((res_suspect & (bit<LIST_BIT_WIDTH>)1 << pos1) != 0) {
                isSuspect = true;
            }
            else {
                isSuspect = false;
            }
        }
        else {
            isSuspect = false;
        }
        if(isSuspect) {

        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* TODO: add deparser logic */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
