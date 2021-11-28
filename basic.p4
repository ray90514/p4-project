/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#define LIST_BIT_WIDTH  256
#define LIST_SIZE 1024
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_Alarm = 0x800;
const int WINDOW_SIZE = 8192;
const int TABLE_NUM = 8192;
//const bit<LIST_BIT_WIDTH> bit_pos_0 = 0x1;
//const bit<LIST_BIT_WIDTH> bit_pos_256 = 0x10000000000000000000000000000000000000000000000000000000000000000;
//const bit<LIST_BIT_WIDTH> bit_pos_512 =0x100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000;
//const bit<LIST_BIT_WIDTH> bit_pos_768 =0x1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000;
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
    bit<LIST_BIT_WIDTH> list0_high;
    bit<LIST_BIT_WIDTH> list0_low;
    bit<LIST_BIT_WIDTH> list1_high;
    bit<LIST_BIT_WIDTH> list1_low;
    bit<LIST_BIT_WIDTH> list2_high;
    bit<LIST_BIT_WIDTH> list2_low;
    bit<LIST_BIT_WIDTH> list3_high;
    bit<LIST_BIT_WIDTH> list3_low;
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
    //TODO: operation of two hash addresses neeeded
    register<bit<1>>(1) test;
    bit<1> flag;
    //
    register<bit<LIST_BIT_WIDTH>>(1) suspect_list_high_0;
    register<bit<LIST_BIT_WIDTH>>(1) suspect_list_low_0;
    register<bit<LIST_BIT_WIDTH>>(1) suspect_list_high_1;
    register<bit<LIST_BIT_WIDTH>>(1) suspect_list_low_1;
    register<bit<LIST_BIT_WIDTH>>(1) suspect_list_high_2;
    register<bit<LIST_BIT_WIDTH>>(1) suspect_list_low_2;
    register<bit<LIST_BIT_WIDTH>>(1) suspect_list_high_3;
    register<bit<LIST_BIT_WIDTH>>(1) suspect_list_low_3;
    bit<LIST_BIT_WIDTH> list_low_value_0;
    bit<LIST_BIT_WIDTH> list_high_value_0;
    bit<LIST_BIT_WIDTH> list_low_value_1;
    bit<LIST_BIT_WIDTH> list_high_value_1;
    bit<LIST_BIT_WIDTH> list_low_value_2;
    bit<LIST_BIT_WIDTH> list_high_value_2;
    bit<LIST_BIT_WIDTH> list_low_value_3;
    bit<LIST_BIT_WIDTH> list_high_value_3;
    bit<LIST_BIT_WIDTH> entry_count;
    bit<LIST_BIT_WIDTH> mask1;
    bit<LIST_BIT_WIDTH> mask2;
    bit<LIST_BIT_WIDTH> bit_mask;
    bit<10> addr;
    bit<8> addr8;
    bool isSuspect;//isSuspect 1
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
    //remove suspect list
    action remove_list_0() {
        addr8 = (bit<8>)addr;
        bit_mask = (bit<LIST_BIT_WIDTH>)1 << (bit<8>)addr;
        entry_count = ((list_high_value_0 & bit_mask) >> (addr8 + 1)) + ((list_low_value_0 & bit_mask) >> addr8) - 1;
        list_high_value_0 = (list_high_value_0 & ~bit_mask) | (entry_count & 0b10) << (addr8 - 1);
        list_low_value_0 = (list_low_value_0 & ~bit_mask) | (entry_count & 0b01) << addr8;
    }
    action remove_list_1() {
        addr8 = (bit<8>)(addr - 256);
        bit_mask = (bit<LIST_BIT_WIDTH>)1 << addr8;
        entry_count = ((list_high_value_1 & bit_mask) >> (addr8 + 1)) + ((list_low_value_1 & bit_mask) >> addr8) - 1;
        list_high_value_1 = (list_high_value_1 & ~bit_mask) | (entry_count & 0b10) << (addr8 - 1);
        list_low_value_1 = (list_low_value_1 & ~bit_mask) | (entry_count & 0b01) << addr8;
    }
    action remove_list_2() {
        addr8 = (bit<8>)(addr - 512);
        bit_mask = (bit<LIST_BIT_WIDTH>)1 << 8;
        entry_count = ((list_high_value_2 & bit_mask) >> (addr8 + 1)) + ((list_low_value_2 & bit_mask) >> addr8) - 1;
        list_high_value_2 = (list_high_value_2 & ~bit_mask) | (entry_count & 0b10) << (addr8 - 1);
        list_low_value_2 = (list_low_value_2 & ~bit_mask) | (entry_count & 0b01) << addr8;
    }
    action remove_list_3() {
        addr8 = (bit<8>)(addr - 768);
        bit_mask = (bit<LIST_BIT_WIDTH>)1 << addr8;
        entry_count = ((list_high_value_3 & bit_mask) >> (addr8 + 1)) + ((list_low_value_3 & bit_mask) >> addr8) - 1;
        list_high_value_3 = (list_high_value_3 & ~bit_mask) | (entry_count & 0b10) << (addr8 - 1);
        list_low_value_3 = (list_low_value_3 & ~bit_mask) | (entry_count & 0b01) << addr8;
    }
    table remove_suspect {
        key = {
            addr : range;
        }
        actions = {
            remove_list_0;
            remove_list_1;
            remove_list_2;
            remove_list_3;
            NoAction;
        }
        default_action = NoAction();
        const entries = {
            (0 .. 255) : remove_list_0();
            (256 .. 511) : remove_list_1();
            (512 .. 767) : remove_list_2();
            (768 .. 1023) : remove_list_3();
        }
    }
    //add suspect list
    action add_list_0() {
        addr8 = (bit<8>)addr;
        bit_mask = (bit<LIST_BIT_WIDTH>)1 << (bit<8>)addr;
        entry_count = ((list_high_value_0 & bit_mask) >> (addr8 + 1)) + ((list_low_value_0 & bit_mask) >> addr8) + 1;
        list_high_value_0 = (list_high_value_0 & ~bit_mask) | (entry_count & 0b10) << (addr8 - 1);
        list_low_value_0 = (list_low_value_0 & ~bit_mask) | (entry_count & 0b01) << addr8;
    }
    action add_list_1() {
        addr8 = (bit<8>)(addr - 256);
        bit_mask = (bit<LIST_BIT_WIDTH>)1 << addr8;
        entry_count = ((list_high_value_1 & bit_mask) >> (addr8 + 1)) + ((list_low_value_1 & bit_mask) >> addr8) + 1;
        list_high_value_1 = (list_high_value_1 & ~bit_mask) | (entry_count & 0b10) << (addr8 - 1);
        list_low_value_1 = (list_low_value_1 & ~bit_mask) | (entry_count & 0b01) << addr8;
    }
    action add_list_2() {
        addr8 = (bit<8>)(addr - 512);
        bit_mask = (bit<LIST_BIT_WIDTH>)1 << 8;
        entry_count = ((list_high_value_2 & bit_mask) >> (addr8 + 1)) + ((list_low_value_2 & bit_mask) >> addr8) + 1;
        list_high_value_2 = (list_high_value_2 & ~bit_mask) | (entry_count & 0b10) << (addr8 - 1);
        list_low_value_2 = (list_low_value_2 & ~bit_mask) | (entry_count & 0b01) << addr8;
    }
    action add_list_3() {
        addr8 = (bit<8>)(addr - 768);
        bit_mask = (bit<LIST_BIT_WIDTH>)1 << addr8;
        entry_count = ((list_high_value_3 & bit_mask) >> (addr8 + 1)) + ((list_low_value_3 & bit_mask) >> addr8) + 1;
        list_high_value_3 = (list_high_value_3 & ~bit_mask) | (entry_count & 0b10) << (addr8 - 1);
        list_low_value_3 = (list_low_value_3 & ~bit_mask) | (entry_count & 0b01) << addr8;
    }
    table add_suspect {
        key = {
            addr : range;
        }
        actions = {
            add_list_0;
            add_list_1;
            add_list_2;
            add_list_3;
            NoAction;
        }
        default_action = NoAction();
        const entries = {
            (0 .. 255) : add_list_0();
            (256 .. 511) : add_list_1();
            (512 .. 767) : add_list_2();
            (768 .. 1023) : add_list_3();
        }
    }
    //check suspect list
    action check_list_0() {
        addr8 = (bit<8>)addr;
        bit_mask = (bit<LIST_BIT_WIDTH>)1 << (bit<8>)addr;
        entry_count = ((list_high_value_0 & bit_mask) >> (addr8 + 1)) + ((list_low_value_0 & bit_mask) >> addr8);
    }
    action check_list_1() {
        addr8 = (bit<8>)(addr - 256);
        bit_mask = (bit<LIST_BIT_WIDTH>)1 << addr8;
        entry_count = ((list_high_value_1 & bit_mask) >> (addr8 + 1)) + ((list_low_value_1 & bit_mask) >> addr8);
    }
    action check_list_2() {
        addr8 = (bit<8>)(addr - 512);
        bit_mask = (bit<LIST_BIT_WIDTH>)1 << 8;
        entry_count = ((list_high_value_2 & bit_mask) >> (addr8 + 1)) + ((list_low_value_2 & bit_mask) >> addr8);
    }
    action check_list_3() {
        addr8 = (bit<8>)(addr - 768);
        bit_mask = (bit<LIST_BIT_WIDTH>)1 << addr8;
        entry_count = ((list_high_value_3 & bit_mask) >> (addr8 + 1)) + ((list_low_value_3 & bit_mask) >> addr8);
    }
    table check_suspect {
        key = {
            addr : range;
        }
        actions = {
            check_list_0;
            check_list_1;
            check_list_2;
            check_list_3;
            NoAction;
        }
        default_action = NoAction();
        const entries = {
            (0 .. 255) : check_list_0();
            (256 .. 511) : check_list_1();
            (512 .. 767) : check_list_2();
            (768 .. 1023) : check_list_3();
        }
    }
    apply {
        /* TODO: fix ingress control logic
         *  - ipv4_lpm should be applied only when IPv4 header is valid
         */
        //get values of whole suspect lists values
        suspect_list_high_0.read(list_high_value_0, 0);
        suspect_list_low_0.read(list_low_value_0, 0);
        suspect_list_high_1.read(list_high_value_1, 0);
        suspect_list_low_1.read(list_low_value_1, 0);
        suspect_list_high_2.read(list_high_value_2, 0);
        suspect_list_low_2.read(list_low_value_2, 0);
        suspect_list_high_3.read(list_high_value_3, 0);
        suspect_list_low_3.read(list_low_value_3, 0);
        test.read(flag,0);
        if(flag == 0) {
            hash(addr, HashAlgorithm.crc16, (bit<32>)0,{(bit<32>)0x0A000101},(bit<32>)LIST_SIZE);
            add_suspect.apply();
            //remove_suspect.apply();
            flag=1;
            test.write(0,flag);
            log_msg("test");
        }
        if(hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }

        hash(addr, HashAlgorithm.crc16,(bit<32>)0, {(bit<32>)hdr.ipv4.srcAddr},(bit<32>)LIST_SIZE);
        //remove ip in suspect_list
        if(hdr.removed_ip_h.isValid()) {
            //remove_suspect.apply();
        }
        //add suspect_list
        if(hdr.suspect_list_h.isValid()) {
            //add_suspect.apply();
        }
        //TODO:suspect checked
        check_suspect.apply();
        log_msg("count: {} {} {}",{hdr.ipv4.srcAddr,hdr.ipv4.dstAddr,entry_count});
        if(entry_count > 0) {
            drop();
            log_msg("drop");
        }
        //apply the whole suspect list
        suspect_list_high_0.write(0, list_high_value_0);
        suspect_list_low_0.write(0, list_low_value_0);
        suspect_list_high_1.write(0, list_high_value_1);
        suspect_list_low_1.write(0, list_low_value_1);
        suspect_list_high_2.write(0, list_high_value_2);
        suspect_list_low_2.write(0, list_low_value_2);
        suspect_list_high_3.write(0, list_high_value_3);
        suspect_list_low_3.write(0, list_low_value_3);
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
