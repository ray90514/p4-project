/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> PROTOCOL_TCP = 0x06;
const bit<8> PROTOCOL_UDP = 0x11;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> time_t;

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

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t      tcp;
}

struct digest_t {
    bit<32> packet_count;
    bit<32> packet_size;
    bit<32> tcp_count;
    bit<32> udp_count;
    bit<32> syn_count;
    time_t interval;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port) {
            default: parse_ethernet;
        }
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTOCOL_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
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

    register<time_t>(1) reg_prev_time;
    register<bit<32>>(1) reg_packet_count;
    register<bit<32>>(1) reg_packet_size;
    register<bit<32>>(1) reg_tcp_count;
    register<bit<32>>(1) reg_udp_count;
    register<bit<32>>(1) reg_syn_count;

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
         time_t prev_time;
         bit<32> packet_count;
         bit<32> packet_size;
         bit<32> udp_count;
         bit<32> tcp_count;
         bit<32> syn_count;

         reg_prev_time.read(prev_time, 0);
         reg_packet_size.read(packet_size, 0);
         reg_packet_count.read(packet_count,0);
         reg_tcp_count.read(tcp_count,0);
         reg_udp_count.read(udp_count,0);
         reg_syn_count.read(syn_count,0);

         packet_count = packet_count + 1;
         packet_size = standard_metadata.packet_length + packet_size;
         if(hdr.ipv4.protocol == PROTOCOL_TCP) {
             tcp_count = tcp_count + 1;
         }
         else if(hdr.ipv4.protocol == PROTOCOL_UDP) {
             udp_count = udp_count + 1;
         }
         if(hdr.tcp.ctrl & 0x2 != 0) {
             syn_count = syn_count + 1;
         }

         if(standard_metadata.ingress_global_timestamp - prev_time > 10000) {
             digest_t info;
             info.packet_size = packet_size;
             info.packet_count = packet_count;
             info.tcp_count = tcp_count;
             info.udp_count = udp_count;
             info.syn_count = syn_count;
             info.interval = standard_metadata.ingress_global_timestamp - prev_time;
             digest<digest_t>(0, info);
             packet_size = 0;
             packet_count = 0;
             tcp_count = 0;
             udp_count = 0;
             syn_count = 0;
             reg_prev_time.write(0, standard_metadata.ingress_global_timestamp);
         }
         reg_packet_count.write(0, packet_count);
         reg_packet_size.write(0, packet_size);
         reg_tcp_count.write(0, tcp_count);
         reg_udp_count.write(0, udp_count);
         reg_syn_count.write(0, syn_count);

         if(hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
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
        packet.emit(hdr.tcp);
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
