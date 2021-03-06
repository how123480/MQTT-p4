/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<16> TYPE_MQTT = 0x1234;

#define BLOOM_FILTER_ENTRIES        32
#define BLOOM_FILTER_BIT_WIDTH      32
#define LOG_BLOOM_FILTER_BIT_WIDTH   5

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header mqtt_t{
    bit<4> message_type;
    bit<1> DUP;
    bit<2> QoS;
    bit<1> R;
}

header topic_t {
    bit<16> topicID;
    bit<32> debug;
}

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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<BLOOM_FILTER_BIT_WIDTH> output_ports;
}

struct headers {
    ethernet_t   ethernet;
    mqtt_t       mqtt;
    topic_t      topic;
    ipv4_t       ipv4;
    tcp_t        tcp;
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
            TYPE_MQTT: parse_mqtt;
            default: accept;
        }
    }

    state parse_mqtt {
        packet.extract(hdr.mqtt);
        transition parse_topic;
    }

    state parse_topic {
        packet.extract(hdr.topic);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            default: accept;
        }
    }

    state tcp {
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

    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_1;

    bit<BLOOM_FILTER_ENTRIES>           topic_pos;
    bit<BLOOM_FILTER_BIT_WIDTH>         temp_port;
    bit<BLOOM_FILTER_BIT_WIDTH>              mask;
    bit<LOG_BLOOM_FILTER_BIT_WIDTH>  mask_power_1;
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action compute_hashes(bit<16> topic){
       //Get topic position
       hash(topic_pos, HashAlgorithm.crc16, (bit<32>)0, {topic}, (bit<32>)BLOOM_FILTER_ENTRIES);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
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
        default_action = drop();
    }

    apply {
        meta.output_ports = 32w0;
        meta.output_ports = meta.output_ports^(~meta.output_ports);

        if (hdr.mqtt.isValid()){
            compute_hashes(hdr.topic.topicID);

            if (hdr.mqtt.message_type == 3) {
                // PUBLISH
                bloom_filter_1.read(meta.output_ports, topic_pos);
                standard_metadata.mcast_grp = 1;
            }else if(hdr.mqtt.message_type == 8){
                //SUBSCRIBE
                bloom_filter_1.read(temp_port, topic_pos);
                // temp_port[standard_metadata.ingress_port-1] = 1;
                mask_power_1 = standard_metadata.ingress_port[LOG_BLOOM_FILTER_BIT_WIDTH-1:0];
                mask_power_1 = mask_power_1 - 5w1;
                mask = 32w1 << mask_power_1;
                temp_port = temp_port | mask;
                bloom_filter_1.write(topic_pos, temp_port);
                drop();
            }else if(hdr.mqtt.message_type == 10){
                //UNSUBSCRIBE
                bloom_filter_1.read(temp_port, topic_pos);
                // temp_port[standard_metadata.ingress_port-1] = 0;
                mask_power_1 = standard_metadata.ingress_port[LOG_BLOOM_FILTER_BIT_WIDTH-1:0];
                mask_power_1 = mask_power_1 - 5w1;
                mask = 32w1 << mask_power_1;
                temp_port = temp_port & ~mask;
                bloom_filter_1.write(topic_pos, temp_port);
                drop();
            }else {
                // do nothing
                drop();
            }
            
        }else if(hdr.ipv4.isValid()){
            // ipv4
            ipv4_lpm.apply();
        }else{
            //drop
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    bit<BLOOM_FILTER_BIT_WIDTH> mask;
    bit<LOG_BLOOM_FILTER_BIT_WIDTH> mask_power_1;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    apply {
        mask_power_1 = standard_metadata.egress_port[LOG_BLOOM_FILTER_BIT_WIDTH-1:0];
        mask_power_1 = mask_power_1 - 5w1;
        mask = 32w1 << mask_power_1;
        hdr.topic.debug = (bit<32>)standard_metadata.ingress_port;
        if((meta.output_ports & mask) == 32w0){
            drop();
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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
        packet.emit(hdr.ethernet);
        packet.emit(hdr.mqtt);
        packet.emit(hdr.topic);
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
