#ifndef _HEADERS_P4_
#define _HEADERS_P4_


#define MAX_HOPS 7

//header identifications
const bit<16> TYPE_IPV4 = 0x800;
const bit<32> CHAIN_SIZE = 3;
const bit<16> TYPE_PRIME = 0x400;
const bit<16> TYPE_INT_HEADER = 0x1212;

typedef bit<48> EthernetAddress;
typedef bit<32> IPv4Address;
typedef bit<9> PortId;

// Physical Ports
const PortId DROP_PORT = 0xF;
// UDP Ports
const bit<16> ACCEPTOR_PORT = 0x8889;
const bit<16> LEARNER_PORT = 0x8890;
const bit<16> APPLICATION_PORT = 56789;


typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> qdepth_t;
typedef bit<32> switchID_t;


//identifies specific functions/programs
struct custom_metadata_t {
    bit<8>                 nf_01_id;
    bit<8>                 nf_02_id; 
    bit<8>                 nf_03_id;
    bit<9>                port;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}


header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

// Headers for Paxos
#define PAXOS_1A 0 
#define PAXOS_1B 1 
#define PAXOS_2A 2
#define PAXOS_2B 3 

#define MSGTYPE_SIZE    16
#define INSTANCE_SIZE   32
#define ROUND_SIZE      16
#define DATAPATH_SIZE   16
#define VALUELEN_SIZE   32
#define VALUE_SIZE      256
#define INSTANCE_COUNT  65536


header paxos_t {
    bit<MSGTYPE_SIZE>   msgtype;    // indicates the message type e.g., 1A, 1B, etc.
    bit<INSTANCE_SIZE>  inst;       // instance number
    bit<ROUND_SIZE>     rnd;        // round number
    bit<ROUND_SIZE>     vrnd;       // round in which an acceptor casted a vote
    bit<DATAPATH_SIZE>  acptid;     // Switch ID
    bit<VALUELEN_SIZE>  paxoslen;   // the length of paxos_value
    bit<VALUE_SIZE>     paxosval;   // the value the acceptor voted for
}


header int_header_t {
	bit<16>     proto_id;
	switchID_t  swid;
	qdepth_t    qdepth;
	switchID_t  hop_delay;
	bit<48>     in_timestamp;
}

header prime_t{
   bit<32>      state_tag;
}

header tcp_t {
  bit<16> srcAddr;
  bit<16> dstAddr;
  bit<32> seqNumber;
  bit<32> ackNumber;
  bit<4> dataOffset;
  bit<4> res;
  bit<8> flags;
  bit<16> window;
  bit<16> checksum;
  bit<16> urgentPtr;
}


header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     totalLen;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     fragOffset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}


struct custom_metadata_t_p1 {
    bit<32> nhop_ipv4;
    bit<16> hash_val1;
    bit<16> hash_val2;
    bit<16> count_val1;
    bit<16> count_val2;
    bit<64> ts_val1;
    bit<64> ts_val2;
    bit<16> tresh;
    bit<16> smalltresh;
    bit<64> ts_aux;
    bit<64> ts_modulo;
    bit<64> ts_zone;
    bit<64> ts_power;
    bit<64> ts_aux1;
    bit<64> ts_aux2;
    bit<64> ts_aux3;
    bit<64> ts_zone_sz;
}


struct paxos_metadata_t {
    bit<ROUND_SIZE> round;
    bit<1> set_drop;
    bit<8> ack_count;
    bit<8> ack_acceptors;
}


struct headers {
    ethernet_t   ethernet;
    int_header_t[MAX_HOPS]	int_header;
    prime_t          prime;
    ipv4_t              ipv4;
    tcp_t		        tcp;
    udp_t udp;
    paxos_t paxos;
}


struct metadata {
    custom_metadata_t_p1              custom_metadata_p1;
    custom_metadata_t                      custom_metadata;
    standard_metadata_t  		        aux;
    egressSpec_t               		        port_aux;
    bit<64>                                                   aux_ingress_metadata;
    bit<64>                                                   aux_swap;
    bit<32>                                                   state_tag;
    paxos_metadata_t   paxos_metadata;
}


#endif
