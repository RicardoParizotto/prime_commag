//header identifications
const bit<16> TYPE_IPV4 = 0x800;
const bit<32> CHAIN_SIZE = 3;
const bit<16> TYPE_PRIME = 0x400;



typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

header prime_t{
   bit<32>      state_tag;
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

struct metadata {
    custom_metadata_t                      custom_metadata;
    standard_metadata_t  		        aux;
    egressSpec_t               		        port_aux;
    bit<64>                                                   aux_ingress_metadata;
    bit<64>                                                   aux_swap;
    bit<32>                                                   state_tag;
}

struct headers {
    ethernet_t   ethernet;
    prime_t          prime;
    ipv4_t              ipv4;
}