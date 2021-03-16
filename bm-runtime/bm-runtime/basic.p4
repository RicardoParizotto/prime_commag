/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "include/headers.p4"
#include "include/parser.p4"
#include "modules/flowstalker.p4"
#include "modules/INT.p4"
#include "modules/leader.p4"


control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/************ registers for evaluation ***********************/
register<bit<64>>(1) timestamps_bank;
register<bit<64>>(1) packet_count;
register<bit<64>>(1000) ingress_timestamp;
register<bit<64>>(1000) egress_timestamp;
register<bit<32>>(1000) state_tag;

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

       FlowStalker()              flowstalker_instance;
       INTIngress()                int_instance;
       LeaderIngress()        leader_instance;

    counter(CHAIN_SIZE + 1, CounterType.packets_and_bytes) programProcessingCounter;
    counter(1, CounterType.packets_and_bytes) dropped_packets_count;

    action drop() {
        mark_to_drop(standard_metadata);
        dropped_packets_count.count((bit<32>)0);
    }
    
    action commited(bit <32> new_tag){
	meta.state_tag = new_tag;
    }

    action catalogue( bit<8> nf1, bit<8> nf2, bit<8> nf3, egressSpec_t port, macAddr_t dstAddr) {
        meta.custom_metadata.nf_01_id  =  nf1;
        meta.custom_metadata.nf_02_id  =  nf2;
        meta.custom_metadata.nf_03_id  =  nf3;                   
        meta.custom_metadata.port = port;
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
     }

    table shadow{
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            commited;
            drop;
        }
	    size = 1024;

     }

    table steering{
        key = {
            hdr.ipv4.dstAddr: lpm;
            meta.state_tag : exact;
        }
        actions = {
            catalogue;
            drop;
        }
	    size = 1024;
     }

    apply {

	if(!hdr.prime.isValid()){
              shadow.apply();
              hdr.prime.setValid();
              hdr.prime.state_tag = meta.state_tag; 
              hdr.ethernet.etherType =  TYPE_PRIME;
        }else{
 	      meta.state_tag = hdr.prime.state_tag;             
        }

	steering.apply();

        meta.aux_ingress_metadata = ( bit<64> ) standard_metadata.ingress_global_timestamp;
        packet_count.read(meta.aux_swap,0);
        meta.aux_swap = meta.aux_swap + 1;
        packet_count.write(0, meta.aux_swap);


         ingress_timestamp.write((bit<32>)meta.aux_swap,  ( bit<64> )                  standard_metadata.ingress_global_timestamp);
         state_tag.write((bit<32>) meta.aux_swap, meta.state_tag);

        //if the next function to be processed is the function with ID=1
	 if (meta.custom_metadata.nf_01_id == 1){
 		flowstalker_instance.apply(hdr, meta, standard_metadata)  ;
                programProcessingCounter.count((bit<32>)1);
        }
        if (meta.custom_metadata.nf_02_id == 1){
           int_instance.apply(hdr, meta, standard_metadata)  ;
           programProcessingCounter.count((bit<32>)2);
        }
        if (meta.custom_metadata.nf_03_id == 1){
	  leader_instance.apply(hdr, meta, standard_metadata)  ;
           programProcessingCounter.count((bit<32>)3);
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

       INTEgress()               int_instance;
       LeaderEgress()        leader_instance;

    apply {
	    if (meta.custom_metadata.nf_01_id == 1){
	        //Function_1
        }
        if (meta.custom_metadata.nf_02_id == 1){
           int_instance.apply(hdr, meta, standard_metadata)  ;
        }
        if (meta.custom_metadata.nf_03_id == 1){
	  leader_instance.apply(hdr, meta, standard_metadata)  ;
    	    //Function_3  
        }

       //timestamps_bank.read(meta.aux_swap,0);
       //imestamps_bank.write(0, meta.aux_swap + (( bit<64>) standard_metadata.egress_global_timestamp - meta.aux_ingress_metadata));
 
       egress_timestamp.write((bit<32>)meta.aux_swap,  ( bit<64> ) standard_metadata.egress_global_timestamp);
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
