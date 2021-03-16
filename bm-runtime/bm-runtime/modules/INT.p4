/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control INTIngress(inout headers hdr,
				  inout metadata meta,
				  inout standard_metadata_t standard_metadata) {
	action drop() {
		mark_to_drop(standard_metadata);
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
		default_action = NoAction();
	}

	apply {
		if (hdr.ipv4.isValid()) {
			ipv4_lpm.apply();
		}
	}
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control INTEgress(inout headers hdr,
				 inout metadata meta,
				 inout standard_metadata_t standard_metadata) {

		action add_swtrace(switchID_t swid){
				 	hdr.int_header.push_front(1);
					hdr.int_header[0].setValid();
					hdr.int_header[0].proto_id = TYPE_INT_HEADER;
			 		hdr.int_header[0].swid = swid;
			 		hdr.int_header[0].qdepth = (qdepth_t) standard_metadata.deq_qdepth;
			 		hdr.int_header[0].hop_delay = (bit <32>) standard_metadata.deq_timedelta;  //Hop delay is in microsseconds
			 		hdr.int_header[0].in_timestamp = (bit <48>) standard_metadata.ingress_global_timestamp;
		}

	table swtrace {
		actions = {
			add_swtrace;
  		NoAction;
		}
		default_action = NoAction();
	}

	apply {
		swtrace.apply();
	}
}


