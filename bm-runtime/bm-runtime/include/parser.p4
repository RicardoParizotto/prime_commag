#ifndef _PARSER_P4_
#define _PARSER_P4_


#define ETHERTYPE_IPV4 16w0x0800
#define UDP_PROTOCOL 8w0x11
#define PAXOS_PROTOCOL 16w0x8888


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
	    TYPE_INT_HEADER: parse_hint;
            TYPE_PRIME: parse_prime;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

       state parse_hint {
		packet.extract(hdr.int_header.next);
		transition select(hdr.int_header.last.proto_id) {
			TYPE_IPV4: parse_ipv4;
			TYPE_INT_HEADER : parse_hint;
			default: accept;
		}
	}

    state parse_prime {
         packet.extract(hdr.prime);
         transition parse_ipv4;
     }

   state parse_ipv4 {
		packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol){
                        UDP_PROTOCOL : parse_udp;
			6       : parse_tcp;
			default : accept;
		}
	}

	state parse_tcp {
		packet.extract(hdr.tcp);
		transition accept;
	}

      state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            PAXOS_PROTOCOL : parse_paxos;
            default : accept;
        }
    }

    state parse_paxos {
        packet.extract(hdr.paxos);
        transition accept;
    }

}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.prime);
	packet.emit(hdr.int_header);
        packet.emit(hdr.ipv4);
	packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.paxos);
    }
}

#endif

