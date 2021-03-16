
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
            TYPE_PRIME: parse_prime;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_prime {
         packet.extract(hdr.prime);
         transition parse_ipv4;
     }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.prime);
        packet.emit(hdr.ipv4);
    }
}



