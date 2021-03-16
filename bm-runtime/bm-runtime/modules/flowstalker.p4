
control FlowStalker(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }
    register<bit<16>>(32w16) heavy_hitter_counter1;
    register<bit<16>>(32w16) heavy_hitter_counter2;
    register<bit<16>>(1) smalltresh;
    register<bit<16>>(1) tresh;
    register<bit<64>>(1024) ts;
    register<bit<64>>(256) ts_sender;
    register<bit<64>>(256) ts_recver;
    register<bit<1>>(256) ts_valid;
    register<bit<32>>(32w16) Whois;
    register<bit<16>>(32w16) flowMax;
    register<bit<16>>(32w16) flowMin;
    action do_copy_to_cpu() {
        clone3(CloneType.I2E, (bit<32>)32w250, { standard_metadata });
    }
    action watch_ts() {
        meta.custom_metadata_p1.ts_aux = (bit<64>)standard_metadata.ingress_global_timestamp;
        meta.custom_metadata_p1.ts_zone = (bit<64>)hdr.ipv4.dstAddr & 0xf;
        ts_sender.read(meta.custom_metadata_p1.ts_aux1, (bit<32>)meta.custom_metadata_p1.ts_zone);
        ts_recver.read(meta.custom_metadata_p1.ts_aux2, (bit<32>)meta.custom_metadata_p1.ts_zone);
        if (meta.custom_metadata_p1.ts_aux1 == (bit<64>)hdr.ipv4.srcAddr && meta.custom_metadata_p1.ts_aux2 == (bit<64>)hdr.ipv4.dstAddr || meta.custom_metadata_p1.ts_aux1 == 0 || meta.custom_metadata_p1.ts_aux2 == 0) {
            meta.custom_metadata_p1.ts_power = meta.custom_metadata_p1.ts_aux >> 8;
            meta.custom_metadata_p1.ts_modulo = meta.custom_metadata_p1.ts_aux & 0xff;
            if (meta.custom_metadata_p1.ts_power < 5) {
                if (meta.custom_metadata_p1.ts_power == 0) {
                    meta.custom_metadata_p1.ts_power = 1;
                } else {
                    if (meta.custom_metadata_p1.ts_power == 1) {
                        meta.custom_metadata_p1.ts_power = 2;
                    } else {
                        if (meta.custom_metadata_p1.ts_power == 2) {
                            meta.custom_metadata_p1.ts_power = 4;
                        } else {
                            if (meta.custom_metadata_p1.ts_power == 3) {
                                meta.custom_metadata_p1.ts_power = 8;
                            } else {
                                if (meta.custom_metadata_p1.ts_power == 4) {
                                    meta.custom_metadata_p1.ts_power = 16;
                                } else {
                                    if (meta.custom_metadata_p1.ts_power == 5) {
                                        meta.custom_metadata_p1.ts_power = 32;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            meta.custom_metadata_p1.ts_zone = -1;
        }
        ts.read(meta.custom_metadata_p1.ts_val1, (bit<32>)meta.custom_metadata_p1.ts_zone + (bit<32>)meta.custom_metadata_p1.ts_modulo);
        ts.write((bit<32>)meta.custom_metadata_p1.ts_zone + (bit<32>)meta.custom_metadata_p1.ts_modulo, meta.custom_metadata_p1.ts_val1 + meta.custom_metadata_p1.ts_power);
    }
    action set_heavy_hitter_count() {
        hash(meta.custom_metadata_p1.hash_val1, HashAlgorithm.csum16, (bit<16>)0, { hdr.ipv4.dstAddr }, (bit<32>)16);
        heavy_hitter_counter1.read(meta.custom_metadata_p1.count_val1, (bit<32>)meta.custom_metadata_p1.hash_val1);
        meta.custom_metadata_p1.count_val1 = meta.custom_metadata_p1.count_val1 + 16w1;
        heavy_hitter_counter1.write((bit<32>)meta.custom_metadata_p1.hash_val1, (bit<16>)meta.custom_metadata_p1.count_val1);
        heavy_hitter_counter2.read(meta.custom_metadata_p1.count_val2, (bit<32>)meta.custom_metadata_p1.hash_val1);
        meta.custom_metadata_p1.count_val2 = meta.custom_metadata_p1.count_val2 + hdr.ipv4.totalLen;
        heavy_hitter_counter2.write((bit<32>)meta.custom_metadata_p1.hash_val1, (bit<16>)meta.custom_metadata_p1.count_val2);
    }
    action simple_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }
    table set_heavy_hitter_count_table {
        actions = {
            set_heavy_hitter_count;
        }
        default_action = set_heavy_hitter_count;
        size = 1;
    }
    table copy_to_cpu {
        actions = {
            do_copy_to_cpu;
        }
        default_action = do_copy_to_cpu;
        size = 1;
    }
    table monitor {
        actions = {
            watch_ts;
        }
        default_action = watch_ts;
        size = 1;
    }
    apply {
        if (hdr.ipv4.isValid()) {
            set_heavy_hitter_count_table.apply();
            smalltresh.read(meta.custom_metadata_p1.smalltresh, 0);
            tresh.read(meta.custom_metadata_p1.tresh, 0);
            if (meta.custom_metadata_p1.count_val1 > meta.custom_metadata_p1.smalltresh) {
                monitor.apply();
            }
            if (meta.custom_metadata_p1.count_val1 > meta.custom_metadata_p1.tresh) {
                copy_to_cpu.apply();
            }
        }
    }
}




