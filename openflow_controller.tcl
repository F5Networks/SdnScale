# openflow_controller.tcl --
#
#       This file implements a simple OpenFlow 1.3 Controller
#       to be used in a Proof on Concept Environment only
#
# Copyright (c) 2014-2016 F5 Networks, Inc.
# See the file "license.terms" for information on usage and
# redistribution of this file, and for a DISCLAIMER OF ALL WARRANTIES.
#
# version 1.1
#
# TODO:
# - fix binary data types to unsigned
# - replace bcat with something better


proc bcat {a b} {
    set la [ string length $a ]
    set lb [ string length $b ]
    return [ binary format a[set la]a[set lb] $a $b]
}

proc ip_to_bin {ip} {
    set octets [split $ip .]
    return [binary format c4 $octets]
}

proc bin_to_ip {bin} {
    binary scan $bin c4 octets
    foreach octet $octets {
        lappend result [expr {$octet & 0xFF}]
    }
    return [join $result .]
}

proc ip_to_hex {ip } {
    set octets [split $ip .]
    binary scan [binary format c4 $octets] H8 x
    return 0x$x
}

proc hex_to_ip {hex} {
    set bin [binary format I [expr {$hex}]]
    binary scan $bin c4 octets
    foreach octet $octets {
        lappend result [expr {$octet & 0xFF}]
    }
    return [join $result .]
}

proc cdir_to_bin {cdir} {
    return [expr {((0xFFFFFFFF << (32 - $cdir)) & 0xFFFFFFFF) }]
}

proc cdir_to_net_mask {cdir} {
    # helper function, takes cdir and returns list with net / mask
    set res [ lindex [ split $cdir / ] 0 ]
    lappend res [ lindex [ split $cdir / ] 1 ]
    return $res
}


proc ip_network {ip_addr cdir} {
    return [call hex_to_ip [ expr { [ call ip_to_hex $ip_addr ]  \
        & [call cdir_to_bin $cdir] }]]
}

proc mac_to_bin {mac} {
    regsub -all {:} $mac {} mac
    return [binary format H12 $mac]
}

proc bin_to_mac {bin} {
    binary scan $bin H2H2H2H2H2H2 a b c d e f
    return "$a:$b:$c:$d:$e:$f"
}

proc simple_carp {input size} {
    # we do not support more than 32 bit int
    set hash [md5 $input]
    binary scan $hash H8H8 null hash_low
    set hash_low 0x$hash_low
    return [ expr { $hash_low % $size } ]
}

proc ofp_padme {length} {
    set null "\x00"
    set pad ""
    for {set x 0} {$x<$length} {incr x} {
        set pad [set null][set pad]
    }
    return $pad
}

proc ofp_hdr {version type length xid} {
    # add 8 bytes for this ofp_hdr to the length field
    set length [ expr { $length + 8 } ]
    return [binary format ccSI \
        $version \
        $type \
        $length\
        $xid ]
}

proc add_ofp_hdr {version type xid pdu} {
    set length [string length $pdu ]
    set ofp_hdr [call ofp_hdr $version $type $length $xid]
    return [call bcat $ofp_hdr $pdu ]
}

proc ofp_hello {xid} {
    return [ call ofp_hdr \
        $static::MY_OFP_VERSION \
        $static::OFPT_HELLO \
        $static::OFP_HEADER_ZERO_PAYLOAD \
        $xid  ]
}

proc ofp_echo_respond {} {
    return [ call ofp_hdr \
        $static::MY_OFP_VERSION \
        $static::OFPT_ECHO_REPLY \
        $static::OFP_HEADER_ZERO_PAYLOAD \
        $static::OFP_HEADER_NO_XID ]
}

proc ofp_barrier_request {xid}{
   return [ call ofp_hdr \
        $static::MY_OFP_VERSION \
        $static::OFPT_BARRIER_REQUEST \
        $static::OFP_HEADER_ZERO_PAYLOAD \
        $xid  ]
}


proc add_ofp_match {pdu} {
    set type $static::OFP_MATCH_T(OFPMT_OXM)
    set length [string length $pdu]
    set ofp_match [binary format SS $type [ expr { $length + 4 } ]]
    set match_pdu [set ofp_match][set pdu]
    set length [ string length $match_pdu]
    set pad [call ofp_padme [expr {($length + 7 ) /8 * 8 -$length }]]

    return [ call bcat $match_pdu $pad]
}

proc add_ofp_instr_acts {pdu} {
    set type $static::OFP_INS_T(OFPIT_APPLY_ACTIONS)
    set pad [ call ofp_padme 4 ]
    set pdu_length [ string length $pdu]
    set length [expr { $pdu_length + 8 }]

    return [ binary format SSa4a[set pdu_length] $type $length $pad $pdu ]
}

proc add_ofp_act_hdr {pdu type} {
    set hdr_size 4
    set pdu_length [string length $pdu]
    set length [expr {$pdu_length + $hdr_size}]
    set pad_length [expr {($length + 15 ) /16 * 16 - $length }]
    set pad [call ofp_padme $pad_length]
    set length [ expr { $length + $pad_length }]

    return [ binary format SSa[set pdu_length]a[set pad_length] $type $length $pdu $pad ]
}

proc add_ofp_act_set_field_hdr {pdu} {
    return [ call add_ofp_act_hdr $pdu $static::OFP_ACTION_T(OFPAT_SET_FIELD)]
}

proc add_ofp_act_set_output_hdr {pdu} {
    return [ call add_ofp_act_hdr $pdu $static::OFP_ACTION_T(OFPAT_OUTPUT)]
}

proc ofp_oxm_port {port} {
    if {$port eq "NORMAL"} {
        return [ binary format a4S $static::OFPP_NORMAL 0 ]
    }
    else {
        return [ binary format a4S $port 0 ]
    }
}
proc add_ofp_act_normal {} {
    set pdu [call ofp_oxm_port "NORMAL"]
    return [ call add_ofp_act_set_output_hdr $pdu ]
}

proc add_ofp_fwd_to_controller {} {
    set max_length 70
    set pdu [binary format a4S $static::OFPP_CONTROLLER $max_length ]
    return [ call add_ofp_act_hdr $pdu $static::OFP_ACTION_T(OFPAT_OUTPUT)]
}

proc add_ofp_oxm_hdr {oxm_class oxm_field has_mask pdu} {
    # see p.39 OpenFlow 1.3, stealing lsb from oxm_field and
    # make it a binary flag for has_mask
    set oxm_length [string length $pdu ]
    set oxm_field [ expr { ( $oxm_field << 1 ) + $has_mask }]
    return [ binary format a2cca[set oxm_length] \
        $oxm_class \
        $oxm_field \
        $oxm_length \
        $pdu ]
}

proc ofp_oxm_vlan_vid {vid} {
    # adding 4096 to set OFPVID_PRESENT in the upper bit
    set vid [expr $vid + 4096 ]
    set pdu [ binary format S $vid ]
    return [ call add_ofp_oxm_hdr \
        $static::OFPXMC_OPENFLOW_BASIC \
        $static::OXM_OFB_MATCH_FIELDS(OFPXMT_OFB_VLAN_VID) \
        $static::OFP_OXM_HAS_NO_MASK \
        $pdu ]
}

proc ofp_oxm_eth_dst {mac} {
    set pdu [ call mac_to_bin $mac ]
    return [ call add_ofp_oxm_hdr \
        $static::OFPXMC_OPENFLOW_BASIC \
        $static::OXM_OFB_MATCH_FIELDS(OFPXMT_OFB_ETH_DST) \
        $static::OFP_OXM_HAS_NO_MASK \
        $pdu ]
}

proc ofp_oxm_eth_src {mac} {
    set pdu [ call mac_to_bin $mac ]
    return [ call add_ofp_oxm_hdr \
        $static::OFPXMC_OPENFLOW_BASIC \
        $static::OXM_OFB_MATCH_FIELDS(OFPXMT_OFB_ETH_SRC) \
        $static::OFP_OXM_HAS_NO_MASK \
        $pdu ]
}

proc ofp_oxm_eth_type {pdu} {
    return [ call add_ofp_oxm_hdr \
        $static::OFPXMC_OPENFLOW_BASIC \
        $static::OXM_OFB_MATCH_FIELDS(OFPXMT_OFB_ETH_TYPE) \
        $static::OFP_OXM_HAS_NO_MASK \
        $pdu ]
}

proc ofp_oxm_ipv4_src_nw {cdir} {
    foreach { nw mask } [call cdir_to_net_mask $cdir] break
    set pdu [ binary format a4I [call ip_to_bin $nw] [ call cdir_to_bin $mask ]]
    return [ call add_ofp_oxm_hdr \
        $static::OFPXMC_OPENFLOW_BASIC \
        $static::OXM_OFB_MATCH_FIELDS(OFPXMT_OFB_IPV4_SRC) \
        $static::OFP_OXM_HAS_MASK \
        $pdu ]
}

proc ofp_oxm_ipv4_dst_nw {cdir} {
    foreach { nw mask } [call cdir_to_net_mask $cdir] break
    set pdu [ binary format a4I [call ip_to_bin $nw] [ call cdir_to_bin $mask ]]
    return [ call add_ofp_oxm_hdr \
        $static::OFPXMC_OPENFLOW_BASIC \
        $static::OXM_OFB_MATCH_FIELDS(OFPXMT_OFB_IPV4_DST) \
        $static::OFP_OXM_HAS_MASK \
        $pdu ]
}

proc ofp_oxm_ipv4_dst {address} {
    return [ call add_ofp_oxm_hdr \
        $static::OFPXMC_OPENFLOW_BASIC \
        $static::OXM_OFB_MATCH_FIELDS(OFPXMT_OFB_IPV4_DST) \
        $static::OFP_OXM_HAS_NO_MASK \
        $address ]
}

proc ofp_oxm_ipv4_src {address} {
    return [ call add_ofp_oxm_hdr \
        $static::OFPXMC_OPENFLOW_BASIC \
        $static::OXM_OFB_MATCH_FIELDS(OFPXMT_OFB_IPV4_SRC) \
        $static::OFP_OXM_HAS_NO_MASK \
        $address ]
}

proc ofp_flow_mod_hdr {xid table_id priority idle_timeout hard_timeout buffer_id} {
    # as per OpenFlow 1.3 Specification page 54
    # construct OFPT_FLOW_MOD message ofp_hdr of size 56 byte
    # as per OpenFlow 1.3 B.6.9 Modify Actions in Existing Flow Entries
    # If the controller uses the OFPFC_ADD command to add an entry that already exists,
    # then the new entry replaces the old and all counters and timers are reset.

    set cookie  0
    set cookie_mask 0
    set command $static::OFP_FLOW_MOD_COMMAND(OFPFC_ADD)
    set out_port "\xff\xff\xff\xff"
    set out_group "\xff\xff\xff\xff"
    set buffer_id "\xff\xff\xff\xff"
    set flags 0
    set pad 0

    return [binary format WWccSSSa4a4a4SS \
        $cookie \
        $cookie_mask \
        $table_id \
        $command \
        $idle_timeout \
        $hard_timeout \
        $priority \
        $buffer_id \
        $out_port \
        $out_group  \
        $flags \
        $pad ]
}

proc add_ofp_flow_mod_hdr {xid table_id priority idle_timeout hard_timeout buffer_id pdu}{
    set ofp_flow_mod_hdr [call ofp_flow_mod_hdr \
                               $xid \
                               $table_id \
                               $priority \
                               $idle_timeout \
                               $hard_timeout \
                               $buffer_id]

    return [call bcat $ofp_flow_mod_hdr $pdu]
}

proc ofp_flow_mod {xid table_id priority buffer_id idle_timeout hard_timeout pdu}{
    set version $static::MY_OFP_VERSION
    set command $static::OFPT_FLOW_MOD
    set flow_mod_pdu [call add_ofp_flow_mod_hdr \
        $xid \
        $table_id \
        $priority \
        $idle_timeout \
        $hard_timeout \
        $buffer_id\
        $pdu]

    return [call add_ofp_hdr $version $command $xid $flow_mod_pdu ]
}

proc parse_ofpt_packet_in {pdu} {
    binary scan $pdu a8a4Scca8SSa8a2a*  \
        ofp_header \
        buffer_id \
        total_len \
        reason \
        table_id \
        cookie \
        match_type \
        match_length \
        oxm pad \
        l2_pdu

    lappend result $buffer_id
    # parsing l2 headers
    binary scan $l2_pdu a4a6a6a2a* null eth_dst eth_src eth_type l3_pdu
    binary scan $eth_type H2 eth_type_d
    lappend result [ call bin_to_mac $eth_dst] [ call bin_to_mac  $eth_src ] $eth_type_d

    binary scan $l3_pdu cca2a2a2cca2a4a4a*  \
        version_length \
        dscp \
        total_len \
        ip_id \
        flags \
        ttl \
        proto \
        checksum \
        nw_src \
        nw_dst \
        l4_pdu


    lappend result [ call bin_to_ip $nw_src ] [ call bin_to_ip $nw_dst]
    return $result

}

proc send_pdu {pdu} {
    # specification is unclear about if ECHO_REPLY, which contains 0 xid
    # still increases the xid. We do this here, as it is simpler
    upvar 1 xid lxid
    incr lxid
    TCP::respond $pdu
    # leaving the stack to sent the segment, we need a TCP::flush
}

proc send_barrier_request {xid} {
    upvar 1 OFP_XON_XOFF LOFP_XON_XOFF
    call send_pdu [ call ofp_barrier_request $xid ]
    set LOFP_XON_XOFF 0

    if { $static::OFP_DBG > 1 } {
        log local0.debug "SND OFPT_BARRIER_REQUEST disabling OFP_XON_XOFF"
    }
}

proc oxm_mapper {oxms}  {
    foreach { command oxm } $oxms break
    switch $command {
        nw_src { return [ call ofp_oxm_ipv4_src_nw $oxm ]}
        nw_dst { return [ call ofp_oxm_ipv4_dst_nw $oxm ]}
        dl_src { return [ call ofp_oxm_eth_src $oxm ]}
        dl_dst { return [ call ofp_oxm_eth_dst $oxm]}
        vlan_vid { return [ call ofp_oxm_vlan_vid $oxm]}
        port { return [ call ofp_oxm_port $oxm ]}
    }
}

proc rule_engine {rule} {
    # rule engine 1.0
    # expects rules in the following format
    # set test_rule
    #{ match {{ vlan_vid 2001 }  { nw_src 10.42.0.0/27 }}
    # action  {{ dl_src 02:01:00:f5:00:02 } { port NORMAL }} }
    # returns OpenFlow mod flow pdu

    set command  ""
    set match_pdu ""
    set action_pdu ""
    set needs_ethertype_oxm 0

    foreach rule_element $rule {
        switch $rule_element {
            match {
                set command "match"
            }
            action {
                if {$command eq "match"} {
                   # if a match for ip addresses, ethertype is mandentory
                   if { $needs_ethertype_oxm } {
                        set ethertype_ipv4 \
                            [call ofp_oxm_eth_type $static::ETHER_TYPE_IPV4]
                        set match_pdu [ call bcat $ethertype_ipv4 $match_pdu]
                   }
                   set match_pdu  [ call add_ofp_match $match_pdu ]
                }
                set command "action"
            }
            default {
                # if not match or action it will be a data field
                foreach oxm $rule_element {
                    switch $command {
                        match {
                            switch [lindex $oxm 0] {
                                nw_src { set needs_ethertype_oxm 1}
                                nw_dst { set needs_ethertype_oxm 1}
                            }
                            set match_pdu [
                                call bcat $match_pdu [
                                call oxm_mapper $oxm ]]
                        }
                        action {
                            switch [lindex $oxm 0] {
                                port {
                                    set action_pdu_element \
                                        [call add_ofp_act_set_output_hdr \
                                        [call oxm_mapper $oxm] ]
                                }
                                default {
                                    set action_pdu_element \
                                        [ call add_ofp_act_set_field_hdr \
                                        [ call oxm_mapper $oxm] ]
                                }
                            }
                            set action_pdu \
                                [ call bcat $action_pdu $action_pdu_element]
                        }
                    }
                }
            }
        }
    }
    set instruction_pdu [ call add_ofp_instr_acts $action_pdu ]
    return [ call bcat $match_pdu $instruction_pdu ]
}



when RULE_INIT {
    # lots of OpenFlow specific enums

    array set static::OFP_T {
        0       OFPT_HELLO
        1       OFPT_ERROR
        2       OFPT_ECHO_REQUEST
        3       OFPT_ECHO_REPLY
        4       OFPT_EXPERIMENTER
        5       OFPT_FEATURES_REQUEST
        6       OFPT_FEATURES_REPLY
        7       OFPT_GET_CONFIG_REQUEST
        8       OFPT_GET_CONFIG_REPLY
        9       OFPT_SET_CONFIG
        10      OFPT_PACKET_IN
        11      OFPT_FLOW_REMOVED
        12      OFPT_PORT_STATUS
        13      OFPT_PACKET_OUT
        14      OFPT_FLOW_MOD
        15      OFPT_GROUP_MOD
        16      OFPT_PORT_MOD
        17      OFPT_TABLE_MOD
        18      OFPT_MULTIPART_REQUEST
        19      OFPT_MULTIPART_REPLY
        20      OFPT_BARRIER_REQUEST
        21      OFPT_BARRIER_REPLY
        22      OFPT_QUEUE_GET_CONFIG_REQUEST
        23      OFPT_QUEUE_GET_CONFIG_REQUEST
        24      OFPT_ROLE_REQUEST
        25      OFPT_ROLE_REPLY
        26      OFPT_GET_ASYNC_REQUEST
        27      OFPT_GET_ASYNC_REPLY
        28      OFPT_SET_ASYNC
        29      OFPT_METER_MOD
    }

    array set static::OFP_FLOW_MOD_COMMAND {
        OFPFC_ADD 0
        OFPFC_MODIFY 1
        OFPFC_MODIFY_STRICT 2
        OFPFC_DELETE 3
    }

    array set static::OFP_MATCH_T {
        OFPMT_STANDARD 0
        OFPMT_OXM 1
    }

    array set static::OFP_INS_T {
        OFPIT_GOTO_TABLE 1
        OFPIT_WRITE_METADATA 2
        OFPIT_WRITE_ACTIONS 3
        OFPIT_APPLY_ACTIONS 4
        OFPIT_CLEAR_ACTIONS 5
        OFPIT_METER 6
        OFPIT_EXPERIMENTER 255
    }

    array set static::OFP_ACTION_T {
        OFPAT_OUTPUT 0
        OFPAT_COPY_TTL_OUT 11
        OFPAT_COPY_TTL_IN 12
        OFPAT_SET_MPLS_TTL 15
        OFPAT_DEC_MPLS_TTL 16
        OFPAT_PUSH_VLAN 17
        OFPAT_POP_VLAN 18
        OFPAT_PUSH_MPLS 19
        OFPAT_POP_MPLS 20
        OFPAT_SET_QUEUE 21
        OFPAT_GROUP 22
        OFPAT_SET_NW_TTL 23
        OFPAT_DEC_NW_TTL 24
        OFPAT_SET_FIELD 25
        OFPAT_PUSH_PBB 26
        OFPAT_POP_PBB 27
        OFPAT_EXPERIMENTER 255
    }

    array set static::OXM_OFB_MATCH_FIELDS {
        OFPXMT_OFB_IN_PORT 0
        OFPXMT_OFB_ETH_DST 3
        OFPXMT_OFB_ETH_SRC 4
        OFPXMT_OFB_ETH_TYPE 5
        OFPXMT_OFB_VLAN_VID 6
        OFPXMT_OFB_IP_PROTO 10
        OFPXMT_OFB_IPV4_SRC 11
        OFPXMT_OFB_IPV4_DST 12
        OFPXMT_OFB_TCP_SRC 13
        OFPXMT_OFB_TCP_DST 14
        OFPXMT_OFB_UDP_SRC 15
        OFPXMT_OFB_UDP_DST 16
        OFPXMT_OFB_ARP_OP 21
        OFPXMT_OFB_ARP_SPA 22
        OFPXMT_OFB_ARP_TPA 23
        OFPXMT_OFB_ARP_SHA 24
        OFPXMT_OFB_ARP_THA 25
    }

    array set static::OFP_VERSION {
        0       "OpenFlow 0.9"
        1       "OpenFlow 1.0"
        2       "OpenFlow 1.1"
        3       "OpenFlow 1.2"
        4       "OpenFlow 1.3"
    }

    # TODO: populate data-group instead

    array set static::NODES {
        0   "02:01:00:f5:00:01"
        1   "02:01:00:f5:00:02"
        2   "02:01:00:f5:00:03"
        3   "02:01:00:f5:00:04"
    }
    set static::NODES_AMOUNT 4

    set static::OP_command "proactive"
    set static::MY_OFP_VERSION 4
    set static::OFP_HEADER_ZERO_PAYLOAD 0
    set static::OFP_HEADER_NO_XID 0
    set static::OFPT_HELLO 0
    set static::OFPT_ECHO_REPLY 3
    set static::OFPT_FLOW_MOD 14
    set static::OFPT_BARRIER_REQUEST 20
    set static::OFPXMC_OPENFLOW_BASIC "\x80\x00"
    set static::OFP_OXM_HAS_MASK 1
    set static::OFP_OXM_HAS_NO_MASK 0
    set static::ETHER_TYPE_IPV4 "\x08\x00"
    set static::ETHER_TYPE_ARP "\x08\x02"
    set static::OFPP_NORMAL "\xff\xff\xff\xfa"
    set static::OFPP_CONTROLLER "\xff\xff\xff\xfd"
    set static::OFP_NO_BUF "\xff\xff\xff\xff"

    # configuration parameters
    set static::DAG_FLOW_IDLE_TIMEOUT <%=$disaggregation__idle%>
    set static::DAG_PREFIX_LEN <%=$disaggregation__depth%>
    set static::OFP_DBG <%=$debug__level%>
    set static::OF_RULES xcmp_dag_database

}


when CLIENT_ACCEPTED {
    if { $static::OFP_DBG > 0 }  {
        log local0.debug "connected from Switch [IP::client_addr]:[TCP::client_port]"
    }
    TCP::collect
    set OFP_CONN_STATE_UP 0
    set OFP_XON_XOFF 1
    set xid 0
}

when CLIENT_DATA {
    set pdu [TCP::payload ]
    set pdulength [TCP::payload length]

# reading the OFP_Header
binary scan $pdu ccSI version type length rxid

    # If we come across a switch sending more that one OFP PDU in a segment ASSERT
    # as this is not expected. If this ever happens will implement graceful collection
    if { $length > $pdulength } {
        log local0.error "ASSERTION OFP header indicates more payload needed."
        reject
    }

    if { $static::OFP_DBG > 2 } {
        set dbg_msg "$static::OFP_VERSION($version) "
        lappend dbg_msg "Message $static::OFP_T($type) "
        lappend dbg_msg "Length $length XID $rxid"
        log local0.debug $dbg_msg
    }

    switch $static::OFP_T($type) {
        OFPT_HELLO {
            if { $static::OFP_DBG > 0} {
                log local0.debug "RCVD OFPT_HELLO, RPLY OFPT_HELLO"
            }
            # be polite and sent a ofp_hello back
            call send_pdu [call ofp_hello $xid]
            # we said hello, so we are friends :)
            set OFP_CONN_STATE_UP 1

        }
        OFPT_ECHO_REQUEST {
            if { $static::OFP_DBG > 2} {
                log local0.debug "RCVD OFPT_ECHO_REQUEST, RPLY OFPT_ECHO_RESPOND"
            }
           call send_pdu [call ofp_echo_respond]
        }
        OFPT_BARRIER_REPLY {
            # the switched had processed all the rules we gave him
            # assuming that we want ot sent a blow of transactions every second
            # we block and pace the communication a bit.
            if { $static::OFP_DBG > 0} {
                log local0.debug "RCVD OFPT_BARRIER_REPLY enabling OFP_XON_XOFF"
            }
            after 1000
            set OFP_XON_XOFF 1
        }
        OFPT_ERROR {
            log local0.error "ASSERTION OFPT_ERROR disable OFP_XON_XOFF"
            set OFP_XON_XOFF 0
        }
        OFPT_PACKET_IN {
             # this is for tcl 8.4 the only way to mimic lassgin. *sigh*

             foreach { buffer_id eth_dst eth_src eth_type ipv4_src ipv4_dst } \
                 [ call parse_ofpt_packet_in $pdu ]\
                 break
             # currently unused code
         }
    }

    if { $OFP_CONN_STATE_UP && $OFP_XON_XOFF} {
        if { $static::OP_command == "proactive" } {

        set dag_rule [class startsearch sdn_scale_rules]

        set table_id 0
        set priority 1
        set idle_timeout 0
        set hard_timeout 5
        set buffer_id "\xff\xff\xff\xff"



        while {[class anymore sdn_scale_rules $dag_rule]}{
            set rule [ lindex \
                     [ lindex \
                     [class nextelement sdn_scale_rules $dag_rule] 1 ] 0 ]

            call send_pdu [ call ofp_flow_mod \
                                 $xid \
                                 $table_id \
                                 $priority \
                                 $buffer_id \
                                 $idle_timeout \
                                 $hard_timeout \
                                 [ call rule_engine $rule ] ]

        }
        class donesearch sdn_scale_rules $dag_rule

        set rules ""
        lappend  rules  { match {{ vlan_vid 2001 }} action {{ port NORMAL }} }
        lappend  rules  { match {{ vlan_vid 2002 }} action {{ port NORMAL }} }
        lappend  rules  { match {{ vlan_vid 2003 }} action {{ port NORMAL }} }

        foreach rule $rules {
            call send_pdu [ call ofp_flow_mod \
                         $xid \
                         $table_id \
                         $priority \
                         $buffer_id \
                         $idle_timeout \
                         $hard_timeout \
                         [ call rule_engine $rule ] ]
         }

         # tell the switch to notify us when he is finished processing the rules
         call send_barrier_request $xid
        }
    }

    TCP::payload replace 0 $pdulength ""
    TCP::collect
}
