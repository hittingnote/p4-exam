#include<core.p4>
#include<v1model.p4>

#define CPU_PORT    255

const bit<32> I2E_CLONE_SESSION_ID = 9;

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP = 0x06;
const bit<9>  PORT_ONE=0x1;
const bit<9>  PORT_TWO=0x2;
const bit<9>  PORT_THREE=0x3;
const bit<9>  PORT_FOUR=0x4;
const bit<1> ZERO=0;
const bit<1> one = 1;
const bit<9> CPU_MIRROR_SESSION_ID=0x9;

typedef bit<32> nhop_ipv4_t;
typedef bit<48> dmac_t;
typedef bit<9> port_t;
typedef bit<48> smac_t;


header ethernet_t{
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t{
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
//    bit<8>  floodFlags;
}
header tcp_t{
    bit<16>  srcPort;
    bit<16>  dstPort;
    bit<32>  seq;
    bit<32>  ackNumber;
    bit<4>   dataOffset;
    bit<6>   reserve;
    bit<1>   URG;
    bit<1>   ACK;
    bit<1>   PSH;
    bit<1>   RST;
    bit<1>   SYN;
    bit<1>   FIN;
    bit<16>  window;
    bit<16>  checkSum;
    bit<16>  urgentPointer;
//    bit<24>  option;
//    bit<8>  padding;
    bit<64> firstoption;
    bit<32> timestampval;
    bit<32> timestampreply;
}

struct csum_tcp_t {
    bit<32> src_ip_addr;
    bit<32> dst_ip_addr;
    bit<16> protocol;
    bit<16> tcp_len;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seq;
    bit<32> ackNumber;
    bit<16> hl;
    bit<16> window;
    bit<16> urgentPointer;
}

#define REGISTER_SIZE 32

/*
register srcAddr_register {
	width : 16;
	instance_count : REGISTER_SIZE;
}*/

struct metadata{
     bit<9> in_port;
     bit<9> out_port;
     bit<9> value;
      bit<32>nhop_ipv4;
      bit<32>srcAddr;
      bit<1>flag;
     csum_tcp_t csum_tcp_header;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

register <bit<32>>(REGISTER_SIZE) srcAddr_register;
//#############################################解析######################################3
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata){
    state start {
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP : parse_tcp;
            default : accept;
        }
    }
    
    state parse_tcp {
        packet.extract(hdr.tcp);
	
	meta.csum_tcp_header.src_ip_addr = hdr.ipv4.srcAddr;
	meta.csum_tcp_header.dst_ip_addr = hdr.ipv4.dstAddr;
	meta.csum_tcp_header.protocol = (bit<16>)hdr.ipv4.protocol;
	meta.csum_tcp_header.tcp_len = ((bit<16>)hdr.ipv4.totalLen - (bit<16>)hdr.ipv4.ihl*4) / 4;
	meta.csum_tcp_header.srcPort = hdr.tcp.srcPort;
	meta.csum_tcp_header.dstPort = hdr.tcp.dstPort;
	meta.csum_tcp_header.seq = hdr.tcp.seq;
	meta.csum_tcp_header.ackNumber = hdr.tcp.ackNumber;
//	meta.csum_tcp_header.hl = hdr.tcp.dataOffset<<12 + hdr.tcp.reserve<<6 + hdr.tcp.URG<<5 + hdr.tcp.ACK<<4 + hdr.tcp.PSH<<3 + hdr.tcp.RST<<2 + hdr.tcp.SYN<<1 + hdr.tcp.FIN;
//	meta.csum_tcp_header.hl = hdr.tcp.dataOffset*4096 + hdr.tcp.reserve*64 + hdr.tcp.URG*32 + hdr.tcp.ACK*16 + hdr.tcp.PSH*8 + hdr.tcp.RST*4 + hdr.tcp.SYN*2 + hdr.tcp.FIN;
	meta.csum_tcp_header.hl = (bit<16>)hdr.tcp.dataOffset<<12 + (bit<16>)hdr.tcp.reserve<<6 + (bit<16>)hdr.tcp.URG<<5 + (bit<16>)hdr.tcp.ACK<<4 + (bit<16>)hdr.tcp.PUSH<<3 + (bit<16>)hdr.tcp.RST<<2 + (bit<16>)hdr.tcp.SYN<<1 + (bit<16>)hdr.tcp.FIN;
	meta.csum_tcp_header.window = hdr.tcp.window;
	meta.csum_tcp_header.urgentPointer = hdr.tcp.urgentPointer;
	
        transition accept;
    }
}
//###################################################3333333
 control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
     apply {  }
}

//######################################ingress#########################################
control MyIngress (inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata){
//################action&&table########
action _drop(){
	mark_to_drop();
}
action matchYes(){
   	 meta.flag=one;
}
action matchNo(){
        meta.flag=ZERO;
}
table boundTable{//匹配绑定表，成功就让flag=one失败就让flag=zero
    key=
    {
        hdr.ipv4.srcAddr:exact;
    }
    actions = {
        matchYes;
	matchNo;
    }
    size = 1024;
    default_action = matchNo;
}
action get_port_action(){
        meta.in_port = standard_metadata.ingress_port;
}
table get_port{//让meta.in_port = standard_metadata.ingress_port;
   key={}
   actions={
        get_port_action;
}
}
action syn_action(){//在index=入端口处，存储源ip地址，然后把目的端口改成入端口，转发
    meta.value = meta.in_port % REGISTER_SIZE;
    
    srcAddr_register.write((bit<32>)meta.value, (bit<32>)hdr.ipv4.srcAddr);

    bit<32> tmp32 = hdr.ipv4.srcAddr;
    hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
    hdr.ipv4.dstAddr = tmp32;

    bit<16> tmp16 = hdr.tcp.srcPort;
    hdr.tcp.srcPort = (bit<16>)hdr.tcp.dstPort;
    hdr.tcp.dstPort = tmp16;


    hdr.tcp.ACK = 1;
    hdr.tcp.ackNumber = hdr.tcp.seq + 1;

    hdr.tcp.timestampreply = hdr.tcp.timestampval;
    hdr.tcp.timestampval = hdr.tcp.timestampval + 1;

    standard_metadata.egress_spec=standard_metadata.ingress_port;
//    standard_metadata.egress_spec = CPU_PORT;
}
table SYN{
   key={}
    actions={
        syn_action;
    }
    default_action = syn_action;
}
action ack_action(){//在index=入端口处，取出存储的IP地址
    meta.value = meta.in_port % REGISTER_SIZE;
//    srcAddr_register.read(meta.srcAddr, (bit<32>)meta.value);
}
table ACK{
   key={}
    actions={
        ack_action;
        _drop;
    }
}
//以下是传统的转发过程（抄助教的代码）
action set_nhop(nhop_ipv4_t nhop_ipv4) {
    meta.nhop_ipv4=nhop_ipv4;
    hdr.ipv4.ttl=hdr.ipv4.ttl-1;
    // modify_field(ipv4.ttl, ipv4.ttl - 1);
}

table rib {
    key={
        hdr.ipv4.dstAddr : lpm;
    }
    actions= {
        set_nhop;
        _drop;
    }
    size=1024;
}

action set_dmac(dmac_t dmac, port_t port) {
    hdr.ethernet.dstAddr=dmac;
    standard_metadata.egress_spec=port;
}

table interface {
    key={
        meta.nhop_ipv4 : exact;
    }
    actions ={
        set_dmac;
        _drop;
    }
    size =512;
}

action rewrite_mac(smac_t smac) {
    hdr.ethernet.srcAddr=smac;
}

table fib {
    key= {
        standard_metadata.egress_spec: exact;
    }
    actions ={
        rewrite_mac;
        _drop;
    }
    size =  256;
}
table dropTable{
    actions={
        _drop();
    }
}

/*
action do_copy_to_cpu() {
  standard_metadata.egress_spec = CPU_PORT;
}

table copy_to_cpu {
    key={}
    actions= {do_copy_to_cpu;}
    size =1;
    default_action = do_copy_to_cpu;
}
*/

//############################apply过程#######33
apply{
/*
	csum_tcp_header.src_ip_addr = hdr.ipv4.srcAddr;
	csum_tcp_header.dst_ip_addr = hdr.ipv4.dstAddr;
	csum_tcp_header.protocol = (bit<16>)hdr.ipv4.protocol;
	csum_tcp_header.tcp_len = (hdr.ipv4.totalLen - hdr.ipv4.ihl*4) / 4;
	csum_tcp_header.srcPort = hdr.tcp.srcPort;
	csum_tcp_header.dstPort = hdr.tcp.dstPort;
	csum_tcp_header.seq = hdr.tcp.seq;
	csum_tcp_header.ackNumber = hdr.tcp.ackNumber;
	csum_tcp_header.hl = (bit<16>)hdr.tcp.dataOffset<<12 + (bit<16>)hdr.tcp.reserve<<6 + (bit<16>)hdr.tcp.URG<<5 + (bit<16>)hdr.tcp.ACK<<4 + (bit<16>)hdr.tcp.PUSH<<3 + (bit<16>)hdr.tcp.RST<<2 + (bit<16>)hdr.tcp.SYN<<1 + (bit<16>)hdr.tcp.FIN;
	csum_tcp_header.window = hdr.tcp.window;
	csum_tcp_header.urgentPointer = hdr.tcp.urgentPointer;
*/
    if(hdr.ipv4.ttl>0){
//查看端口号，对端口号时Port_one\port_two\port_three\Port_four的端口认为他们是与客服端相连的端口，并对他们进行源地址认证
        if(standard_metadata.ingress_port==PORT_ONE || standard_metadata.ingress_port==PORT_TWO || standard_metadata.ingress_port==PORT_THREE){
            boundTable.apply();//验证绑定表
            get_port.apply();//将入端口的值从standard.ingress_port,传给meta.in_port
            if(meta.flag==ZERO){//验证绑定表失bai
                if(hdr.tcp.SYN==1){//查看是否是syn报文
                    SYN.apply();
                 }
                else if(hdr.tcp.ACK==1){//查看是否是ACK报文
                    ACK.apply();
                    if(meta.srcAddr==hdr.ipv4.srcAddr){
                      //  standard_metadata.egress_spec = CPU_PORT;
                      }
                  }
                  else{
                     dropTable.apply();
                  }
             }
            else{//验证绑定表成功，然后执行转发操作
               rib.apply();
               interface.apply();
               fib.apply();
              }
        }
       else{
            rib.apply();
              interface.apply();
              fib.apply();
        }
  }
}
}
//##########################Egress##########################
control MyEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata)
{
apply{}
}
//############################copmputerChecksum#############33
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
	     
	update_checksum_with_payload(
		hdr.tcp.isValid(),
		{
			meta.csum_tcp_header.src_ip_addr,
			meta.csum_tcp_header.dst_ip_addr,
			meta.csum_tcp_header.protocol,
			meta.csum_tcp_header.tcp_len,
			meta.csum_tcp_header.srcPort,
			meta.csum_tcp_header.dstPort,
			meta.csum_tcp_header.seq,
			meta.csum_tcp_header.ackNumber,
			meta.csum_tcp_header.hl,
			meta.csum_tcp_header.window,
			meta.csum_tcp_header.urgentPointer,
			hdr.tcp.firstoption,
			hdr.tcp.timestampval,
			hdr.tcp.timestampreply
		},
		hdr.tcp.checkSum,
		HashAlgorithm.csum16
	);

/*    bit<16> tcplen = ((bit<16>)hdr.ipv4.totalLen-(bit<16>)hdr.ipv4.ihl*4)/4;
    update_checksum_with_payload(
        hdr.tcp.isValid(),
        {
          hdr.ipv4.srcAddr,
          hdr.ipv4.dstAddr,
//          (bit<8>)0,
          (bit<16>)hdr.ipv4.protocol,
          tcplen,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.tcp.seq,
          hdr.tcp.ackNumber,
          hdr.tcp.dataOffset,
          hdr.tcp.reserve,
          hdr.tcp.URG,
          hdr.tcp.ACK,
          hdr.tcp.PSH,
          hdr.tcp.RST,
          hdr.tcp.SYN,
          hdr.tcp.FIN,
          hdr.tcp.window,
          hdr.tcp.urgentPointer,
          hdr.tcp.firstoption,
          hdr.tcp.timestampval,
          hdr.tcp.timestampreply,
          hdr.tcp.padding
        },
        hdr.tcp.checkSum,
        HashAlgorithm.csum16
    );*/
     }
 }
//#########################depaser##########################
control MyDeparser(packet_out packet, in headers hdr) {
   apply {
         packet.emit(hdr.ethernet);
         packet.emit(hdr.ipv4);
         packet.emit(hdr.tcp);
     }
 }

 V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
