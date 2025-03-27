package fastpkt

// <linux/if_ether.h>
//
//	struct ethhdr {
//	    unsigned char h_dest[6];
//	    unsigned char h_source[6];
//	    __be16 h_proto;
//	};

type EthHeader struct {
	HwDest   [6]byte
	HwSource [6]byte
	HwProto  uint16
}

// <linux/if_vlan.h>
//
//	struct vlan_hdr {
//	    __be16 h_vlan_TCI;
//	    __be16 h_vlan_encapsulated_proto;
//	};

type VLANHeader struct {
	ID                uint16
	EncapsulatedProto uint16
}

// <linux/if_arp.h>
//
// struct arphdr {
//     __be16 ar_hrd;        /* format of hardware address	*/
//     __be16 ar_pro;        /* format of protocol address	*/
//     unsigned char ar_hln; /* length of hardware address	*/
//     unsigned char ar_pln; /* length of protocol address	*/
//     __be16 ar_op;         /* ARP opcode (command)		*/
// };

type ARPHeader struct {
	HwAddrType   uint16
	ProtAddrType uint16
	HwAddrLen    uint8
	ProtAddrLen  uint8
	Operation    uint16
}
