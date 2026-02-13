/**
 * Source optimization for cache plugin 
 * 
 * Check if source or destination IP is in given CIDR range and optionally exclude some subranges. 
 * This is used to collect all flows to/from a specific destination into single flow record in cache and then export them together when flow is exported.
 * Main use case is when you want to limit the number of records exported and you only are intresed in where the traffic is going to/from rather than individual flows.
 * 
 * 
 * Author: Jimmy Björklund <jimmy@lolo.company>
 * 
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <vector>
#include <string>
#include "sourceOptimization.hpp"

SourceOptimization::SourceOptimization() {
    net_count = 0;
    memset(&nets,0,sizeof(nets));
}

SourceOptimization::SourceOptimization(int count, std::vector<std::string>& vnets) {
    limit = count;
    net_count = 0;
    for( size_t i=0; i < vnets.size(); i++ ) {
        std::string delimiter = ",";
		std::string token;
        std::string arg = vnets[i];
		bool main = true;
        int ext = 0;
        while ( arg.length() ) {
            size_t pos = arg.find(delimiter);
			token = arg.substr(0, pos);
            if( main ) {
                cidr_to_mask(token.c_str(), nets[net_count].cidr);
                printf("Adding network for source optimization %s\n", token.c_str());
                main = false;
            } else {
                cidr_to_mask(token.c_str(), nets[net_count].cidr_exlude[ext]);
                if( nets[net_count].cidr_exlude[ext].family != nets[net_count].cidr.family ) {
                    printf("Invalid network exclude range %s, family does not match main range.\n", token.c_str());
                    break;
                }
                
                if( nets[net_count].cidr.family == AF_INET && !ip_in_cidr(nets[net_count].cidr_exlude[ext].addr.v4, nets[net_count].cidr)) {
                    printf("Invalid network exclude range %s, need to be part of main range.\n", token.c_str());
                } else if( nets[net_count].cidr.family == AF_INET6 && !ip_in_cidr(nets[net_count].cidr_exlude[ext].addr.v6, nets[net_count].cidr)) {
                    printf("Invalid network exclude range %s, need to be part of main range.\n", token.c_str());
                } else {
                    printf("Exlude network for source optimization %s\n", token.c_str());
                }
            }
            if( pos == std::string::npos ) {
                net_count++;
                break;
            }
            arg.erase(0, pos + delimiter.length());
        }
    }
}

source_optimization_mode_t SourceOptimization::get_mode(ipxp::Packet& pkt) {
    for( int i=0; i < net_count &&  i < MAX_CIDER_NETS; i++ ) {
        if( pkt.ip_version == ipxp::IP::v4) {
            u_int32_t src_ipv4 = ntohl(pkt.src_ip.v4);
            u_int32_t dst_ipv4 = ntohl(pkt.dst_ip.v4);
            if( ip_in_cidr( src_ipv4, nets[i].cidr ) ) {
                bool excluded = false;
                for ( int j=0; j < MAX_CIDER_EXLUDE && nets[i].cidr_exlude[j].mask.v4_mask != 0; j++ ) {
                    if( ip_in_cidr( src_ipv4, nets[i].cidr_exlude[j])) {
                        excluded = true;
                        break;
                    }
                }
                return excluded ? MODE_DST : MODE_SRC;
            } else if( ip_in_cidr( dst_ipv4, nets[i].cidr)) {
                bool excluded = false;
                for ( int j=0; j < MAX_CIDER_EXLUDE && nets[i].cidr_exlude[j].mask.v4_mask != 0; j++ ) {
                    if( ip_in_cidr( dst_ipv4, nets[i].cidr_exlude[j])) {
                        excluded = true;
                        break;
                    }
                }
                return excluded ? MODE_SRC : MODE_DST;
            }
        } else {
            if( ip_in_cidr( pkt.src_ip.v6, nets[i].cidr)) {
                bool excluded = false;
                for ( int j=0; j < MAX_CIDER_EXLUDE && nets[i].cidr_exlude[j].mask.v4_mask != 0; j++ ) {
                    if( ip_in_cidr( pkt.src_ip.v6, nets[i].cidr_exlude[j])) {
                        excluded = true;
                        break;
                    }
                }
                return excluded ? MODE_DST : MODE_SRC;
            } else if( ip_in_cidr( pkt.dst_ip.v6, nets[i].cidr)) {
                bool excluded = false;
                for ( int j=0; j < MAX_CIDER_EXLUDE && nets[i].cidr_exlude[j].mask.v4_mask != 0; j++ ) {
                    if( ip_in_cidr( pkt.dst_ip.v6, nets[i].cidr_exlude[j])) {
                        excluded = true;
                        break;
                    }
                }
                return excluded ? MODE_SRC : MODE_DST;
            }
        }
    }
    return MODE_NONE;
}
    
/**
 * Convert IPv4 or IPv6 string to binary form and detect family
 * Returns family or AF_UNSPEC on error
 */
int SourceOptimization::ip_to_binary(const char *ip_str, unsigned char *out_buf, size_t buf_len) {
    if (buf_len < IP6_ADDR_LEN) return AF_UNSPEC;

    struct in_addr in4;
    if (inet_pton(AF_INET, ip_str, &in4) == 1) {
        uint32_t host_order = ntohl(in4.s_addr);           // ← add this
        memcpy(out_buf, &host_order, 4);                   // now host order
        return AF_INET;
    }

    struct in6_addr in6;
    if (inet_pton(AF_INET6, ip_str, &in6) == 1) {
        memcpy(out_buf, in6.s6_addr, IP6_ADDR_LEN);        // IPv6 is always network order, but we treat as opaque
        return AF_INET6;
    }
    return AF_UNSPEC;
}

/**
 * Parse CIDR string "ip/prefix" into cidr_mask
 * Returns true on success
 */
bool SourceOptimization::cidr_to_mask(const char *cidr_str, cidr_mask& out) {
    if (!cidr_str ) return false;

    char ip_part[128];  // large enough for IPv6
    int prefix = -1;

    if (sscanf(cidr_str, "%127[^/]/%d", ip_part, &prefix) != 2) {
        return false;
    }

    if (prefix < 0) return false;

    unsigned char addr_buf[IP6_ADDR_LEN];
    int family = ip_to_binary(ip_part, addr_buf, sizeof(addr_buf));

    if (family == AF_UNSPEC) {
        return false;
    }

    out.family = family;

    if (family == AF_INET) {
        if (prefix > 32) return false;
        memcpy(&out.addr.v4, addr_buf, 4);

        if (prefix == 0) {
            out.mask.v4_mask = 0;
        } else {
            out.mask.v4_mask = 0xFFFFFFFFU << (32 - prefix);
        }
    } else { // IPv6
        if (prefix > 128) return false;
        memcpy(out.addr.v6, addr_buf, IP6_ADDR_LEN);

        // Build IPv6 mask: first 'prefix' bits set to 1
        memset(out.mask.v6_mask, 0, IP6_ADDR_LEN);
        int full_bytes = prefix / 8;
        int remain_bits = prefix % 8;

        memset(out.mask.v6_mask, 0xFF, full_bytes);

        if (remain_bits > 0 && full_bytes < IP6_ADDR_LEN) {
            out.mask.v6_mask[full_bytes] = (0xFF << (8 - remain_bits)) & 0xFF;
        }
    }
    return true;
}

/**
 * Check if ip_str is inside the given CIDR
 * Returns true if it matches
 */
bool SourceOptimization::ip_in_cidr(const char *ip_str, const cidr_mask& cidr) {

    unsigned char ip_buf[IP6_ADDR_LEN];
    int family = ip_to_binary(ip_str, ip_buf, sizeof(ip_buf));

    if (family == AF_UNSPEC ) {
        printf("Invalid family\n");
        return false;
    }
    if( family != cidr.family ) {
        return false;
    }
    if (family == AF_INET) {
        uint32_t ip = *(uint32_t*)ip_buf;
        return ip_in_cidr(ip, cidr);
    } 
    // IPv6
    // Compare byte-by-byte after applying mask
    return ip_in_cidr(ip_buf, cidr);
}
bool SourceOptimization::ip_in_cidr(uint32_t ipv4, const cidr_mask& cidr) {
    return (ipv4 & cidr.mask.v4_mask) == (cidr.addr.v4 & cidr.mask.v4_mask);
}
bool SourceOptimization::ip_in_cidr(unsigned char ipv6[IP6_ADDR_LEN], const cidr_mask& cidr) {
    // Compare byte-by-byte after applying mask
    for (int i = 0; i < IP6_ADDR_LEN; i++) {
        if ((ipv6[i] & cidr.mask.v6_mask[i]) != (cidr.addr.v6[i] & cidr.mask.v6_mask[i])) {
            return false;
        }
    }
    return true;
}

/* -------------------------------------------------------------------------- 

int main(void) {
    // Test IPs - mix of v4 and v6
    const char *test_ips[] = {
        "10.0.0.5",
        "10.0.1.23",
        "2001:db8::1",
        "2001:db8:abcd::ff",
        "2001:db9::1",
        "fe80::1",
        "192.168.100.10",
    };

    printf("Testing IP in CIDR (IPv4 + IPv6):\n");
    printf("==================================\n");

    SourceOptimization range;

    // Example: IPv4 range + exclusion
    if (!range.cidr_to_mask("10.0.0.0/8", range.nets[0].cidr)) {
        printf("Failed to parse main CIDR\n");
        return 1;
    }
    if (!range.cidr_to_mask("10.0.1.0/24", range.nets[0].cidr_exlude[0])) {
        printf("Failed to parse exclude CIDR\n");
        return 1;
    }

    // Example: IPv6 range + exclusion
    // Uncomment to test IPv6
    //
    //if (!cidr_to_mask("2001:db8::/32", &range.cidr)) {
    //    printf("Failed to parse IPv6 CIDR\n");
    //    return 1;
    //}
    //if (!cidr_to_mask("2001:db8:abcd::/48", &range.cidr_exclude[0])) {
    //    printf("Failed to parse IPv6 exclude\n");
    //    return 1;
    //}    

    for (size_t i = 0; i < sizeof(test_ips) / sizeof(test_ips[0]); i++) {
        const char *result = "OUTSIDE";

        if (range.ip_in_cidr(test_ips[i], range.nets[0].cidr)) {
            result = "IN RANGE";

            for (int j = 0; j < MAX_CIDER_EXLUDE; j++) {
                if (range.nets[0].cidr_exlude[j].mask.v4_mask == 0) break;

                if (range.ip_in_cidr(test_ips[i], range.nets[0].cidr_exlude[j])) {
                    result = "EXCLUDED";
                    break;
                }
            }
        }

        printf("%-30s → %s\n", test_ips[i], result);
    }

    return 0;
}

*/