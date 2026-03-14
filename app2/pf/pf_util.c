// cidr_utils.c

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/ioccom.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/pfvar.h>
#include <netpfil/pf/pf.h>

#define NATPASS     1
#define ALLTABLE    -1

typedef struct filter_addr_t{
    uint8_t type;
    char addr[MAXPATHLEN];
} filter_addr;

/*
*/
int ruleset_exists(int dev, char* anchor, int action )
{
    struct pfioc_ruleset pr={0};
    strlcpy(pr.path, anchor, sizeof(pr.path));
    if(ioctl(dev, DIOCGETRULESETS, &pr)<0)
    {
        perror("DIOCGETRULESETS");
        return  0;
    }
    printf("Anchor %s Exists\n", anchor);
    return 1;
}

/*
* Clear rdr ruleset under `anchor`
*/
int clear_ruleset(int dev, char* anchor)
{
    printf("Clearing nat ruleset\n");
    clear_nat_ruleset();
    printf("Clearing rdr ruleset\n");
    clear_rdr_ruleset();
    printf("Clearing pass ruleset\n");
    clear_pass_ruleset();
    printf("Ruleset %s cleared succesfully\n");
}

int clear_nat_ruleset(int dev, char* anchor)
{
    struct pfioc_trans pt = {0};
    struct pfioc_trans_e pte = {0};
    pt.size = 1;
    pt.esize = sizeof(pte);
    pt.array = &pte;

    pte.rs_num = PF_RULESET_NAT;
    strlcpy(pte.anchor, anchor, sizeof(pte.anchor));
    
    if (ioctl(dev, DIOCXBEGIN, &pt) < 0) {
        perror("DIOCXBEGIN");
        return 1;
    }


    if (ioctl(dev, DIOCXCOMMIT, &pt) < 0) 
    {
        perror("DIOCXCOMMIT");
        return 1;
    }
    return 0;
}

int clear_rdr_ruleset(int dev, char* anchor)
{
    struct pfioc_trans pt = {0};
    struct pfioc_trans_e pte = {0};
    pt.size = 1;
    pt.esize = sizeof(pte);
    pt.array = &pte;

    pte.rs_num = PF_RULESET_RDR;
    strlcpy(pte.anchor, anchor, sizeof(pte.anchor));
    
    if (ioctl(dev, DIOCXBEGIN, &pt) < 0) {
        perror("DIOCXBEGIN");
        return 1;
    }


    if (ioctl(dev, DIOCXCOMMIT, &pt) < 0) 
    {
        perror("DIOCXCOMMIT");
        return 1;
    }
    return 0;
}

int clear_pass_ruleset(int dev, char* anchor)
{
    struct pfioc_trans pt = {0};
    struct pfioc_trans_e pte = {0};
    pt.size = 1;
    pt.esize = sizeof(pte);
    pt.array = &pte;

    pte.rs_num = PF_RULESET_PASS;
    strlcpy(pte.anchor, anchor, sizeof(pte.anchor));
    
    if (ioctl(dev, DIOCXBEGIN, &pt) < 0) {
        perror("DIOCXBEGIN");
        return 1;
    }


    if (ioctl(dev, DIOCXCOMMIT, &pt) < 0) 
    {
        perror("DIOCXCOMMIT");
        return 1;
    }
    return 0;
}

/*
* convert cidr int to 32 bit mask
*/
uint32_t cidr_to_mask(int cidr)
{
    return  htonl(0xFFFFFFFF << (32 - cidr));
}

/*
* Return ip/mask
*/
char* pf_print_addr(struct pf_addr_wrap * addr)
{
    int n = 0;
    char *mask_str, *ip_str;
    static char ip_mask[128];
    ip_str = inet_ntoa(addr->v.a.addr.v4);
    n = snprintf(ip_mask, 128, "%s/", ip_str);
    mask_str = inet_ntoa(addr->v.a.mask.v4);
    snprintf(ip_mask+n, 128-n, "%s", mask_str);
    return ip_mask;
}



/*
* Function to print address 
* Input: struct pf_addr_wrap* paddr
*/
void print_rdr_address(struct pf_addr_wrap* paddr)
{
    switch (paddr->type) {
        case PF_ADDR_ADDRMASK:
            printf("%s\n", pf_print_addr(paddr));
            break;
        
        case PF_ADDR_TABLE:
            printf("<%s>\n", paddr->v.tblname);
            break;
        case PF_ADDR_DYNIFTL:
            printf("(%s)\n", paddr->v.ifname);
            break;
        default:
            printf("Unknown type\n");
            break;
    }

}



int fill_pf_addr_and_mask(const char* cidr_str, struct pf_addr_wrap* out) 
{
    char ip_str[INET6_ADDRSTRLEN];
    int prefix = -1, i =0, is_ipv6;
    uint32_t mask; const char* slash;

    if (!cidr_str || !out) return -1;
    slash = strchr(cidr_str, '/');

    if (slash) 
    {
        size_t len = slash - cidr_str;
        if (len >= sizeof(ip_str)) return -1;
        strncpy(ip_str, cidr_str, len);
        ip_str[len] = '\0';
        prefix = atoi(slash + 1);
    } else 
    {
        strncpy(ip_str, cidr_str, sizeof(ip_str) - 1);
        ip_str[sizeof(ip_str) - 1] = '\0';
        prefix = strchr(ip_str, ':') ? 128 : 32;
    }

    is_ipv6 = strchr(ip_str, ':') != NULL;

    if (is_ipv6) 
    {
        if (inet_pton(AF_INET6, ip_str, &out->v.a.addr.v6) != 1) 
        {
            fprintf(stderr, "Invalid IPv6 address: %s\n", ip_str);
            return -1;
        }

        memset(&out->v.a.mask.v6, 0, sizeof(struct in6_addr));
        for (i = 0; i < 16; ++i) 
        {
            if (prefix >= 8) {
                out->v.a.mask.addr8[i] = 0xFF;
                prefix -= 8;
            } else if (prefix > 0) {
                out->v.a.mask.addr8[i] = (0xFF << (8 - prefix)) & 0xFF;
                prefix = 0;
            } else {
                out->v.a.mask.addr8[i] = 0x00;
            }
        }

    } else 
    {
        if (inet_pton(AF_INET, ip_str, &out->v.a.addr.v4) != 1) {
            fprintf(stderr, "Invalid IPv4 address: %s\n", ip_str);
            return -1;
        }

        mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
        out->v.a.mask.v4.s_addr = htonl(mask);
    }
    return 0;
}

int append_rdr_rule(int dev, char* if_name, char* anchor, char* src, int src_port, char* dst, int dst_port,
                char** rdr, int rdr_count, int d_port, int proto)
{
    struct pfioc_rule pr;
    u_int32_t ticket, pool_ticket;
    struct pf_rule* r;
    struct pfioc_pooladdr paddr = {0};
    int i=0;


    memset(&pr, 0, sizeof(pr));
    pr.action = PF_CHANGE_GET_TICKET;
    pr.rule.action = PF_RDR;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
    if (ioctl(dev, DIOCCHANGERULE, &pr) < 0) 
    {
        perror("ioctl get ticket");
        return 1;
    }

    ticket = pr.ticket;
    memset(&paddr, 0, sizeof(struct pfioc_pooladdr));
    strlcpy(paddr.anchor, anchor, sizeof(paddr.anchor));
    if (ioctl(dev, DIOCBEGINADDRS, &paddr) < 0) 
    {
        perror("DIOCBEGINADDRS");
        return 1;
    }

    pool_ticket = paddr.ticket;
    for(i=0;  i<rdr_count; i++)
    {
        paddr.addr.addr.type = PF_ADDR_ADDRMASK;
        if (fill_pf_addr_and_mask(rdr[i], &paddr.addr.addr) < 0) {
            fprintf(stderr, "Failed to parse rdr address\n");
            return 1;
        }
    

        if (ioctl(dev, DIOCADDADDR, &paddr) < 0) {
            perror("DIOCADDADDR");
            return 1;
        }    
    }

    
    pr.ticket = ticket;
    pr.pool_ticket = pool_ticket;
    pr.action = PF_CHANGE_ADD_TAIL;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));

    r = &pr.rule;
    r->action = PF_RDR ;
    r->af = AF_INET;
    r->proto = proto;
    r->direction = PF_INOUT;
    r->natpass = 1;
    r->rtableid = -1;
    strlcpy(r->ifname, if_name, sizeof(r->ifname));
    

    if(dst_port >0)
    {
        r->dst.port_op = PF_OP_EQ;
        r->dst.port[0] = htons(dst_port);  
    }
    else{
        r->dst.port_op = PF_OP_NONE;        
    }
    
    if(src_port >0)
    {
        r->src.port_op = PF_OP_EQ;
        r->src.port[0] = htons(src_port);  
    }
    else{
        r->src.port_op = PF_OP_NONE;        
    }
    
    r->rpool.proxy_port[0] = d_port; 
    r->rpool.opts          = PF_POOL_ROUNDROBIN;              


    if (fill_pf_addr_and_mask(src, &r->src.addr) < 0 ||
        fill_pf_addr_and_mask(dst, &r->dst.addr) < 0) {
        fprintf(stderr, "Failed to parse source or destination address\n");
        return 1;
    }

    
    if (ioctl(dev, DIOCCHANGERULE, &pr) < 0) {
        perror("ioctl add_rule");
        return 1;
    }

    printf("Rule appended successfully.\n");
    return 0;
}

int add_rdr_rule(int dev, char* if_name, char* anchor, char* src, int src_port, char* dst, int dst_port,
                char** rdr, int rdr_count, int d_port, int proto)
{
    struct pfioc_pooladdr paddr = {0};
    struct pfioc_trans pt = {0};
    struct pfioc_rule pr = {0};
    struct pfioc_trans_e pte = {0};
    struct pf_rule *r;
    int i=0;
    pt.size = 1;
    pt.esize = sizeof(pte);
    pt.array = &pte;

    pte.rs_num = PF_RULESET_RDR;
    strlcpy(pte.anchor, anchor, sizeof(pte.anchor));
    
    if (ioctl(dev, DIOCXBEGIN, &pt) < 0) {
        perror("DIOCXBEGIN");
        return 1;
    }

    
    if (ioctl(dev, DIOCBEGINADDRS, &paddr) < 0) {
        perror("DIOCBEGINADDRS");
        return 1;
    }

    for(i=0;  i<rdr_count; i++)
    {
        paddr.addr.addr.type = PF_ADDR_ADDRMASK;
        paddr.addr.ifname[0] = '\0';
        if (fill_pf_addr_and_mask(rdr[i], &paddr.addr.addr) < 0) {
            fprintf(stderr, "Failed to parse rdr address\n");
            return 1;
        }
    

        if (ioctl(dev, DIOCADDADDR, &paddr) < 0) {
            perror("DIOCADDADDR");
            return 1;
        }    
    }
    
    pr.ticket = pte.ticket;
    pr.pool_ticket = paddr.ticket;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
    
    r            = &pr.rule;
    r->action    = PF_RDR ;
    r->af        = AF_INET;
    r->proto     = proto;
    r->direction = PF_INOUT;
    r->natpass   = NATPASS;
    r->rtableid  = ALLTABLE;
    r->dst.addr.type = PF_ADDR_ADDRMASK;
    r->src.addr.type = PF_ADDR_ADDRMASK;
    strlcpy(r->ifname, if_name, sizeof(r->ifname));

    if(dst_port >0)
    {
        
        r->dst.port_op = PF_OP_EQ;
        r->dst.port[0] = htons(dst_port);  
    }
    else{
        r->dst.port_op = PF_OP_NONE;        
    }
    
    if(src_port >0)
    {
        r->src.port_op = PF_OP_EQ;
        r->src.port[0] = htons(src_port);  
    }
    else{
        r->src.port_op = PF_OP_NONE;        
    }
    
    r->rpool.proxy_port[0] = d_port; 
    r->rpool.opts          = PF_POOL_ROUNDROBIN;              


    if (fill_pf_addr_and_mask(src, &r->src.addr) < 0 ||
        fill_pf_addr_and_mask(dst, &r->dst.addr) < 0) {
        fprintf(stderr, "Failed to parse source or destination address\n");
        return 1;
    }
    
    if (ioctl(dev, DIOCADDRULE, &pr) < 0) 
    {
        perror("DIOCADDRULE");
        return 1;
    }

    if (ioctl(dev, DIOCXCOMMIT, &pt) < 0) 
    {
        perror("DIOCXCOMMIT");
        return 1;
    }
    return 0;
}

int add_rdr_rule_if(int dev, char* if_name, char* anchor, char* src, int src_port, char* dst, int dst_port,
                char* rdr_if, int d_port, int proto)
{
    struct pfioc_pooladdr paddr = {0};
    struct pfioc_trans pt = {0};
    struct pfioc_rule pr = {0};
    struct pfioc_trans_e pte = {0};
    struct pf_rule *r;
    pt.size = 1;
    pt.esize = sizeof(pte);
    pt.array = &pte;

    printf("Adding RDR Rule for %s\n", if_name);
    pte.rs_num = PF_RULESET_RDR;
    strlcpy(pte.anchor, anchor, sizeof(pte.anchor));
    
    if (ioctl(dev, DIOCXBEGIN, &pt) < 0) {
        perror("DIOCXBEGIN");
        return 1;
    }

    
    if (ioctl(dev, DIOCBEGINADDRS, &paddr) < 0) {
        perror("DIOCBEGINADDRS");
        return 1;
    }

    paddr.addr.addr.type = PF_ADDR_DYNIFTL;
    paddr.addr.ifname[0] = '\0';
    strlcpy(paddr.addr.addr.v.ifname, rdr_if, sizeof(paddr.addr.addr.v.ifname));
    paddr.addr.addr.v.a.mask.v4.s_addr = 0xffffffff;

    if (ioctl(dev, DIOCADDADDR, &paddr) < 0) {
        perror("DIOCADDADDR");
        return 1;
    }    
    
    
    pr.ticket = pte.ticket;
    pr.pool_ticket = paddr.ticket;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
    
    r            = &pr.rule;
    r->action    = PF_RDR ;
    r->af        = AF_INET;
    r->proto     = proto;
    r->direction = PF_INOUT;
    r->natpass   = NATPASS;
    r->rtableid  = ALLTABLE;
    r->dst.addr.type = PF_ADDR_ADDRMASK;
    r->src.addr.type = PF_ADDR_ADDRMASK;
    strlcpy(r->ifname, if_name, sizeof(r->ifname));

    if(dst_port >0)
    {
        
        r->dst.port_op = PF_OP_EQ;
        r->dst.port[0] = htons(dst_port);  
    }
    else{
        r->dst.port_op = PF_OP_NONE;        
    }
    
    if(src_port >0)
    {
        r->src.port_op = PF_OP_EQ;
        r->src.port[0] = htons(src_port);  
    }
    else{
        r->src.port_op = PF_OP_NONE;        
    }
    
    r->rpool.proxy_port[0] = d_port; 
    r->rpool.opts          = PF_POOL_ROUNDROBIN;              


    if (fill_pf_addr_and_mask(src, &r->src.addr) < 0 ||
        fill_pf_addr_and_mask(dst, &r->dst.addr) < 0) {
        fprintf(stderr, "Failed to parse source or destination address\n");
        return 1;
    }
    
    if (ioctl(dev, DIOCADDRULE, &pr) < 0) 
    {
        perror("DIOCADDRULE");
        return 1;
    }

    if (ioctl(dev, DIOCXCOMMIT, &pt) < 0) 
    {
        perror("DIOCXCOMMIT");
        return 1;
    }
    return 0;
}


/**
 * New function: Print IP/CIDR from sockaddr*
 */
void print_cidr_from_sockaddr(const struct sockaddr *ip, const struct sockaddr *netmask) {
    if (!ip || !netmask) {
        printf("Invalid input\n");
        return;
    }

    const struct sockaddr_in *ip_in = (const struct sockaddr_in *)ip;
    const struct sockaddr_in *mask_in = (const struct sockaddr_in *)netmask;

    char ip_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &ip_in->sin_addr, ip_str, sizeof(ip_str))) {
        perror("inet_ntop");
        return;
    }

    // Convert netmask to prefix length
    uint32_t mask = ntohl(mask_in->sin_addr.s_addr);
    int prefix_len = 0;

    for (int i = 31; i >= 0; i--) {
        if (mask & (1U << i)) {
            prefix_len++;
        } else {
            break;
        }
    }

    printf("%s/%d\n", ip_str, prefix_len);
}



/*
 * compare_cidr - Compare network a/a_mask with cidr_str
 *
 * Returns:
 *   -1 if a/a_mask < cidr_str
 *    0 if cidr_str is inside a/a_mask (or equal)
 *    1 if a/a_mask > cidr_str
 */
int compare_cidr(in_addr_t a, in_addr_t a_mask, const char *cidr_str)
{
    char addr_buf[64];
    char *slash;
    int prefix_len;
    struct in_addr cidr_ip;

    uint32_t cidr_mask;
    uint32_t a_host, a_mask_host;
    uint32_t cidr_host, cidr_mask_host;
    uint32_t a_network, cidr_network;
    uint32_t a_broadcast;
    uint32_t cidr_start, cidr_end;

    /* Copy and parse the CIDR string */
    strncpy(addr_buf, cidr_str, sizeof(addr_buf));
    addr_buf[sizeof(addr_buf) - 1] = '\0';

    slash = strchr(addr_buf, '/');
    prefix_len = 32; /* default if / not given */

    if (slash) {
        *slash = '\0';
        prefix_len = atoi(slash + 1);
        if (prefix_len < 0 || prefix_len > 32) {
            fprintf(stderr, "Invalid prefix length: %d\n", prefix_len);
            return 0;
        }
    }

    if (inet_pton(AF_INET, addr_buf, &cidr_ip) != 1) {
        fprintf(stderr, "Invalid CIDR IP: %s\n", addr_buf);
        return 0;
    }

    /* Build mask for CIDR */
    if (prefix_len == 0)
        cidr_mask = 0;
    else
        cidr_mask = htonl(0xFFFFFFFF << (32 - prefix_len));

    /* Convert to host byte order for arithmetic */
    a_host         = ntohl(a);
    a_mask_host    = ntohl(a_mask);
    cidr_host      = ntohl(cidr_ip.s_addr);
    cidr_mask_host = ntohl(cidr_mask);

    /* Compute network and broadcast addresses */
    a_network   = a_host & a_mask_host;
    a_broadcast = a_network | (~a_mask_host);
    cidr_network = cidr_host & cidr_mask_host;

    /* Containment check */
    cidr_start = cidr_network;
    cidr_end   = cidr_network | (~cidr_mask_host);

    if (cidr_start >= a_network && cidr_end <= a_broadcast)
        return 0; /* inside */

    /* Numeric comparison */
    if (a_network > cidr_network)
        return 1;
    else if (a_network < cidr_network)
        return -1;
    else
        return 0;
}

int add_address_to_pool(int dev, const char* cidr_str, const char* path, int pos, int ticket, int r_num)
{
    
    struct pfioc_pooladdr paddr = {0};
    if(!cidr_str) {
        printf("cidr string cannot be null");
        return -1;
    }
    
    memset(&paddr, 0, sizeof(paddr));
    paddr.r_action = PF_RDR;
    paddr.r_num =r_num;
    paddr.ticket = ticket;
    paddr.af = AF_INET;
    if(pos == 0) {
        paddr.action = PF_CHANGE_ADD_HEAD;	
        paddr.nr = 0;
        printf("Action: PF_CHANGE_ADD_HEAD\n");
    }else if (pos==-1) {
        paddr.action = PF_CHANGE_ADD_TAIL;	
        paddr.nr = 0;
        printf("Action: PF_CHANGE_ADD_TAIL\n");
    } else {
        paddr.action = PF_CHANGE_ADD_BEFORE;	
        paddr.nr = pos;
        printf("Action: PF_CHANGE_ADD_BEFORE\n");
    }

    strlcpy(paddr.anchor, path, sizeof(paddr.anchor));
    if(fill_pf_addr_and_mask(cidr_str, &paddr.addr.addr)){
        printf("Failed to parse adddress\n");
        return -1;
    }

    if (ioctl(dev, DIOCCHANGEADDR, &paddr) < 0) {
        perror("DIOCCHANGEADDR");
        return -1;
    }

    return 0;
}


int remove_address_from_pool(int dev, const char* cidr_str, const char* path, int pos, int ticket, int r_num)
{
    
    struct pfioc_pooladdr paddr = {0};
    if(!cidr_str) {
        printf("cidr string cannot be null");
        return -1;
    }
    
    memset(&paddr, 0, sizeof(paddr));
    paddr.r_action = PF_RDR;
    paddr.r_num =r_num;
    paddr.ticket = ticket;
    paddr.af = AF_INET;
    paddr.action = PF_CHANGE_REMOVE;	
    paddr.nr = pos;
    strlcpy(paddr.anchor, path, sizeof(paddr.anchor));
    if(fill_pf_addr_and_mask(cidr_str, &paddr.addr.addr)){
        printf("Failed to parse adddress\n");
        return -1;
    }

    if (ioctl(dev, DIOCCHANGEADDR, &paddr) < 0) {
        perror("DIOCCHANGEADDR");
        return -1;
    }
    return 0;
}



int add_addressList_to_pool(int dev, char* path, int r_num, char* addrList[], int n_addr)
{
    int cmp, total, ticket, nr, i, j, res, fetch=1;
    struct pfioc_pooladdr paddr;
    struct pfioc_rule pr;

    if (!addrList || n_addr ==0 ){
        printf("AddrList cannot be null");
        return -1;
    }

    memset(&pr, 0, sizeof(pr));
    pr.action = PF_CHANGE_GET_TICKET;
    pr.rule.action= PF_RDR;
    strlcpy(pr.anchor, path, sizeof(pr.anchor));
    if (ioctl(dev, DIOCCHANGERULE, &pr) < 0) 
    {
        perror("ioctl get ticket");
        return -1;
    }
    ticket = pr.ticket;
    printf("Got Ticket (pr): %d\n", ticket);

    /*
    * Get Existing Address count for rule
    */
    memset(&paddr, 0, sizeof(paddr));
    paddr.r_action = PF_RDR;
    strncpy(paddr.anchor, path, sizeof(paddr.anchor) - 1);
    paddr.r_num = r_num; 
    if (ioctl(dev, DIOCGETADDRS, &paddr) < 0) {
        perror("ioctl DIOCGETADDRS");
        return 1;
    }
    /* 
    * Request success
    * Iterate over existing address and insert 
    * address before the address bigger than current address
    * Or at end
    */
    nr = paddr.nr;
    total = nr;

    i=0;
    j=0;
    fetch =1;

    while(i< total && j < n_addr)
    {
        paddr.nr = i;
        paddr.ticket = ticket;
        /*
        * Fetch only if current address is used 
        * else reuse same address for comparison
        */
        if(fetch)
        {
            if (ioctl(dev, DIOCGETADDR, &paddr) < 0) {
                perror("ioctl DIOCGETADDR");
                return  -1;
            }
            printf("Got address (%d): ", i );
            print_rdr_address(&paddr.addr.addr);
        }
        
        printf("Adding %s to pool\n", addrList[j]);
        cmp = compare_cidr(paddr.addr.addr.v.a.addr.v4.s_addr, 
            paddr.addr.addr.v.a.mask.v4.s_addr, 
            addrList[j]
        );

        if(cmp<0)
        {
                i++;
                fetch = 1;
        } else if (cmp ==0) {
            /*
            * Goto next address in both new addresses and already present addresses
            * Set fetch = 1 
            */
            i++;
            j++;
            fetch =1;
        } else{
            /*
            * Add before present[i], addrList[j]
            * Increase total : total++
            * Increase next insert address pointer: j++
            * increase i as inserts will move present[i] to present[i+1]: i++
            */
            res = add_address_to_pool(dev, addrList[j], path, i, ticket, r_num);
            if(res < 0){
                printf("Failed to add address %s\n", addrList[i]);
                return  -1;;
            }
            total++;
            i++;
            j++;
            fetch = 0;
            
        }
    }
    
    while(j < n_addr )
    {
        
        res = add_address_to_pool(dev, addrList[j], path, -1, ticket, r_num);
        if(res < 0){
            printf("Failed to add address %s\n", addrList[j]);
            return -1;
        }
        j++;
            
    }
    return 0;
}

/*
* Remove a list of address from address pool of the rdr rule
*/
int remove_addressList_from_pool(int dev, char* path, int r_num, char* addrList[], int n_addr)
{
    int cmp, total, ticket, nr, i, j, fetch=1;
    struct pfioc_pooladdr paddr;
    struct pfioc_rule pr;

    if (!addrList || n_addr ==0 ){
        printf("AddrList cannot be null");
        return -1;
    }

    memset(&pr, 0, sizeof(pr));
    pr.action = PF_CHANGE_GET_TICKET;
    pr.rule.action= PF_RDR;
    strlcpy(pr.anchor, path, sizeof(pr.anchor));
    if (ioctl(dev, DIOCCHANGERULE, &pr) < 0) 
    {
        perror("ioctl get ticket");
        return -1;
    }
    ticket = pr.ticket;
    printf("Got Ticket (pr): %d\n", ticket);

    /*
    * Get Existing Address count for rule
    */
    memset(&paddr, 0, sizeof(paddr));
    paddr.r_action = PF_RDR;
    strncpy(paddr.anchor, path, sizeof(paddr.anchor) - 1);
    paddr.r_num = r_num; 
    if (ioctl(dev, DIOCGETADDRS, &paddr) < 0) {
        perror("ioctl DIOCGETADDRS");
        return 1;
    }

    /* 
    * Request success
    * Iterate over existing address and remove address
    */
    nr = paddr.nr;
    total = nr;

    i=0;
    j=0;
    fetch =1;

    while(i< total && j < n_addr)
    {
        paddr.nr = i;
        paddr.ticket = ticket;
        /*
        * Fetch only if current address is used 
        * else reuse same address for comparison
        */
        if(fetch)
        {
            if (ioctl(dev, DIOCGETADDR, &paddr) < 0) {
                perror("ioctl DIOCGETADDR");
                return  -1;
            }
            printf("Got address (%d): ", i );
            print_rdr_address(&paddr.addr.addr);
        }
        
        printf("Removing %s from pool\n", addrList[j]);
        cmp = compare_cidr(paddr.addr.addr.v.a.addr.v4.s_addr, 
            paddr.addr.addr.v.a.mask.v4.s_addr, 
            addrList[j]
        );

        if(cmp<0)
        {
                i++;
                fetch = 1;
        } else if (cmp ==0) {
            /*
            * Remove this address
            * Set fetch = 1 
            * j++
            * total--
            */
            if(remove_address_from_pool(dev, addrList[j], path, i, ticket, r_num)<0)
            {
                printf("Failed to remove address %s\n", addrList[j]);
                return -1;
            }
            j++;
            fetch =1;
        } else{
            /*
            * Move to next address in address list
            * This address is not present
            * Set fetch = 0 as current address is less than addr[j]
            */
            j++;
            fetch = 0;
        }
    }    
    return 0;
}

int append_rdr_rule_src_if(int dev, char* if_name, char* anchor, filter_addr* src, int src_port, filter_addr* dst, int dst_port,
                char** rdr, int rdr_count, int d_port, int proto)
{
    struct pfioc_rule pr;
    u_int32_t ticket, pool_ticket;
    struct pf_rule* r;
    struct pfioc_pooladdr paddr = {0};
    int i=0;


    memset(&pr, 0, sizeof(pr));
    pr.action = PF_CHANGE_GET_TICKET;
    pr.rule.action = PF_RDR;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
    if (ioctl(dev, DIOCCHANGERULE, &pr) < 0) 
    {
        perror("ioctl get ticket");
        return 1;
    }

    ticket = pr.ticket;
    memset(&paddr, 0, sizeof(struct pfioc_pooladdr));
    strlcpy(paddr.anchor, anchor, sizeof(paddr.anchor));
    if (ioctl(dev, DIOCBEGINADDRS, &paddr) < 0) 
    {
        perror("DIOCBEGINADDRS");
        return 1;
    }

    pool_ticket = paddr.ticket;
    for(i=0;  i<rdr_count; i++)
    {
        paddr.addr.addr.type = PF_ADDR_ADDRMASK;
        if (fill_pf_addr_and_mask(rdr[i], &paddr.addr.addr) < 0) {
            fprintf(stderr, "Failed to parse rdr address\n");
            return 1;
        }
    

        if (ioctl(dev, DIOCADDADDR, &paddr) < 0) {
            perror("DIOCADDADDR");
            return 1;
        }    
    }

    
    pr.ticket = ticket;
    pr.pool_ticket = pool_ticket;
    pr.action = PF_CHANGE_ADD_TAIL;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));

    r = &pr.rule;
    r->action = PF_RDR ;
    r->af = AF_INET;
    r->proto = proto;
    r->direction = PF_INOUT;
    r->natpass = 1;
    r->rtableid = -1;
    strlcpy(r->ifname, if_name, sizeof(r->ifname));
    

    if(dst_port >0)
    {
        r->dst.port_op = PF_OP_EQ;
        r->dst.port[0] = htons(dst_port);  
    }
    else{
        r->dst.port_op = PF_OP_NONE;        
    }
    
    if(src_port >0)
    {
        r->src.port_op = PF_OP_EQ;
        r->src.port[0] = htons(src_port);  
    }
    else{
        r->src.port_op = PF_OP_NONE;        
    }
    
    r->rpool.proxy_port[0] = d_port; 
    r->rpool.opts          = PF_POOL_ROUNDROBIN;              

    if(src->type == PF_ADDR_ADDRMASK)
    {
        if (fill_pf_addr_and_mask(src->addr, &r->src.addr) < 0) {
            fprintf(stderr, "Failed to parse rdr address\n");
            return 1;
        }        
        r->src.addr.type = PF_ADDR_ADDRMASK;
    }
    else if (src->type == PF_ADDR_DYNIFTL) {
        strlcpy(r->src.addr.v.ifname, src->addr, sizeof(r->src.addr.v.ifname));
        r->src.addr.type = PF_ADDR_DYNIFTL;
        r->src.addr.v.a.mask.v4.s_addr = 0xffffffff;
    }
    else if(src->type == PF_ADDR_TABLE){
        strlcpy(r->src.addr.v.tblname, src->addr, sizeof(r->src.addr.v.tblname));
        r->src.addr.type = PF_ADDR_TABLE;
        r->src.addr.v.a.mask.v4.s_addr = 0xffffffff;
    }
    else{
        printf("Invalid Address type\n");
        return 1;
    }

    if(dst->type == PF_ADDR_ADDRMASK)
    {
        if (fill_pf_addr_and_mask(dst->addr, &r->dst.addr) < 0) {
            fprintf(stderr, "Failed to parse rdr address\n");
            return 1;
        }        
        r->dst.addr.type = PF_ADDR_ADDRMASK;
    }
    else if (dst->type == PF_ADDR_DYNIFTL) {
        strlcpy(r->dst.addr.v.ifname, dst->addr, sizeof(r->dst.addr.v.ifname));
        r->dst.addr.type = PF_ADDR_DYNIFTL;
        r->dst.addr.v.a.mask.v4.s_addr = 0xffffffff;
    }
    else if(dst->type == PF_ADDR_TABLE){
        strlcpy(r->dst.addr.v.tblname, dst->addr, sizeof(r->dst.addr.v.tblname));
        r->dst.addr.type = PF_ADDR_TABLE;
        r->dst.addr.v.a.mask.v4.s_addr = 0xffffffff;
    }
    else{
        printf("Invalid Address type\n");
        return 1;
    }

    
    if (ioctl(dev, DIOCCHANGERULE, &pr) < 0) {
        perror("ioctl add_rule");
        return 1;
    }

    printf("Rule appended successfully.\n");
    return 0;
}


int add_rdr_rule_generic(int dev, char* if_name, char* anchor, filter_addr* src, int src_port, filter_addr* dst, int dst_port,
                char** rdr, int rdr_count, int d_port, int proto)
{
    struct pfioc_pooladdr paddr = {0};
    struct pfioc_trans pt = {0};
    struct pfioc_rule pr = {0};
    struct pfioc_trans_e pte = {0};
    struct pf_rule *r;
    int i=0, neg=0;
    pt.size = 1;
    pt.esize = sizeof(pte);
    pt.array = &pte;

    pte.rs_num = PF_RULESET_RDR;
    strlcpy(pte.anchor, anchor, sizeof(pte.anchor));
    
    if (ioctl(dev, DIOCXBEGIN, &pt) < 0) {
        perror("DIOCXBEGIN");
        return 1;
    }

    
    if (ioctl(dev, DIOCBEGINADDRS, &paddr) < 0) {
        perror("DIOCBEGINADDRS");
        return 1;
    }

    for(i=0;  i<rdr_count; i++)
    {
        paddr.addr.addr.type = PF_ADDR_ADDRMASK;
        paddr.addr.ifname[0] = '\0';
        if (fill_pf_addr_and_mask(rdr[i], &paddr.addr.addr) < 0) {
            fprintf(stderr, "Failed to parse rdr address\n");
            return 1;
        }
    

        if (ioctl(dev, DIOCADDADDR, &paddr) < 0) {
            perror("DIOCADDADDR");
            return 1;
        }    
    }
    
    pr.ticket = pte.ticket;
    pr.pool_ticket = paddr.ticket;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
    
    r            = &pr.rule;
    r->action    = PF_RDR ;
    r->af        = AF_INET;
    r->proto     = proto;
    r->direction = PF_INOUT;
    r->natpass   = NATPASS;
    r->rtableid  = ALLTABLE;
    
    
    if(if_name && strnlen(if_name, sizeof(r->ifname))>0)
    {
        if(if_name[0] == '!'){
            strlcpy(r->ifname, if_name+1, sizeof(r->ifname)-1);
            r->ifnot = 1;
        }else{
            strlcpy(r->ifname, if_name, sizeof(r->ifname));
        }
    }

    if(dst_port >0)
    {
        
        r->dst.port_op = PF_OP_EQ;
        r->dst.port[0] = htons(dst_port);  
    }
    else{
        r->dst.port_op = PF_OP_NONE;        
    }
    
    if(src_port >0)
    {
        r->src.port_op = PF_OP_EQ;
        r->src.port[0] = htons(src_port);  
    }
    else{
        r->src.port_op = PF_OP_NONE;        
    }
    
    r->rpool.proxy_port[0] = d_port; 
    r->rpool.opts          = PF_POOL_ROUNDROBIN;              


    neg = 0;
    if(src != NULL)
    {
        if(src->addr[0] == '!')
            neg=1;
        printf("Src -addr: %s\nNeg = %d\nSrcAddr: %s\n", src->addr+neg, neg, src->addr);
        if(src->type == PF_ADDR_ADDRMASK)
        {
            
            if (fill_pf_addr_and_mask(src->addr+neg, &r->src.addr) < 0) {
                fprintf(stderr, "Failed to parse rdr address\n");
                return -1;
            }        
            r->src.addr.type = PF_ADDR_ADDRMASK;
            r->src.neg = neg;
        }
        else if (src->type == PF_ADDR_DYNIFTL) {
            strlcpy(r->src.addr.v.ifname, src->addr+neg, sizeof(r->src.addr.v.ifname));
            r->src.addr.type = PF_ADDR_DYNIFTL;
            r->src.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->src.neg = neg;
        }
        else if(src->type == PF_ADDR_TABLE){
            strlcpy(r->src.addr.v.tblname, src->addr+neg, sizeof(r->src.addr.v.tblname));
            r->src.addr.type = PF_ADDR_TABLE;
            r->src.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->src.neg = neg;
        }
        else{
            printf("Invalid Address type\n");
            return -11;
        }    
    }

    neg = 0;
    if(dst != NULL)
    {
        if(dst->addr[0] == '!')
            neg =1;

        if(dst->type == PF_ADDR_ADDRMASK)
        {
            if (fill_pf_addr_and_mask(dst->addr+neg, &r->dst.addr) < 0) {
                fprintf(stderr, "Failed to parse rdr address\n");
                return -1;
            }        
            r->dst.addr.type = PF_ADDR_ADDRMASK;
            r->dst.neg = neg;
        }
        else if (dst->type == PF_ADDR_DYNIFTL) {
            strlcpy(r->dst.addr.v.ifname, dst->addr+neg, sizeof(r->dst.addr.v.ifname));
            r->dst.addr.type = PF_ADDR_DYNIFTL;
            r->dst.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->dst.neg = neg;
        }
        else if(dst->type == PF_ADDR_TABLE){
            strlcpy(r->dst.addr.v.tblname, dst->addr+neg, sizeof(r->dst.addr.v.tblname));
            r->dst.addr.type = PF_ADDR_TABLE;
            r->dst.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->dst.neg = neg;
        }
        else{
            printf("Invalid Address type\n");
            return -1;
        }    
    }
    
    if (ioctl(dev, DIOCADDRULE, &pr) < 0) 
    {
        perror("DIOCADDRULE");
        return 1;
    }

    if (ioctl(dev, DIOCXCOMMIT, &pt) < 0) 
    {
        perror("DIOCXCOMMIT");
        return 1;
    }
    printf("Rule Added Succesfully\n");
    return 0;
}


int append_rdr_rule_generic(int dev, char* if_name, char* anchor, filter_addr* src, int src_port, filter_addr* dst, int dst_port,
                char** rdr, int rdr_count, int d_port, int proto, int quick)
{
    struct pfioc_rule pr;
    u_int32_t ticket, pool_ticket;
    struct pf_rule* r;
    struct pfioc_pooladdr paddr = {0};
    int i=0, neg=0;

    if(!ruleset_exists(dev, anchor, PF_RDR)){
        return add_rdr_rule_generic(dev, if_name, anchor, src, src_port, dst, dst_port, rdr, rdr_count, d_port, proto);
    }
    memset(&pr, 0, sizeof(pr));
    pr.action = PF_CHANGE_GET_TICKET;
    pr.rule.action = PF_RDR;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
    if (ioctl(dev, DIOCCHANGERULE, &pr) < 0) 
    {
        perror("ioctl get ticket");
        printf("Ruleset Doesn't Exists\n");
        return -1;
    }

    ticket = pr.ticket;
    memset(&paddr, 0, sizeof(struct pfioc_pooladdr));
    strlcpy(paddr.anchor, anchor, sizeof(paddr.anchor));
    if (ioctl(dev, DIOCBEGINADDRS, &paddr) < 0) 
    {
        perror("DIOCBEGINADDRS");
        return 1;
    }

    pool_ticket = paddr.ticket;
    for(i=0;  i<rdr_count; i++)
    {
        paddr.addr.addr.type = PF_ADDR_ADDRMASK;
        if (fill_pf_addr_and_mask(rdr[i], &paddr.addr.addr) < 0) {
            fprintf(stderr, "Failed to parse rdr address\n");
            return 1;
        }
    

        if (ioctl(dev, DIOCADDADDR, &paddr) < 0) {
            perror("DIOCADDADDR");
            return 1;
        }    
    }

    
    pr.ticket = ticket;
    pr.pool_ticket = pool_ticket;
    pr.action = PF_CHANGE_ADD_TAIL;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));

    r = &pr.rule;
    r->action = PF_RDR ;
    r->af = AF_INET;
    r->proto = proto;
    r->direction = PF_INOUT;
    r->natpass = 1;
    r->rtableid = -1;
    r->quick = quick;


    if(if_name && strnlen(if_name, sizeof(r->ifname))>0)
    {
        if(if_name[0] == '!'){
            strlcpy(r->ifname, if_name+1, sizeof(r->ifname)-1);
            r->ifnot = 1;
        }else{
            strlcpy(r->ifname, if_name, sizeof(r->ifname));
        }
    }
    

    if(dst_port >0)
    {
        r->dst.port_op = PF_OP_EQ;
        r->dst.port[0] = htons(dst_port);  
    }
    else{
        r->dst.port_op = PF_OP_NONE;        
    }
    
    if(src_port >0)
    {
        r->src.port_op = PF_OP_EQ;
        r->src.port[0] = htons(src_port);  
    }
    else{
        r->src.port_op = PF_OP_NONE;        
    }
    
    r->rpool.proxy_port[0] = d_port; 
    r->rpool.opts          = PF_POOL_ROUNDROBIN;              

    neg = 0;
    if(src != NULL)
    {
        if(src->addr[0] == '!')
            neg=1;
        printf("Src -addr: %s\nNeg = %d\nSrcAddr: %s\n", src->addr+neg, neg, src->addr);
        if(src->type == PF_ADDR_ADDRMASK)
        {
            
            if (fill_pf_addr_and_mask(src->addr+neg, &r->src.addr) < 0) {
                fprintf(stderr, "Failed to parse rdr address\n");
                return -1;
            }        
            r->src.addr.type = PF_ADDR_ADDRMASK;
            r->src.neg = neg;
        }
        else if (src->type == PF_ADDR_DYNIFTL) {
            strlcpy(r->src.addr.v.ifname, src->addr+neg, sizeof(r->src.addr.v.ifname));
            r->src.addr.type = PF_ADDR_DYNIFTL;
            r->src.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->src.neg = neg;
        }
        else if(src->type == PF_ADDR_TABLE){
            strlcpy(r->src.addr.v.tblname, src->addr+neg, sizeof(r->src.addr.v.tblname));
            r->src.addr.type = PF_ADDR_TABLE;
            r->src.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->src.neg = neg;
        }
        else{
            printf("Invalid Address type\n");
            return -11;
        }    
    }

    neg = 0;
    if(dst != NULL)
    {
        if(dst->addr[0] == '!')
            neg =1;

        if(dst->type == PF_ADDR_ADDRMASK)
        {
            if (fill_pf_addr_and_mask(dst->addr+neg, &r->dst.addr) < 0) {
                fprintf(stderr, "Failed to parse rdr address\n");
                return -1;
            }        
            r->dst.addr.type = PF_ADDR_ADDRMASK;
            r->dst.neg = neg;
        }
        else if (dst->type == PF_ADDR_DYNIFTL) {
            strlcpy(r->dst.addr.v.ifname, dst->addr+neg, sizeof(r->dst.addr.v.ifname));
            r->dst.addr.type = PF_ADDR_DYNIFTL;
            r->dst.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->dst.neg = neg;
        }
        else if(dst->type == PF_ADDR_TABLE){
            strlcpy(r->dst.addr.v.tblname, dst->addr+neg, sizeof(r->dst.addr.v.tblname));
            r->dst.addr.type = PF_ADDR_TABLE;
            r->dst.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->dst.neg = neg;
        }
        else{
            printf("Invalid Address type\n");
            return -1;
        }    
    }
    
    if (ioctl(dev, DIOCCHANGERULE, &pr) < 0) {
        perror("ioctl add_rule");
        return 1;
    }

    printf("Rule appended successfully.\n");
    return 0;
}

int remove_nth_rule(int dev, int r_num, char* anchor, int action)
{
    struct pfioc_rule pr;
    u_int32_t ticket;

    memset(&pr, 0, sizeof(pr));
    pr.action = PF_CHANGE_GET_TICKET;
    pr.rule.action = action;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
    if (ioctl(dev, DIOCCHANGERULE, &pr) < 0) 
    {
        perror("ioctl get ticket");
        return -1;
    }

    
    pr.action = PF_CHANGE_REMOVE;
    pr.rule.action = action;
    pr.nr = r_num;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
    if (ioctl(dev, DIOCCHANGERULE, &pr) < 0) 
    {
        perror("ioctl get ticket");
        return -1;
    }
    return 0;
}



int remove_rdr_port_rule(int dev, char* anchor, int port, int proto)
{
    
    struct pfioc_rule pr;
    u_int32_t ticket, change_ticket;
    struct pf_rule* r;
    int i=0, total=0, pos=0;
    int rule_positions[16];

    if(!ruleset_exists(dev, anchor, PF_RDR)){
        printf("Warning: Ruleset Doesn't Exist\n");
        
        return 0;
    }

    pr.rule.action = PF_RDR;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
    if(ioctl(dev, DIOCGETRULES, &pr) < 0){
        perror("DIOCGETRULES");
        return -1;
    }
    total = pr.nr;
    printf("Total Rules: %d\n", total);
    for(i=0; i< total; i++)
    {
        pr.rule.action = PF_RDR;
        strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
        pr.nr = i;
        if(ioctl(dev, DIOCGETRULE, &pr) < 0){
            perror("DIOCGETRULE");
            return -1;
        }

        printf("%d: %d: %d\n", i, ntohs(pr.rule.dst.port[0]), pr.rule.proto);
        if(pr.rule.dst.port[0] == htons(port) && pr.rule.proto == proto){
            printf("Found Rule at %d\n", i);
            /*
            if(remove_nth_rule(dev, i, anchor, PF_RDR) < 0){
                printf("Failed to remove rule\n");
                return -1;
            }
            printf("Removed Rule at %d\n", i);
            */
            rule_positions[pos++] = i;
        }
    }
    if(total == pos){
        printf("Total == nr\nClearing Ruleset\n");
        return clear_ruleset(dev, anchor);
    }
    
    for(i=0; i< pos; i++){
        printf("Matching Rule found at: %d ", rule_positions[i]);
        if(remove_nth_rule(dev, rule_positions[i]-i, anchor, PF_RDR)<0){
            printf("Failed to clear rule\n");
            return -1;
        }
    }
    return 0;
}

int add_nat_rule_generic(int dev, char* if_name, char* anchor, filter_addr* src, int src_port, filter_addr* dst, int dst_port,
                char** rdr, int rdr_count, int d_port, int proto)
{
    struct pfioc_pooladdr paddr = {0};
    struct pfioc_trans pt = {0}; 
    struct pfioc_rule pr = {0};
    struct pfioc_trans_e pte = {0};
    struct pf_rule *r;
    int i=0, neg=0;
    pt.size = 1;
    pt.esize = sizeof(pte);
    pt.array = &pte;

    pte.rs_num = PF_RULESET_NAT;
    strlcpy(pte.anchor, anchor, sizeof(pte.anchor));
    
    if (ioctl(dev, DIOCXBEGIN, &pt) < 0) {
        perror("DIOCXBEGIN");
        return 1;
    }

    
    if (ioctl(dev, DIOCBEGINADDRS, &paddr) < 0) {
        perror("DIOCBEGINADDRS");
        return 1;
    }

    for(i=0;  i<rdr_count; i++)
    {
        paddr.addr.addr.type = PF_ADDR_DYNIFTL;
        paddr.addr.ifname[0] = '\0';
        strlcpy(paddr.addr.addr.v.ifname, rdr[i], sizeof(paddr.addr.addr.v.ifname));
        paddr.addr.addr.v.a.mask.v4.s_addr = 0xffffffff;

        /*
        if (fill_pf_addr_and_mask(rdr[i], &paddr.addr.addr) < 0) {
            fprintf(stderr, "Failed to parse rdr address\n");
            return 1;
        }
        */

        if (ioctl(dev, DIOCADDADDR, &paddr) < 0) {
            perror("DIOCADDADDR");
            return 1;
        }    
    }
    
    pr.ticket = pte.ticket;
    pr.pool_ticket = paddr.ticket;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
    
    r            = &pr.rule;
    r->action    = PF_NAT ;
    r->af        = AF_INET;
    r->proto     = proto;
    r->direction = PF_INOUT;
    // r->natpass   = NATPASS;
    r->rtableid  = ALLTABLE;
    
    
    if(if_name && strnlen(if_name, sizeof(r->ifname))>0)
    {
        if(if_name[0] == '!'){
            strlcpy(r->ifname, if_name+1, sizeof(r->ifname)-1);
            r->ifnot = 1;
        }else{
            strlcpy(r->ifname, if_name, sizeof(r->ifname));
        }
    }

    if(dst_port >0)
    {
        
        r->dst.port_op = PF_OP_EQ;
        r->dst.port[0] = htons(dst_port);  
    }
    else{
        r->dst.port_op = PF_OP_NONE;        
    }
    
    if(src_port >0)
    {
        r->src.port_op = PF_OP_EQ;
        r->src.port[0] = htons(src_port);  
    }
    else{
        r->src.port_op = PF_OP_NONE;        
    }
    
    r->rpool.proxy_port[0] = 50001;
    r->rpool.proxy_port[1] = 65535;
    r->rpool.opts          = PF_POOL_ROUNDROBIN;              


    neg = 0;
    if(src != NULL)
    {
        if(src->addr[0] == '!')
            neg=1;
        printf("Src -addr: %s\nNeg = %d\nSrcAddr: %s\n", src->addr+neg, neg, src->addr);
        if(src->type == PF_ADDR_ADDRMASK)
        {
            
            if (fill_pf_addr_and_mask(src->addr+neg, &r->src.addr) < 0) {
                fprintf(stderr, "Failed to parse rdr address\n");
                return -1;
            }        
            r->src.addr.type = PF_ADDR_ADDRMASK;
            r->src.neg = neg;
        }
        else if (src->type == PF_ADDR_DYNIFTL) {
            strlcpy(r->src.addr.v.ifname, src->addr+neg, sizeof(r->src.addr.v.ifname));
            r->src.addr.type = PF_ADDR_DYNIFTL;
            r->src.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->src.neg = neg;
        }
        else if(src->type == PF_ADDR_TABLE){
            strlcpy(r->src.addr.v.tblname, src->addr+neg, sizeof(r->src.addr.v.tblname));
            r->src.addr.type = PF_ADDR_TABLE;
            r->src.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->src.neg = neg;
        }
        else{
            printf("Invalid Address type\n");
            return -11;
        }    
    }

    neg = 0;
    if(dst != NULL)
    {
        if(dst->addr[0] == '!')
            neg =1;

        if(dst->type == PF_ADDR_ADDRMASK)
        {
            if (fill_pf_addr_and_mask(dst->addr+neg, &r->dst.addr) < 0) {
                fprintf(stderr, "Failed to parse rdr address\n");
                return -1;
            }        
            r->dst.addr.type = PF_ADDR_ADDRMASK;
            r->dst.neg = neg;
        }
        else if (dst->type == PF_ADDR_DYNIFTL) {
            strlcpy(r->dst.addr.v.ifname, dst->addr+neg, sizeof(r->dst.addr.v.ifname));
            r->dst.addr.type = PF_ADDR_DYNIFTL;
            r->dst.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->dst.neg = neg;
        }
        else if(dst->type == PF_ADDR_TABLE){
            strlcpy(r->dst.addr.v.tblname, dst->addr+neg, sizeof(r->dst.addr.v.tblname));
            r->dst.addr.type = PF_ADDR_TABLE;
            r->dst.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->dst.neg = neg;
        }
        else{
            printf("Invalid Address type\n");
            return -1;
        }    
    }
    
    if (ioctl(dev, DIOCADDRULE, &pr) < 0) 
    {
        perror("DIOCADDRULE");
        return 1;
    }

    if (ioctl(dev, DIOCXCOMMIT, &pt) < 0) 
    {
        perror("DIOCXCOMMIT");
        return 1;
    }
    printf("Rule Added Succesfully\n");
    return 0;
}



int add_nat_rule(int dev, char* if_name, char* anchor, filter_addr* src, int src_port, filter_addr* dst, int dst_port,
                char** rdr, int rdr_count, int d_port, int proto, int quick)
{
    struct pfioc_rule pr;
    u_int32_t ticket, pool_ticket;
    struct pf_rule* r;
    struct pfioc_pooladdr paddr = {0};
    int i=0, neg=0;

    if(!ruleset_exists(dev, anchor, PF_NAT)){
        return add_nat_rule_generic(dev, if_name, anchor, src, src_port, dst, dst_port, rdr, rdr_count, d_port, proto);
    }
    memset(&pr, 0, sizeof(pr));
    pr.action = PF_CHANGE_GET_TICKET;
    pr.rule.action = PF_NAT;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
    if (ioctl(dev, DIOCCHANGERULE, &pr) < 0) 
    {
        perror("ioctl get ticket");
        printf("Ruleset Doesn't Exists\n");
        return -1;
    }

    ticket = pr.ticket;
    memset(&paddr, 0, sizeof(struct pfioc_pooladdr));
    strlcpy(paddr.anchor, anchor, sizeof(paddr.anchor));
    if (ioctl(dev, DIOCBEGINADDRS, &paddr) < 0) 
    {
        perror("DIOCBEGINADDRS");
        return 1;
    }

    pool_ticket = paddr.ticket;
    for(i=0;  i<rdr_count; i++)
    {
        paddr.addr.addr.type = PF_ADDR_ADDRMASK;
        if (fill_pf_addr_and_mask(rdr[i], &paddr.addr.addr) < 0) {
            fprintf(stderr, "Failed to parse rdr address\n");
            return 1;
        }
    

        if (ioctl(dev, DIOCADDADDR, &paddr) < 0) {
            perror("DIOCADDADDR");
            return 1;
        }    
    }

    
    pr.ticket = ticket;
    pr.pool_ticket = pool_ticket;
    pr.action = PF_CHANGE_ADD_TAIL;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));

    r = &pr.rule;
    r->action = PF_NAT;
    r->af = AF_INET;
    r->proto = proto;
    r->direction = PF_INOUT;
    r->natpass = 1;
    r->rtableid = -1;
    r->quick = quick;


    if(if_name && strnlen(if_name, sizeof(r->ifname))>0)
    {
        if(if_name[0] == '!'){
            strlcpy(r->ifname, if_name+1, sizeof(r->ifname)-1);
            r->ifnot = 1;
        }else{
            strlcpy(r->ifname, if_name, sizeof(r->ifname));
        }
    }
    

    if(dst_port >0)
    {
        r->dst.port_op = PF_OP_EQ;
        r->dst.port[0] = htons(dst_port);  
    }
    else{
        r->dst.port_op = PF_OP_NONE;        
    }
    
    if(src_port >0)
    {
        r->src.port_op = PF_OP_EQ;
        r->src.port[0] = htons(src_port);  
    }
    else{
        r->src.port_op = PF_OP_NONE;        
    }
    
    r->rpool.proxy_port[0] = d_port; 
    r->rpool.opts          = PF_POOL_ROUNDROBIN;              

    neg = 0;
    if(src != NULL)
    {
        if(src->addr[0] == '!')
            neg=1;
        printf("Src -addr: %s\nNeg = %d\nSrcAddr: %s\n", src->addr+neg, neg, src->addr);
        if(src->type == PF_ADDR_ADDRMASK)
        {
            
            if (fill_pf_addr_and_mask(src->addr+neg, &r->src.addr) < 0) {
                fprintf(stderr, "Failed to parse rdr address\n");
                return -1;
            }        
            r->src.addr.type = PF_ADDR_ADDRMASK;
            r->src.neg = neg;
        }
        else if (src->type == PF_ADDR_DYNIFTL) {
            strlcpy(r->src.addr.v.ifname, src->addr+neg, sizeof(r->src.addr.v.ifname));
            r->src.addr.type = PF_ADDR_DYNIFTL;
            r->src.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->src.neg = neg;
        }
        else if(src->type == PF_ADDR_TABLE){
            strlcpy(r->src.addr.v.tblname, src->addr+neg, sizeof(r->src.addr.v.tblname));
            r->src.addr.type = PF_ADDR_TABLE;
            r->src.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->src.neg = neg;
        }
        else{
            printf("Invalid Address type\n");
            return -11;
        }    
    }

    neg = 0;
    if(dst != NULL)
    {
        if(dst->addr[0] == '!')
            neg =1;

        if(dst->type == PF_ADDR_ADDRMASK)
        {
            if (fill_pf_addr_and_mask(dst->addr+neg, &r->dst.addr) < 0) {
                fprintf(stderr, "Failed to parse rdr address\n");
                return -1;
            }        
            r->dst.addr.type = PF_ADDR_ADDRMASK;
            r->dst.neg = neg;
        }
        else if (dst->type == PF_ADDR_DYNIFTL) {
            strlcpy(r->dst.addr.v.ifname, dst->addr+neg, sizeof(r->dst.addr.v.ifname));
            r->dst.addr.type = PF_ADDR_DYNIFTL;
            r->dst.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->dst.neg = neg;
        }
        else if(dst->type == PF_ADDR_TABLE){
            strlcpy(r->dst.addr.v.tblname, dst->addr+neg, sizeof(r->dst.addr.v.tblname));
            r->dst.addr.type = PF_ADDR_TABLE;
            r->dst.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->dst.neg = neg;
        }
        else{
            printf("Invalid Address type\n");
            return -1;
        }    
    }
    
    if (ioctl(dev, DIOCCHANGERULE, &pr) < 0) {
        perror("ioctl add_rule");
        return 1;
    }

    printf("Rule appended successfully.\n");
    return 0;
}

int remove_nat_port_rule(int dev, char* anchor, int port, int proto)
{
    
    struct pfioc_rule pr;
    u_int32_t ticket, change_ticket;
    struct pf_rule* r;
    int i=0, total=0, pos=0;
    int rule_positions[16];

    if(!ruleset_exists(dev, anchor, PF_NAT)){
        printf("Warning: Ruleset Doesn't Exist\n");
        return 0;
    }

    pr.rule.action = PF_NAT;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
    if(ioctl(dev, DIOCGETRULES, &pr) < 0){
        perror("DIOCGETRULES");
        return -1;
    }
    total = pr.nr;
    printf("Total Rules: %d\n", total);
    for(i=0; i< total; i++)
    {
        pr.rule.action = PF_NAT;
        strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
        pr.nr = i;
        if(ioctl(dev, DIOCGETRULE, &pr) < 0){
            perror("DIOCGETRULE");
            return -1;
        }

        printf("%d: %d: %d\n", i, ntohs(pr.rule.dst.port[0]), pr.rule.proto);
        if(pr.rule.dst.port[0] == htons(port) && pr.rule.proto == proto){
            printf("Found Rule at %d\n", i);
            /*
            if(remove_nth_rule(dev, i, anchor, PF_RDR) < 0){
                printf("Failed to remove rule\n");
                return -1;
            }
            printf("Removed Rule at %d\n", i);
            */
            rule_positions[pos++] = i;
        }
    }
    if(total == pos){
        printf("Total == nr\nClearing Ruleset\n");
        return clear_nat_ruleset(dev, anchor);
    }
    
    for(i=0; i< pos; i++){
        printf("Matching Rule found at: %d ", rule_positions[i]);
        if(remove_nth_rule(dev, rule_positions[i]-i, anchor, PF_NAT)<0){
            printf("Failed to clear rule\n");
            return -1;
        }
    }
    return 0;
}


int append_nat_rule_src_if(int dev, char* if_name, char* anchor, filter_addr* src, int src_port, filter_addr* dst, int dst_port,
                char** rdr, int rdr_count, int d_port, int proto)
{
    struct pfioc_rule pr;
    u_int32_t ticket, pool_ticket;
    struct pf_rule* r;
    struct pfioc_pooladdr paddr = {0};
    int i=0;


    memset(&pr, 0, sizeof(pr));
    pr.action = PF_CHANGE_GET_TICKET;
    pr.rule.action = PF_NAT;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
    if (ioctl(dev, DIOCCHANGERULE, &pr) < 0) 
    {
        perror("ioctl get ticket");
        return 1;
    }

    ticket = pr.ticket;
    memset(&paddr, 0, sizeof(struct pfioc_pooladdr));
    strlcpy(paddr.anchor, anchor, sizeof(paddr.anchor));
    if (ioctl(dev, DIOCBEGINADDRS, &paddr) < 0) 
    {
        perror("DIOCBEGINADDRS");
        return 1;
    }

    pool_ticket = paddr.ticket;
    for(i=0;  i<rdr_count; i++)
    {
        paddr.addr.addr.type = PF_ADDR_ADDRMASK;
        if (fill_pf_addr_and_mask(rdr[i], &paddr.addr.addr) < 0) {
            fprintf(stderr, "Failed to parse rdr address\n");
            return 1;
        }
    

        if (ioctl(dev, DIOCADDADDR, &paddr) < 0) {
            perror("DIOCADDADDR");
            return 1;
        }    
    }

    
    pr.ticket = ticket;
    pr.pool_ticket = pool_ticket;
    pr.action = PF_CHANGE_ADD_TAIL;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));

    r = &pr.rule;
    r->action = PF_NAT;
    r->af = AF_INET;
    r->proto = proto;
    r->direction = PF_INOUT;
    r->natpass = 1;
    r->rtableid = -1;
    strlcpy(r->ifname, if_name, sizeof(r->ifname));
    

    if(dst_port >0)
    {
        r->dst.port_op = PF_OP_EQ;
        r->dst.port[0] = htons(dst_port);  
    }
    else{
        r->dst.port_op = PF_OP_NONE;        
    }
    
    if(src_port >0)
    {
        r->src.port_op = PF_OP_EQ;
        r->src.port[0] = htons(src_port);  
    }
    else{
        r->src.port_op = PF_OP_NONE;        
    }
    
    r->rpool.proxy_port[0] = d_port; 
    r->rpool.opts          = PF_POOL_ROUNDROBIN;              

    if(src->type == PF_ADDR_ADDRMASK)
    {
        if (fill_pf_addr_and_mask(src->addr, &r->src.addr) < 0) {
            fprintf(stderr, "Failed to parse rdr address\n");
            return 1;
        }        
        r->src.addr.type = PF_ADDR_ADDRMASK;
    }
    else if (src->type == PF_ADDR_DYNIFTL) {
        strlcpy(r->src.addr.v.ifname, src->addr, sizeof(r->src.addr.v.ifname));
        r->src.addr.type = PF_ADDR_DYNIFTL;
        r->src.addr.v.a.mask.v4.s_addr = 0xffffffff;
    }
    else if(src->type == PF_ADDR_TABLE){
        strlcpy(r->src.addr.v.tblname, src->addr, sizeof(r->src.addr.v.tblname));
        r->src.addr.type = PF_ADDR_TABLE;
        r->src.addr.v.a.mask.v4.s_addr = 0xffffffff;
    }
    else{
        printf("Invalid Address type\n");
        return 1;
    }

    if(dst->type == PF_ADDR_ADDRMASK)
    {
        if (fill_pf_addr_and_mask(dst->addr, &r->dst.addr) < 0) {
            fprintf(stderr, "Failed to parse rdr address\n");
            return 1;
        }        
        r->dst.addr.type = PF_ADDR_ADDRMASK;
    }
    else if (dst->type == PF_ADDR_DYNIFTL) {
        strlcpy(r->dst.addr.v.ifname, dst->addr, sizeof(r->dst.addr.v.ifname));
        r->dst.addr.type = PF_ADDR_DYNIFTL;
        r->dst.addr.v.a.mask.v4.s_addr = 0xffffffff;
    }
    else if(dst->type == PF_ADDR_TABLE){
        strlcpy(r->dst.addr.v.tblname, dst->addr, sizeof(r->dst.addr.v.tblname));
        r->dst.addr.type = PF_ADDR_TABLE;
        r->dst.addr.v.a.mask.v4.s_addr = 0xffffffff;
    }
    else{
        printf("Invalid Address type\n");
        return 1;
    }

    
    if (ioctl(dev, DIOCCHANGERULE, &pr) < 0) {
        perror("ioctl add_rule");
        return 1;
    }

    printf("Rule appended successfully.\n");
    return 0;
}

int append_nat_rule_generic(int dev, char* if_name, char* anchor, filter_addr* src, int src_port, filter_addr* dst, int dst_port,
                char** rdr, int rdr_count, int d_port, int proto, int quick)
{
    struct pfioc_rule pr;
    u_int32_t ticket, pool_ticket;
    struct pf_rule* r;
    struct pfioc_pooladdr paddr = {0};
    int i=0, neg=0;

    if(!ruleset_exists(dev, anchor, PF_NAT)){
        return add_nat_rule_generic(dev, if_name, anchor, src, src_port, dst, dst_port, rdr, rdr_count, d_port, proto);
    }
    memset(&pr, 0, sizeof(pr));
    pr.action = PF_CHANGE_GET_TICKET;
    pr.rule.action = PF_NAT;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
    if (ioctl(dev, DIOCCHANGERULE, &pr) < 0) 
    {
        perror("ioctl get ticket");
        printf("Ruleset Doesn't Exists\n");
        return -1;
    }

    ticket = pr.ticket;
    memset(&paddr, 0, sizeof(struct pfioc_pooladdr));
    strlcpy(paddr.anchor, anchor, sizeof(paddr.anchor));
    if (ioctl(dev, DIOCBEGINADDRS, &paddr) < 0) 
    {
        perror("DIOCBEGINADDRS");
        return 1;
    }

    pool_ticket = paddr.ticket;
    for(i=0;  i<rdr_count; i++)
    {
        paddr.addr.addr.type = PF_ADDR_DYNIFTL;
        // if (fill_pf_addr_and_mask(rdr[i], &paddr.addr.addr) < 0) {
        //     fprintf(stderr, "Failed to parse rdr address\n");
        //     return 1;
        // }
        strlcpy(paddr.addr.addr.v.ifname, rdr[i], sizeof(paddr.addr.addr.v.ifname));
        paddr.addr.addr.v.a.mask.v4.s_addr = 0xffffffff;
        

        if (ioctl(dev, DIOCADDADDR, &paddr) < 0) {
            perror("DIOCADDADDR");
            return 1;
        }    
    }

    
    pr.ticket = ticket;
    pr.pool_ticket = pool_ticket;
    pr.action = PF_CHANGE_ADD_TAIL;
    strlcpy(pr.anchor, anchor, sizeof(pr.anchor));

    r = &pr.rule;
    r->action = PF_NAT;
    r->af = AF_INET;
    r->proto = proto;
    r->direction = PF_INOUT;
    // r->natpass = 1;
    r->rtableid = -1;
    r->quick = quick;


    if(if_name && strnlen(if_name, sizeof(r->ifname))>0)
    {
        if(if_name[0] == '!'){
            strlcpy(r->ifname, if_name+1, sizeof(r->ifname)-1);
            r->ifnot = 1;
        }else{
            strlcpy(r->ifname, if_name, sizeof(r->ifname));
        }
    }
    

    if(dst_port >0)
    {
        r->dst.port_op = PF_OP_EQ;
        r->dst.port[0] = htons(dst_port);  
    }
    else{
        r->dst.port_op = PF_OP_NONE;        
    }
    
    if(src_port >0)
    {
        r->src.port_op = PF_OP_EQ;
        r->src.port[0] = htons(src_port);  
    }
    else{
        r->src.port_op = PF_OP_NONE;        
    }
    
    r->rpool.proxy_port[0] = 50001; 
    r->rpool.proxy_port[1] = 65535; 
    r->rpool.opts          = PF_POOL_ROUNDROBIN;              

    neg = 0;
    if(src != NULL)
    {
        if(src->addr[0] == '!')
            neg=1;
        printf("Src -addr: %s\nNeg = %d\nSrcAddr: %s\n", src->addr+neg, neg, src->addr);
        if(src->type == PF_ADDR_ADDRMASK)
        {
            
            if (fill_pf_addr_and_mask(src->addr+neg, &r->src.addr) < 0) {
                fprintf(stderr, "Failed to parse rdr address\n");
                return -1;
            }        
            r->src.addr.type = PF_ADDR_ADDRMASK;
            r->src.neg = neg;
        }
        else if (src->type == PF_ADDR_DYNIFTL) {
            strlcpy(r->src.addr.v.ifname, src->addr+neg, sizeof(r->src.addr.v.ifname));
            r->src.addr.type = PF_ADDR_DYNIFTL;
            r->src.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->src.neg = neg;
        }
        else if(src->type == PF_ADDR_TABLE){
            strlcpy(r->src.addr.v.tblname, src->addr+neg, sizeof(r->src.addr.v.tblname));
            r->src.addr.type = PF_ADDR_TABLE;
            r->src.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->src.neg = neg;
        }
        else{
            printf("Invalid Address type\n");
            return -11;
        }    
    }

    neg = 0;
    if(dst != NULL)
    {
        if(dst->addr[0] == '!')
            neg =1;

        if(dst->type == PF_ADDR_ADDRMASK)
        {
            if (fill_pf_addr_and_mask(dst->addr+neg, &r->dst.addr) < 0) {
                fprintf(stderr, "Failed to parse rdr address\n");
                return -1;
            }        
            r->dst.addr.type = PF_ADDR_ADDRMASK;
            r->dst.neg = neg;
        }
        else if (dst->type == PF_ADDR_DYNIFTL) {
            strlcpy(r->dst.addr.v.ifname, dst->addr+neg, sizeof(r->dst.addr.v.ifname));
            r->dst.addr.type = PF_ADDR_DYNIFTL;
            r->dst.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->dst.neg = neg;
        }
        else if(dst->type == PF_ADDR_TABLE){
            strlcpy(r->dst.addr.v.tblname, dst->addr+neg, sizeof(r->dst.addr.v.tblname));
            r->dst.addr.type = PF_ADDR_TABLE;
            r->dst.addr.v.a.mask.v4.s_addr = 0xffffffff;
            r->dst.neg = neg;
        }
        else{
            printf("Invalid Address type\n");
            return -1;
        }    
    }
    
    if (ioctl(dev, DIOCCHANGERULE, &pr) < 0) {
        perror("ioctl add_rule");
        return 1;
    }

    printf("Rule appended successfully.\n");
    return 0;
}
