#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

/*

Add an IPv4 route using a PF_ROUTE socket (BSD/macOS).

Parameters
----------
destination : str
    Destination IPv4 address (e.g. "192.168.10.0", "8.8.8.8", "0.0.0.0")
netmask : str
    Netmask (e.g. "255.255.255.0", "255.255.255.255", "0.0.0.0")
gateway : str or None
    Gateway IP (None for direct / on-link routes)
flags : int or None
    Route flags (RTF_*). If None, sensible defaults are chosen.
seq : int
    Routing message sequence number
    
*/
int add_route(int rtsock, char* destination, char* netmask, char* gateway)
{
    char buf[512];
    struct rt_msghdr *rtm;
    struct sockaddr_in *dst, *gw, *dst_mask;
    /* Check for null/invalid values */
    if(destination == NULL || netmask == NULL)
    {
        printf("Destination or Netmask cannot be null\n");
        return -1;
    }
    memset(buf, 0, sizeof(buf));
    rtm = (struct rt_msghdr *)buf;
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_type = RTM_ADD;
    rtm->rtm_flags = RTF_UP | RTF_GATEWAY|RTF_STATIC;
    rtm->rtm_seq = 1;
    rtm->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
    
    
    /* Auto Decide Flags Marks Route Static*/
    if(strncmp(netmask, "255.255.255.255", strlen(netmask)))
        rtm->rtm_flags |= RTF_HOST;
    
    dst = (struct sockaddr_in *)(rtm + 1);
    dst->sin_len = sizeof(*dst);
    dst->sin_family = AF_INET;
    if(inet_pton(AF_INET, destination, &dst->sin_addr)<0){
        perror("inet_pton");
        printf("Invalid Destination Address\n");
        return -1;
    }
    /* Setup Gateway */
    gw = (struct sockaddr_in *)(dst + 1);
    gw->sin_len = sizeof(*gw);
    gw->sin_family = AF_INET;
    if(inet_pton(AF_INET, gateway, &gw->sin_addr)<0){
        perror("inet_pton");
        printf("Invalid Destination Mask\n");
        return -1;
    }

    dst_mask = (struct sockaddr_in *)(gw + 1);
    dst_mask->sin_len = sizeof(*dst_mask);
    dst_mask->sin_family = AF_INET;
    if(inet_pton(AF_INET, netmask, &dst_mask->sin_addr)<0){
        perror("inet_pton");
        printf("Invalid Destination Mask\n");
        return -1;
    }

    
    /* */
    rtm->rtm_msglen =
        sizeof(*rtm) +
        sizeof(*dst) +
        sizeof(*gw) +
        sizeof(*dst_mask);

    if (write(rtsock, buf, rtm->rtm_msglen) < 0) {
        perror("write");
        return -1;
    }
    printf("Route Added Succesfully\n");
    return 0;
}
