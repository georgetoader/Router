#include <queue.h>
#include "skel.h"

#define MAX_WORD_LEN 30
#define MAX_LINE_LEN 120
#define MAX_TABLE_SIZE 70000
#define MAX_ARP_SIZE 200
#define ICMP_CODE_ZERO 0
#define BONUS_SIZE 10000

// structura din laborator
struct route_table_entry *rtable;
struct arp_entry *arp_table;
long int rtable_size = 0;
long int arp_table_len = 0;

// moves the elements from 'source' to 'dest' and return the size
int queue_move(queue source, queue dest) {
	int size = 0;
	while (queue_empty(source) != 1) {
		queue_enq(dest, queue_deq(source));
		size++;
	}
	return size;
}

// returns a pointer to the best matching ARP entry for given IP
struct arp_entry *get_arp_entry(uint32_t ip) {
	for (long int i = 0; i < arp_table_len; i++)
		if (arp_table[i].ip == ip)
			return &arp_table[i];

	return NULL;
}

// counts the lines in a file whose name is given as parameter
long int file_lines(char *filename) {
	FILE *fd = fopen(filename, "r");
	DIE(fd == NULL, "Error opening file.");
	char *entry = (char *)malloc(MAX_LINE_LEN * sizeof(char));
	size_t length = 0;

	long int size = 1;
	while (getline(&entry, &length, fd) != -1) {
		size++;
	}
	fclose(fd);
	return size;
}

// separate the string "entry" into addresses and build the routing table
void build_rtable(struct route_table_entry *rtable, char *entry, long int ct) {
	char *token = (char *)malloc(MAX_WORD_LEN * sizeof(char));
	DIE(token == NULL, "Error malloc.");

	token = strtok(entry, " ");
	rtable[ct].prefix = inet_addr(token);	

	token = strtok(NULL, " ");
	rtable[ct].next_hop = inet_addr(token);

	token = strtok(NULL, " ");
	rtable[ct].mask = inet_addr(token);	

	token = strtok(NULL, " ");
	rtable[ct].interface = atoi(token); 
}

// parse the routing table
void read_rtable(struct route_table_entry *rtable, char *filename) {
	FILE *fd = fopen(filename, "r");
	DIE(fd == NULL, "Error opening file.");

	char *entry = (char *)malloc(MAX_LINE_LEN * sizeof(char));
	long int ct = -1;
	size_t size = 0;

	// go through each line and separate the addresses by " "
	while (getline(&entry, &size, fd) != -1) {
		ct++;
		build_rtable(rtable, entry, ct);
	}
	free(entry);
	fclose(fd);
}

// performs a binary search through the sorted table and returns the rightmost position found
long int binary_search(long int left, long int right, uint32_t dest_ip) {
	long int last_pos = -1;
	long int mid = 0;
	while(left <= right) {
		mid = left + (right - left) / 2;
		// check address and even if a good address has been found, go for the rightmost one
		if ((dest_ip & rtable[mid].mask) == rtable[mid].prefix) {	
			last_pos = mid;
			left = mid + 1;
		} else if ((dest_ip & rtable[mid].mask) < rtable[mid].prefix) {
			right = mid - 1;
		} else {
			left = mid + 1;
		}
	}
	return last_pos;
}

// get best route from rtable using binary search
struct route_table_entry *get_best_route(uint32_t dest_ip) {	
	// get position using binary search
	long int pos = binary_search(0, rtable_size - 1, dest_ip);	
	if (pos == -1)
		return NULL;

	uint32_t max = 0;
	struct route_table_entry *best_route = NULL;
	// make sure to get the rightmost address with the biggest mask
	while ((dest_ip & rtable[pos].mask) == rtable[pos].prefix) {
		if (rtable[pos].mask > max) {
			max = rtable[pos].mask;
			best_route = &rtable[pos];
		}
		pos++;
	}

	return best_route;
}

// adds new entry to arp_table (used for ARP_REPLY)
void update_arptable(struct arp_entry *arp_table, struct arp_header *arp_hdr) {
	arp_table_len++;
	arp_table[arp_table_len].ip = arp_hdr->spa;
	memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, sizeof(arp_hdr->sha));
}

// function used for ARP_REPLY, if the packet extracted from queue
// needed the REPLY then change its ethernet header and send it
packet *my_send_packet(packet *m, struct arp_header *arp_hdr) {
	struct arp_header *arp_hdr_aux = parse_arp(m->payload);				
	if(arp_hdr->spa == arp_hdr_aux->tpa) {		
		struct ether_header *eth_hdr1 = (struct ether_header *)m->payload;
		build_ethhdr(eth_hdr1, arp_hdr_aux->sha, arp_hdr->tha, htons(ETHERTYPE_IP));
		send_packet(m->interface, m);
		return NULL;
	}
	// if it wasn't waiting this REPLY then return it
	return m;
}

// checks each packet in queue if it was waiting for that
// specific ARP REPLY, and if so then sends it
void update_queue_packets(queue q, struct arp_header *arp_hdr) {
	queue q_rest = queue_create();
	// get packets from queue and check each for waiting REPLY
	while(queue_empty(q) != 1) {
		packet *p = my_send_packet(queue_deq(q), arp_hdr);
		if (p != NULL) {
			queue_enq(q_rest, p);
		}
	}
	queue_move(q_rest, q);	
}

// function to print an entry of rtable
void print_rtable_entry(struct route_table_entry rtable_entry) {
	struct in_addr addr1, addr2, addr3;
	addr1.s_addr = rtable_entry.prefix;
	addr2.s_addr = rtable_entry.next_hop;
	addr3.s_addr = rtable_entry.mask;
	printf("%s %s %s %d\n", inet_ntoa(addr1), inet_ntoa(addr2),
		inet_ntoa(addr3), rtable_entry.interface);
}

// function to print the rtable
void print_rtable(struct route_table_entry *rtable_entry) {
	for (long int i = 0; i < rtable_size; i++) {
		print_rtable_entry(rtable[i]);
	}
}

// returns a pointer to a copy of the packet given as parameter
packet *copy_packet(packet m) {
	packet *copy = malloc(sizeof(packet));
	memcpy(copy, &m, sizeof(packet));
	return copy;
}

int comparator(const void *p, const void *q) {
	struct route_table_entry *r1 = (struct route_table_entry *)p;
	struct route_table_entry *r2 = (struct route_table_entry *)q;

	// if prefixes are equal then sort by mask
	if (r1->prefix == r2->prefix) {
		return r1->mask - r2->mask;
	}
	// sort by prefix
	return r1->prefix - r2->prefix;
}

// setup function to initialize and build the 2 tables
void setup(char *file) {
	// parse routing table
	rtable_size = file_lines(file);
	rtable = malloc(rtable_size * sizeof(struct route_table_entry));
	DIE(rtable == NULL, "Error malloc rtable.");
	read_rtable(rtable, file);
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), comparator);

	// static ARP table :(
	arp_table = malloc(MAX_ARP_SIZE * sizeof(struct arp_entry));
	DIE(arp_table == NULL, "Error malloc arp_table.");
	parse_arp_table();
}

int main(int argc, char *argv[]) {
	packet m;
	int rc;
	init(argc - 2, argv + 2);

	// builds the rtable and arp_table
	setup(argv[1]);

	queue q;
	q = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		// ethernet header
		struct ether_header *eth_hdr = (struct ether_header *) m.payload;
		uint16_t type = ntohs(eth_hdr->ether_type);

		if (type == ETHERTYPE_IP) {
			struct iphdr *ip_hdr = (struct iphdr *) (m.payload + sizeof(struct ether_header));
			struct icmphdr *icmp_hdr = parse_icmp(m.payload);

			// Echo reply
			if (icmp_hdr != NULL) {
				if (icmp_hdr->type == ICMP_ECHO) {
					send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost,
						ICMP_ECHOREPLY, ICMP_CODE_ZERO, m.interface, icmp_hdr->un.echo.id,
						icmp_hdr->un.echo.sequence + 1);
				}
				continue;
			}

			// Check TTL / Time exceeded
			if (ip_hdr->ttl <= 1) {
				send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost,
						ICMP_TIME_EXCEEDED, ICMP_CODE_ZERO, m.interface);
				continue;
			}

			// Verify checksum
			uint16_t old_checksum = ip_hdr->check;
			ip_hdr->check = 0;
			if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != old_checksum) {
				// discard the packet
				continue;
			}

			// Update TTL and recalculate checksum (like in lab4)
			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));	

			// Check best route / Destination unreachable
			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
			if (!best_route) {
				send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost,
						ICMP_DEST_UNREACH, ICMP_CODE_ZERO, m.interface);
				continue;
			}

			// Get matching ARP entry
			struct arp_entry *arp = get_arp_entry(best_route->next_hop);
			if (!arp) {
				// entry not found so enque the copy of the packet and send ARP_REQUEST
				queue_enq(q, copy_packet(m));
				send_arp(ip_hdr->saddr, best_route->next_hop, eth_hdr, best_route->interface, ARPOP_REQUEST);
				continue;
			}
			
			// Update Ethernet addresses and send packet
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			send_packet(best_route->interface, &m);

		} else if (type == ETHERTYPE_ARP) {

			struct arp_header *arp_hdr = parse_arp(m.payload);
			if (arp_hdr->op == 1) {
				// it's an ARP REQUEST so modify ethernet header send ARP REPLY
				memcpy(eth_hdr->ether_shost, arp_hdr->tha, sizeof(eth_hdr->ether_shost));
				memcpy(eth_hdr->ether_dhost, arp_hdr->sha, sizeof(eth_hdr->ether_dhost));				
				send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr, m.interface, ARPOP_REPLY);
			} else {
				// ARP REPLY
				// update arp_table with new entry
				update_arptable(arp_table, arp_hdr);
				// call function to check and send each packet in queue
				update_queue_packets(q, arp_hdr);
			}
		}
	}
}			


