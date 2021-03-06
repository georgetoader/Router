# Router Implementation
Programul implementeaza functionalitatile unui router. Am realizat parsarea tabelei de rutare, am implementat procesul de dirijare folosind cautare binara pe tabela sortata si suport pentru protocolul `ICMP`.

* Parsarea tabelei de rutare -> se realizeaza in functia `read_rtable`, initial folosesc functia `file_lines` pentru a obtine numarul de linii din fisier, pe care
il folosesc sa aloc memorie pentru rtable. Apoi citesc fisierul linie cu linie si
utilizez strtok pentru a obtine adresele de pe fiecare linie, cu care apoi construiesc
tabela de rutare.

* Procesul de dirijare -> Tabela de rutare a fost sortata folosind `qsort` dupa prefix si
masca (daca prefixele sunt egale), iar apoi functia `get_best_route` realizeaza o 
cautare binara pe tabela sortata si returneaza cea mai buna ruta. In `main()`, dupa ce
obtin packetul verific daca acesta este de tipul IP sau ARP. 
	* In primul caz, extrag cele 2 headere `IPHDR` si `ICMPHDR` folosind functiile auxiliare
	oferite in `skel.c`. Daca este un packet destinat router-ului, in cazul in care este un
	`ICMP ECHO REQUEST` atunci ii trimit un reply folosind functia `send_icmp` cu parametrii
	ceruti, altfel ii dau discard. Apoi urmez pasii specificati in enuntul temei, adica: daca
	`TTL<=1` trimit un `ICMP_TIME_EXCEEDED` folosind functia `send_icmp_error`, daca checksumul 
	este gresit atunci ii dau discard, decrementez TTL si updatez checksum, apelez `get_best_route`
	si daca nu este gasita ruta atunci trimit un `ICMP_DEST_UNREACH` folosind `send_icmp_error`,
	iar in final caut matching entry-ul din tabela arp, iar daca este gasit atunci ii updatez
	ethernet header-ul si il trimit mai departe. Daca nu este gasit atunci adaug packetul in queue
	si trimit un `ARP_REQUEST`.
	* In cazul 2, daca este de tip `ARP`, atunci obtin `arp_header` folosind functia auxiliara
	din `skel.c` si verific campul `op` sa vad daca este de tip `ARP_REQUEST` sau `ARP_REPLY`.
	Daca este `ARP_REQUEST` atunci modific ethernet header-ul si trimit un `ARP_REPLY` folosind
	`send_arp`, iar daca este un `ARP_REPLY` atunci updatez tabela arp cu noul entry si folosesc
	functia `update_queue_packets` pentru a parcurge toate packetele din queue. Verific fiecare
	packet daca astepta acest `ARP_REPLY` si daca da atunci folosesc `my_send_packet` pentru a le
	modifica ethernet header-ul si a le trimite mai departe.

* Suport pentru protocolul `ICMP` -> am descris cum functioneaza la subpunctul 3.1, in cazul in care
	packetul primit este de tipul `IP`. Daca este un packet destinat router-ului, in cazul in care
	este un `ICMP ECHO REQUEST` atunci ii trimit un reply folosind functia `send_icmp` cu parametrii
	ceruti, altfel arunc pachetul. Daca `TTL<=1` trimit un `ICMP_TIME_EXCEEDED` folosind functia 
	`send_icmp_error` iar daca nu se gaseste ruta atunci trimit un `ICMP_DEST_UNREACH`.
