all : send_arp

send_arp: send_arp.o
	g++ -g -o send_arp send_arp.o -lpcap

send_arp.o:
	g++ -g -c -o send_arp.o send_arp.cpp

clean:
	rm -f send_arp
	rm -f *.o

