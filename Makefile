all : send_arp

send_arp : sendArp.o main.o
	g++ -g -o send_arp sendArp.o main.o -lpcap

main.o :
	g++ -c -g -o main.o main.cpp

sendArp.o :
	g++ -g -c -o sendArp.o sendArp.cpp

clean :
	rm -f send_arp
	rm -f *.o
