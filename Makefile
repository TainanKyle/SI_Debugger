sdb: sdb.cpp
	g++ -Wall -o sdb sdb.cpp -lcapstone

clean:
	rm -f sdb